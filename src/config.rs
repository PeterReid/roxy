use std::net::SocketAddr;
use native_tls::TlsAcceptor;
use std::sync::mpsc::{channel};
use std::sync::{Arc, Mutex};
use futures::sync::mpsc::Receiver as FutureReceiver;
use futures::sync::mpsc::Sender as FutureSender;
use futures::sync::mpsc::channel as future_channel;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use notify::{self, Watcher, RecursiveMode, DebouncedEvent};
use json::{self, JsonValue};
use std::io::Read;
use std::fs::File;
use url::Url;
use native_tls::{Pkcs12,};
use futures::sink::Sink;
use tokio_core::reactor::Core;

type Port = u16;

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct Input {
    pub port: Port,
    pub host: String,
    pub secure: bool,
}

#[derive(Clone)]
pub enum Action{
    Forward{address: SocketAddr, secure: bool},
    Redirect{redirect_to: String},
}

#[derive(Clone)]
pub struct Output {
    pub acceptor: Option<Arc<TlsAcceptor>>,
    pub action: Action,
}

#[derive(Clone)]
pub struct Config {
    inner: Arc<Mutex<HashMap<Input, Output>>>
}

#[derive(Debug)]
pub enum ConfigError {
    UnableToWatchFiles,
    ConfigFileNotFound,
    WatchEnded,
}

fn parse_target(target: &str) -> Result<(SocketAddr, bool), String> {
    let divider = target.find("://").ok_or_else(|| format!("Missing scheme specifier such as http:// in {:?}", target))?;
    let (scheme, addr) = target.split_at(divider+3);
    
    let secure = match scheme {
        "http://" => false,
        "https://" => true,
        _ => {
            return Err(format!("Invalid scheme ({:?}) in {:?}", scheme, target));
        }
    };
    
    let dest = addr.parse().map_err(|_| format!("Malformed IP/port in {:?}", target))?;
    
    Ok((dest, secure))
}

fn process_config_item(incoming_url_str: &str, value: &JsonValue) -> Result<(Port, Input, Output), String> {
    let incoming_url = Url::parse(incoming_url_str).map_err(|e| format!("Badly formatted host: {}\n{:?}", incoming_url_str, e))?;
    
    let incoming_secure = match incoming_url.scheme() {
        "http" => false,
        "https" => true,
        _ => {
            return Err(format!("Invalid scheme {:?} in URL: {:?}", incoming_url.scheme(), incoming_url_str));
        }
    };
    
    let hostname = incoming_url.host_str().ok_or_else(|| format!("Missing host in {:?}", incoming_url_str))?;
    let port = incoming_url.port().unwrap_or(if incoming_secure { 443 } else { 80 });
    let input = Input {
        host: hostname.to_string(),
        secure: incoming_secure,
        port: port
    };
    
    if let JsonValue::Object(ref value) = *value {
        let pfx = value.get("pfx").and_then(|x| x.as_str());
        let target = value.get("target").and_then(|x| x.as_str());
        let redirect = value.get("redirect").and_then(|x| x.as_str());

        if pfx.is_some() != incoming_secure {
            return Err(format!("PFX should be specified only if the incoming connection is HTTPS."));
        }
        
        let acceptor = if let Some(pfx) = pfx {
            let mut file = File::open(pfx).map_err(|e| format!("Unable to open PFX file (specified as {:?}): {:?}", pfx, e))?;
            let mut pkcs12 = vec![];
            file.read_to_end(&mut pkcs12).unwrap();
            let pkcs12 = Pkcs12::from_der(&pkcs12, "").unwrap();
            Some(Arc::new(TlsAcceptor::builder(pkcs12).unwrap().build().unwrap()))
        } else {
            None
        };

        let action = match (target, redirect) {
              (Some(target), None) => {
                  let (address, outgoing_secure) = parse_target(target)?;
                  Action::Forward{
                      address: address,
                      secure: outgoing_secure,
                  }
              },
              (None, Some(redirect)) => {
                  Action::Redirect{
                      redirect_to: redirect.to_string()
                  }
              },
              _ => {
                 return Err("Confused by output".to_string());
              }
        };
        
        let output = Output{
            acceptor: acceptor,
            action: action
        };
        
        Ok((port, input, output))
    } else {
        Err("Instructions should be a JSON object".to_string())
    }

}

fn load_config(path: &Path, data: &Mutex<HashMap<Input, Output>>, port_config_tx: FutureSender<BTreeSet<Port>>) -> Result<(), String> {
    let mut bytes = Vec::new();
    
    File::open(path).unwrap().read_to_end(&mut bytes).unwrap();
    
    let json_str = String::from_utf8(bytes).unwrap();
    let json_ob = json::parse(&json_str).map_err(|e| format!("Configuration file JSON parse failed: {:?}", e))?;
    
    let json_ob = if let JsonValue::Object(json_ob) = json_ob { json_ob } else {
        return Err("Configuration file should be an object".to_string());
    };
    
    let mut inputs = HashMap::new();

    let mut listen_ports = BTreeSet::new();
    
    for (incoming_url_str, value) in json_ob.iter() {
        match process_config_item(incoming_url_str, value) {
            Ok( (port, input, output) ) => {
                println!("Processed rule for {}", incoming_url_str);
                inputs.insert(input, output);
                listen_ports.insert(port);
            }
            Err(e) => {
                println!("Error processing rules for {:?}: {}", incoming_url_str, e);
            }
        }
    }

    *data.lock().expect("config lock failed")= inputs;
    
    let mut core = Core::new().map_err(|e| format!("Internal error: Unable to initialize Core for port configuration send: {:?}", e))?;
    core.run(port_config_tx.send(listen_ports)).map_err(|e| format!("Internal error running port configuration send: {:?}", e))?;
    
    
    Ok( () )
}

fn log_error(res: Result<(), String>) {
    if let Err(e) = res {
        println!("Error: {}", e);
    }
}

fn run_watcher(path: PathBuf, data: Arc<Mutex<HashMap<Input, Output>>>, port_config_tx: FutureSender<BTreeSet<Port>>) -> Result<(), ConfigError> {
    let (tx, rx) = channel();
        
    let mut watcher = notify::watcher(tx, Duration::from_millis(500)).map_err(|_| ConfigError::UnableToWatchFiles)?;
    watcher.watch(&path, RecursiveMode::NonRecursive).map_err(|_| ConfigError::ConfigFileNotFound)?;
    println!("Initial config load");
    log_error(load_config(&path, &data, port_config_tx.clone()));
    
    loop {
        
        if let DebouncedEvent ::Write(_) = rx.recv().map_err(|_| ConfigError::WatchEnded)? {
            println!("Loading config");
            log_error(load_config(&path, &data, port_config_tx.clone()));
        }
    }
}

impl Config {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<(Config, FutureReceiver<BTreeSet<Port>>), ConfigError> {
        let path = path.as_ref().to_path_buf();
        let inner = Arc::new(Mutex::new(HashMap::new()));
        let inner_for_watcher = inner.clone();
        let (port_config_tx, port_config_rx) = future_channel(1); 
        thread::spawn(move || {
            
            match run_watcher(path, inner_for_watcher, port_config_tx) {
                Ok( () ) => {},
                Err( e ) => {
                    println!("config watcher ended: {:?}", e);
                }
            }
        });
        
        Ok((Config{
            inner: inner
        }, port_config_rx))
    }
    
    pub fn get(&self, input: &Input) -> Option<Output> {
        self.inner
            .lock()
            .expect("configuration lock poisoned")
            .get(input)
            .map(|output| (*output).clone())
    }
    
    
    
    
}