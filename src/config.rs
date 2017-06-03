use std::net::SocketAddr;
use native_tls::TlsAcceptor;
use std::sync::RwLock;
use tokio_core::reactor::Core;
use std::sync::mpsc::{channel};
use std::sync::{Arc, Mutex};
use std::rc::Rc;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use futures::{Future, Stream};
use std::thread;
use std::time::Duration;
use notify::{self, Watcher, RecursiveMode, DebouncedEvent};
use json::{self, JsonValue};
use std::io::Read;
use std::fs::File;
use url::Url;

type Port = u16;

#[derive(Hash, Eq, PartialEq, Debug)]
struct Input {
    port: Port,
    host: String,
    secure: bool,
}

#[derive(Clone)]
struct Output {
    acceptor: Arc<TlsAcceptor>,
    port: Port,
    output: SocketAddr,
}

pub struct Config {
    inner: Arc<Mutex<HashMap<Input, Output>>>
}

#[derive(Debug)]
pub enum ConfigError {
    UnableToWatchFiles,
    ConfigFileNotFound,
    WatchEnded,
}


fn load_config(path: &Path, data: &Mutex<HashMap<Input, Output>>) -> Result<(), String> {
    let mut bytes = Vec::new();
    
    File::open(path).unwrap().read_to_end(&mut bytes).unwrap();
    
    let json_str = String::from_utf8(bytes).unwrap();
    let json_ob = json::parse(&json_str).map_err(|e| format!("Configuration file JSON parse failed: {:?}", e))?;
    
    let json_ob = if let JsonValue::Object(json_ob) = json_ob { json_ob } else {
        return Err("Configuration file should be an object".to_string());
    };
    
    let mut inputs = HashMap::new();
    
    for (incoming_url_str, value) in json_ob.iter() {
        
        let incoming_url = Url::parse(incoming_url_str).map_err(|e| format!("Badly formatted host: {}", incoming_url_str))?;
        
        let secure = match incoming_url.scheme() {
            "http" => false,
            "https" => true,
            _ => {
                return Err(format!("Invalid scheme {:?} in URL: {:?}", incoming_url.scheme(), incoming_url_str));
            }
        };
        
        let hostname = incoming_url.host_str().ok_or_else(|| format!("Missing host in {:?}", incoming_url_str))?;
        let input = Input {
            host: hostname.to_string(),
            secure: secure,
            port: incoming_url.port().unwrap_or(if secure { 443 } else { 80 })
        };
        
        println!("{:?}", input);
        if let JsonValue::Object(ref value) = *value {
            let cert = value.get("cert").and_then(|x| x.as_str());
            let target = value.get("target").and_then(|x| x.as_str());
            let _redirect = value.get("target").and_then(|x| x.as_str());
            
            
//            println!("{:?} {:?} {:?} {:?} {:?}", incoming_url.scheme(), incoming_url.host_str(), incoming_url.port(), cert, target);
        }
    }

    *data.lock().expect("config lock failed")= inputs;
    
    Ok( () )
}

fn run_watcher(path: PathBuf, data: Arc<Mutex<HashMap<Input, Output>>>) -> Result<(), ConfigError> {
    let (tx, rx) = channel();
        
    let mut watcher = notify::watcher(tx, Duration::from_millis(500)).map_err(|_| ConfigError::UnableToWatchFiles)?;
    watcher.watch(&path, RecursiveMode::NonRecursive).map_err(|_| ConfigError::ConfigFileNotFound)?;
    println!("Initial config load");
    load_config(&path, &data);
    
    loop {
        
        if let DebouncedEvent ::Write(_) = rx.recv().map_err(|e| ConfigError::WatchEnded)? {
            println!("Loading config");
            load_config(&path, &data);
        }
    }

}

impl Config {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
        let path = path.as_ref().to_path_buf();
        let inner = Arc::new(Mutex::new(HashMap::new()));
        let inner_for_watcher = inner.clone();
        thread::spawn(move || {
            match run_watcher(path, inner_for_watcher) {
                Ok( () ) => {},
                Err( e ) => {
                    println!("config watcher ended: {:?}", e);
                }
            }
        });
        
        Ok(Config{
            inner: inner
        })
    }
    
    pub fn get(&self, input: &Input) -> Option<Output> {
        self.inner
            .lock()
            .expect("configuration lock poisoned")
            .get(input)
            .map(|output| (*output).clone())
    }
    
    
    
    
}