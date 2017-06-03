extern crate futures;
extern crate tokio_tls;
extern crate tokio_io;
extern crate native_tls;
extern crate notify;
extern crate byteorder;
#[macro_use] extern crate tokio_core;
extern crate json;
extern crate url;
extern crate bytes;

mod config;
mod copy_and_yield;
mod prefixed_writer;

use copy_and_yield::bipipe;
use prefixed_writer::PrefixedWriter;

use futures::{Future, Stream};

use futures::sync::oneshot;
use tokio_tls::{TlsAcceptorExt};
use std::collections::BTreeSet;
use std::io::{self, ErrorKind};
use std::collections::HashMap;
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::Core;
use tokio_core::reactor::Handle;
use tokio_io::io::read_exact;
use byteorder::{BigEndian, ByteOrder};
use config::{Config, Input};
use std::cell::RefCell;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;


fn cut_prefix(xs: &[u8], cut: usize) -> Result<&[u8], ()> {
    if cut < xs.len() {
        Ok(&xs[cut..])
    } else {
        Err( () )
    }
}

fn u8_chunk(mut xs: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    let cut_len = match xs.get(0) {
        None => { return Err( () ); }
        Some(x) => *x as usize
    };
    xs = &xs[1..];
    if xs.len() < cut_len {
        return Err( () );
    }
    Ok(xs.split_at(cut_len))
}

fn u16_chunk(xs: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    if xs.len() < 2 {
        return Err( () );
    }
    
    let (length_buf, remainder) = xs.split_at(2);
    let cut_len = BigEndian::read_u16(length_buf) as usize;
    if remainder.len() < cut_len {
        return Err( () );
    }
    
    Ok(remainder.split_at(cut_len))
}


fn get_host(handshake: &[u8]) -> Result<String, ()> {
    let remainder = try!(cut_prefix(handshake, 2));
    let (remainder, _) = try!(u16_chunk(remainder));
    let version_skip = 2;
    let random_skip = 32;
    let remainder = try!(cut_prefix(remainder, version_skip + random_skip));
    let (_session, remainder) = try!(u8_chunk(remainder));
    let (_ciphers, remainder) = try!(u16_chunk(remainder));
    let (_compression_methods, remainder) = try!(u8_chunk(remainder));
    let (extensions, _) = try!(u16_chunk(remainder));
    let mut extensions = extensions;
    while extensions.len() > 4 {
        let type_code = BigEndian::read_u16(&extensions[0..2]);
        let (this_extension, other_extensions) = try!(u16_chunk(&extensions[2..]));
        if type_code == 0 {
            let (sni_header, _) = try!(u16_chunk(this_extension));
            let sni_header = try!(cut_prefix(sni_header, 1));
            let (host_name, _) = try!(u16_chunk(sni_header));
            return String::from_utf8(host_name.to_vec()).map_err(|_| ());
        }
        extensions = other_extensions;
    }
    Err( () )
}

struct PortStatus {
    
    shutdown: oneshot::Sender<()>
}

struct ServerStatus {
    config: Config,
    handle: Handle,
    ports: HashMap<u16, PortStatus>
}

impl ServerStatus {
    fn new(config: Config, handle: Handle) -> ServerStatus {
        ServerStatus {
            ports: HashMap::new(),
            config: config,
            handle: handle,
        }
    }
    
    fn run_server_on_port(&self, port: u16, shutdown_rx: oneshot::Receiver<()>) -> Result<(), io::Error> {
        println!("Going to run server on port {}", port);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        let handle = self.handle.clone();
        let config = self.config.clone();
        
        let sock: TcpListener = TcpListener::bind(&addr, &handle)?;
        let server = sock.incoming().for_each(move |(conn, incoming_addr)| {
            println!("Incoming connection from {:?}", incoming_addr);
            let config = config.clone();
            
            //let snied_stream = conn;//detect_hostname(conn);
            let f = read_exact(conn, [0u8; 5]);
            let snied_stream = f.and_then(|(x, handshake_header)| {
                let handshake_len = BigEndian::read_u16(&handshake_header[3..5]) as usize;

                read_exact(x, vec![0u8; handshake_len]).map(move |(x, handshake_content)| {
                    let mut both = vec![0u8; handshake_len + 5];
                    both[0..5].copy_from_slice(&handshake_header[..]);;
                    both[5..].copy_from_slice(&handshake_content[..]);
                    
                    let res = match get_host(&handshake_content[..]) {
                        Ok(host) => host,
                        Err( () ) => String::new(),
                    };
                    (res, PrefixedWriter::new(x, both.into_boxed_slice()))
                })
            });
            
            let handshaken_stream = snied_stream.and_then(move |(host, conn)| {
                println!("Host is {}", host);
                let input = Input{
                    secure: true,
                    port: port,
                    host: host
                };
                println!("Lookingn for input: {:?}", input);
                let output = config.get(&input).expect("Configuration for input not found");
                
                assert!(!output.secure);
                (output.acceptor.accept_async(conn).map_err(|e| io::Error::new(ErrorKind::Other, e)), Ok(output.address))
            });
            
            let local_handle = handle.clone(); // This clone gets consumed by the tls_stream-handling closure
            let do_stuff = handshaken_stream.and_then(move |(tls_stream, address)| {
                println!("We have tls_stream");
                
                let subconnector = TcpStream::connect(&address, &local_handle);
                let handle_conn = subconnector.and_then(|subconn| {
                    println!("Got subconn");
                    bipipe(tls_stream, subconn)
                });
                
                handle_conn
            });
            
            // Spawn expects things that return Item=(), Error=(), so consume them
            let do_stuff = do_stuff.map(|_| println!("got to end of the conn future!")).map_err(|e| println!("Got error! {:?}", e));
            
            // Spawn the future as a concurrent task
            handle.spawn(do_stuff);
        
            Ok(())
        });
        
        let server = server.map_err(|e| {
            println!("Error running server on port: {:?}", e);
        });
        
        let shutdown_rx = shutdown_rx.map_err(|_| ()).map(|_| ());
        
        let server_or_shut_down = server.select(shutdown_rx).map(|((), _)| ()).map_err(|((),_)| ());
        
        self.handle.spawn(server_or_shut_down);
        
        Ok( () )
    }
    
    fn listen_on(&mut self, goal_ports: &BTreeSet<u16>) {
        for goal_port in goal_ports.iter() {
            if !self.ports.contains_key(goal_port) {
                println!("We'd better start listening to {}", goal_port);
                
                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                let x = PortStatus {
                    shutdown: shutdown_tx
                };
                
                match self.run_server_on_port(*goal_port, shutdown_rx) {
                    Ok( () ) => {
                        self.ports.insert(*goal_port, x);
                    }
                    Err(e) => {
                        println!("Failed to listen on port {}: {:?}", goal_port, e);
                    }
                }
            }
        }
        
        let mut to_removes = Vec::new();
        for (port, _) in self.ports.iter_mut() {
            if !goal_ports.contains(port) {
                to_removes.push(*port);
            } 
        }
        
        for to_remove in to_removes {
            println!("Shutting down listener for port {}", to_remove);
            
            if let Some(port_status) = self.ports.remove(&to_remove) {
                let _ = port_status.shutdown.send( () );
            }
        }
    }
    
}



fn main() {
    let (config, port_settings) = Config::new("config.json").expect("Config setup failed");
    
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    
    let port_statuses = RefCell::new(ServerStatus::new(config.clone(), handle.clone()));
    
    let interpret_port_settings = port_settings.for_each(|setting| {
        println!("port settings: {:?}", setting);
        
        port_statuses.borrow_mut().listen_on(&setting);
        Ok( () )
    });
    
    // Spin up the server on the event loop
    core.run(interpret_port_settings.map_err(|e| println!("interpret_port_settings failed: {:?}", e))).unwrap();
}