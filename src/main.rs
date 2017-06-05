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
mod cutter;

use copy_and_yield::bipipe;
use prefixed_writer::PrefixedWriter;

use futures::{Future, Stream};
use cutter::Cutter;

use futures::sync::oneshot;
use futures::future::Either;
use tokio_tls::{TlsAcceptorExt};
use std::collections::BTreeSet;
use std::io::{self, ErrorKind};
use std::collections::HashMap;
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::Core;
use tokio_core::reactor::Handle;
use tokio_io::io::read_exact;
use tokio_io::io::read;
use tokio_io::io::write_all;
use std::str;
use byteorder::{BigEndian, ByteOrder};
use config::{Config, Input, Action};
use std::cell::RefCell;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::rc::Rc;

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
    ports: HashMap<u16, PortStatus>,
    source_address: Rc<RefCell<HashMap<u16, SocketAddr>>>,
}

fn looks_like_http(x: &[u8]) -> bool {
    x.iter().all(|b| *b>=0x20 && *b<=0x7e) 
}


fn get_between<'a>(haystack: &'a [u8], prefix: &[u8], suffix: &[u8]) -> Option<&'a [u8]> {
    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|window| window == needle)
    }

    let prefix_pos = if let Some(prefix_pos) = find(haystack, prefix) {
        prefix_pos
    } else {
        return None;
    };
    
    let haystack = &haystack[prefix_pos + prefix.len()..];
    let between_len = if let Some(between_len) = find(haystack, suffix) {
        between_len
    } else {
        return None;
    };
    
    Some(&haystack[..between_len])
}

impl ServerStatus {
    fn new(config: Config, handle: Handle) -> ServerStatus {
        ServerStatus {
            ports: HashMap::new(),
            config: config,
            handle: handle,
            source_address: Rc::new(RefCell::new(HashMap::new())),
        }
    }
    
    fn run_server_on_port(&self, port: u16, shutdown_rx: oneshot::Receiver<()>) -> Result<(), io::Error> {
        println!("Going to run server on port {}", port);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        let handle = self.handle.clone();
        let config = self.config.clone();
        let source_address = self.source_address.clone();
        
        let sock: TcpListener = TcpListener::bind(&addr, &handle)?;
        let server = sock.incoming().for_each(move |(conn, incoming_addr)| {
            let source_address = source_address.clone();
            //println!("Incoming connection from {:?}", incoming_addr);
            let config = config.clone();
            
            //let snied_stream = conn;//detect_hostname(conn);
            let f = read_exact(conn, [0u8; 5]);
            let local_handle = handle.clone(); // This clone gets consumed by the tls_stream-handling closure
            
            let do_stuff = f.and_then(move |(x, handshake_header)| {
                if looks_like_http(&handshake_header[..]) {
                    //println!("Looks like HTTP");
                    Either::A(Cutter::new(x, handshake_header.to_vec())
                        .and_then(move |(http_header, x)| {
                            //println!("Got HTTP header: {:?}", str::from_utf8(&http_header));
                            
                            //let path = get_between(http_header, b"\r\nHost: ", b"\r\n");
                            let input = Input{
                                secure: false,
                                port: port,
                                host: get_between(&http_header, b"\r\nHost: ", b"\r\n")
                                    .and_then(|host| String::from_utf8(host.to_vec()).ok())
                                    .unwrap_or_else(|| "*".to_string())
                            };
                            //println!("Input = {:?}", input);
                            
                            let output = config.get(&input).expect("Configuration for input not found");
                            assert!(!output.acceptor.is_some());
                            let handle = match output.action {
                                Action::Forward{address, secure} => {
                                    assert!(!secure);
                                    let x = PrefixedWriter::new(x, http_header.into_boxed_slice());
                                    let handle_http = 
                                        TcpStream::connect(&address, &local_handle)
                                        .and_then(|subconn| {
                                            //println!("Got HTTP subconn");
                                            bipipe(x, subconn)
                                        });
                                    Either::A(handle_http)
                                }
                                Action::Redirect{redirect_to} => {
                                    let path = get_between(&http_header, b" ", b" ").unwrap_or(b"/");
                                    let mut response = Vec::with_capacity(60 + redirect_to.len() + path.len());
                                    response.extend_from_slice(b"HTTP/1.1 301 Moved Permanently\r\nLocation: ");
                                    response.extend_from_slice(redirect_to.as_bytes());
                                    response.extend_from_slice(path);
                                    response.extend_from_slice(b"\r\n\r\n");
                                    
                                    Either::B(write_all(x, response).map(|_| ()))
                                }
                            };
                            handle
                        }))
                } else {
                    //println!("Looks like HTTPS");
                    let handshake_len = BigEndian::read_u16(&handshake_header[3..5]) as usize;
                    
                    let handle_https = read_exact(x, vec![0u8; handshake_len]).map(move |(x, handshake_content)| {
                        let mut both = vec![0u8; handshake_len + 5];
                        both[0..5].copy_from_slice(&handshake_header[..]);;
                        both[5..].copy_from_slice(&handshake_content[..]);
                        
                        let res = match get_host(&handshake_content[..]) {
                            Ok(host) => host,
                            Err( () ) => String::new(),
                        };
                        (res, PrefixedWriter::new(x, both.into_boxed_slice()))
                    }).and_then(move |(host, conn)| {
                        //println!("Host is {}", host);
                        let input = Input{
                            secure: true,
                            port: port,
                            host: host
                        };
                        //println!("Lookingn for input: {:?}", input);
                        let output = config.get(&input).expect("Configuration for input not found");
                        
                        (output.acceptor.expect("Missing acceptor for secure input").accept_async(conn).map_err(|e| io::Error::new(ErrorKind::Other, e)), Ok(output.action))
                    }).and_then(move |(tls_stream, action)| {
                        //println!("We have tls_stream");
                        let handle_conn = match action {
                            Action::Forward{address, secure} => {
                                assert!(!secure);
                                let subconnector = TcpStream::connect(&address, &local_handle);
                                let handle_conn = subconnector.and_then(move |subconn| {
                                    if let Ok(subconn_local_addr) = subconn.local_addr() {
                                        //println!("Subconn port = {}", subconn_local_addr.port());
                                        source_address.borrow_mut().insert(subconn_local_addr.port(), incoming_addr);
                                    }
                                    //println!("Got subconn");
                                    bipipe(tls_stream, subconn)
                                });
                                Either::A(handle_conn.map(|_| ()))
                            }
                            Action::Redirect{redirect_to} => {
                                let cutter = Cutter::new(tls_stream, Vec::new())
                                    .and_then(move |(http_header, x)| {
                                        let path = get_between(&http_header, b" ", b" ").unwrap_or(b"/");
                                        let mut response = Vec::with_capacity(60 + redirect_to.len() + path.len());
                                        response.extend_from_slice(b"HTTP/1.1 301 Moved Permanently\r\nLocation: ");
                                        response.extend_from_slice(redirect_to.as_bytes());
                                        response.extend_from_slice(path);
                                        response.extend_from_slice(b"\r\n\r\n");
                                        
                                        write_all(x, response)
                                    });
                                Either::B(cutter.map(|_| ()))
                            }
                        };
                        handle_conn
                    });
                    
                    Either::B(handle_https)
                }
            });
            
            // Spawn expects things that return Item=(), Error=(), so consume them
            let do_stuff = do_stuff.map(|_| ()).map_err(|e| println!("Got error! {:?}", e));
            
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

fn run_port_server(handle: Handle, server_status: Rc<RefCell<ServerStatus>>) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 10030);
    
    let sock: TcpListener = if let Ok(sock) = TcpListener::bind(&addr, &handle) {
            sock
        } else {
            println!("Unable to set up port_server on {:?}", addr);
            return;
        };
        
    let run = sock.incoming().for_each(move |(conn, _)| {
        let server_status = server_status.clone();
        println!("got a port query conn");
        let xs = vec![0; 1024];
        read(conn, xs)
            .and_then(move |(stream, buf, read_len)| {
                let buf = &buf[..read_len];
                let url_start = buf.iter().position(|x| *x==b'/').map(|pos| pos+1);
                let url_len = url_start.and_then(|start| buf[start..].iter().position(|x| *x==b' '));
                let port_query = if let (Some(url_start), Some(url_len)) = (url_start, url_len) {
                    str::from_utf8(&buf[url_start..url_start+url_len]).ok().and_then(|str| str.parse::<u16>().ok())
                } else {
                    None
                };
                
                let (status_code, content) = if let Some(port_query) = port_query {
                    println!("querying about port {}", port_query);
                    let x = server_status.borrow();
                    let y = x.source_address.borrow();
                    let content = y.get(&port_query).map(|x| format!("{}", x.ip())).unwrap_or("?".to_string());
                    
                    ("200 OK", content)
                } else {
                    println!("bad request");
                    ("400 Bad Request", "Use GET /1234".to_owned())
                };
                let response = format!("HTTP/1.0 {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    status_code, content.len(), content);
                write_all(stream, response)
            }).map(|_| ())
    })
    .map_err(|e| println!("Error running port_server: {:?}", e));
    
    handle.spawn(run);
}

fn main() {
    let (config, port_settings) = Config::new("config.json").expect("Config setup failed");
    
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    
    let port_statuses = Rc::new(RefCell::new(ServerStatus::new(config.clone(), handle.clone())));
    
    let interpret_port_settings = port_settings.for_each(|setting| {
        println!("port settings: {:?}", setting);
        
        port_statuses.borrow_mut().listen_on(&setting);
        Ok( () )
    });
    
    run_port_server(handle.clone(), port_statuses.clone());
    
    // Spin up the server on the event loop
    core.run(interpret_port_settings.map_err(|e| println!("interpret_port_settings failed: {:?}", e))).unwrap();
}