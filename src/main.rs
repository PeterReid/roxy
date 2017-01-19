extern crate futures;
extern crate tokio_tls;
extern crate native_tls;
#[macro_use] extern crate tokio_core;

mod copy_and_yield;
mod closable;

use copy_and_yield::bipipe;

use futures::{Future, Stream};

use native_tls::{Pkcs12, TlsAcceptor};
use tokio_tls::{TlsAcceptorExt};
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::Core;


/*
struct HostReader<R> {
    inner: Option<HostReadResult<R>>
}

struct HostReadResult<R> {
    read_prefix: Vec<u8>,
    reader: R,
}

impl Future for HostReader {
    type Item = HostReadResult;
    type Error;

    fn poll(&mut self) -> Poll<u64, io::Error> {
        loop {
            let n = try_nb!(self.reader.read(&mut self.buf));
            if n == 0 {
                self.read_done = true;
            } else {
                self.pos = 0;
                self.cap = n;
            }
        }
    }
}*/

fn main() {
    let mut file = File::open("identity.pfx").unwrap();
    let mut pkcs12 = vec![];
    file.read_to_end(&mut pkcs12).unwrap();
    let pkcs12 = Pkcs12::from_der(&pkcs12, "").unwrap();

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    
    let acceptor = TlsAcceptor::builder(pkcs12).unwrap().build().unwrap();
    
    let addr = "0.0.0.0:8443".parse().unwrap();
    let sock: TcpListener = TcpListener::bind(&addr, &handle).unwrap();
    
    let server = sock.incoming().for_each(|(conn, _)| {
        let handshaken_stream = acceptor.accept_async(conn);
        
        let local_handle = handle.clone(); // This clone gets consumed by the tls_stream-handling closure
        let do_stuff = handshaken_stream.map_err(|e| io::Error::new(ErrorKind::Other, e)).and_then(move |tls_stream| {
            println!("We have tls_stream");
            
            let addr = "127.0.0.1:8059".parse().unwrap();
            let subconnector = TcpStream::connect(&addr, &local_handle);
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
    
    
    // Spin up the server on the event loop
    core.run(server).unwrap();
    
    /*
    
    fn handle_client(mut stream: TlsStream<TcpStream>) {
        println!("Handling client");
        //let mut xs = vec![];
        //stream.read_to_end(&mut xs).expect("read_to_end failed");
        stream.write_all(
          b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length:4\r\n\r\nHere\r\n").expect("write_all failed");

    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let acceptor = acceptor.clone();
                thread::spawn(move || {
                    let stream = acceptor.accept(stream).unwrap();
                    handle_client(stream);
                });
            }
            Err(e) => { panic!("connection failed {:?}", e) /* connection failed */ }
        }
    }*/
}