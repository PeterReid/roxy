
use std::net::Shutdown;
use tokio_core::net::TcpStream;
use tokio_tls::TlsStream;
use std::io::{Read, Write};

pub trait Closable {
    fn close(&mut self);
}

impl Closable for TcpStream {
    fn close(&mut self) {
        self.shutdown(Shutdown::Both);
    }
}

impl <T: Read + Write> Closable for TlsStream<T> {
    fn close(&mut self) {
        self.get_mut().shutdown();
    }
}

