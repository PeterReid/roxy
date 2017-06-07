

use byteorder::{ByteOrder, LittleEndian};
use futures::{Future, Poll, Async};
use std::io;
use std::io::{ErrorKind, Cursor};
use std::mem::swap;
use tokio_io::AsyncRead;

pub struct Cutter<R> {
    source: Option<R>,
    buffered: Vec<u8>,
}

impl<R> Cutter<R> {
    pub fn new(source: R, initial_buffer: Vec<u8>) -> Cutter<R> {
        Cutter {
            source: Some(source),
            buffered: initial_buffer,
        }
    }
}

impl<R: AsyncRead> Future for Cutter<R> {
    type Item = (Vec<u8>, R);
    type Error = io::Error;
    
    fn poll(&mut self) -> Poll<(Vec<u8>, R), io::Error> {
        loop {
            let mut litte_buf = [0u8];
            match self.source {
                Some(ref mut source) => {
                    let mut c = Cursor::new(&mut litte_buf);
                    match source.read_buf(&mut c) {
                        Ok(Async::Ready(1)) => {
                            //println!("Got a byte!");
                        }
                        Ok(Async::Ready(0)) => {
                            // End of stream
                            return Err(io::Error::new(ErrorKind::Other, "end of stream reached before double-linebreak"));
                        }
                        Ok(Async::Ready(_)) => {
                            unreachable!();
                        }
                        Ok(Async::NotReady) => {
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            return Err(e)
                        }
                    }
                }
                None => {
                    panic!("poll called after delimiter reached");
                }
            }
            self.buffered.push(litte_buf[0]);
            
            if self.buffered.len() >= 4 {
                let suffix = LittleEndian::read_u32(&self.buffered[self.buffered.len()-4..]);
                let rnrn = ((b'\r' as u32) << 0)
                    | ((b'\n' as u32) << 8)
                    | ((b'\r' as u32) << 16)
                    | ((b'\n' as u32) << 24);
                //println!("suffix = {}", suffix);
                if suffix == rnrn {
                    //println!("That's it!");
                    let mut xs = vec![];
                    swap(&mut xs, &mut self.buffered);
                    
                    return Ok(Async::Ready((xs, self.source.take().expect("Cutter missing source contents"))));
                }
            }
            //println!("Got {}", litte_buf[0]);
        }
    }
}
