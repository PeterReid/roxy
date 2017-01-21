use tokio_core::io::Io;
use futures::Async;
use std::io::{self, Read, Write};
use std::cmp::min;

pub struct PrefixedWriter<S> {
    inner: S,
    prefix: Option<Box<[u8]>>,
    offset: usize,
}

impl<S> PrefixedWriter<S> {
    pub fn new(inner: S, prefix: Box<[u8]>) -> PrefixedWriter<S> {
        PrefixedWriter {
            inner: inner,
            prefix: 
                if prefix.len() == 0 {
                    None
                } else {
                    Some(prefix)
                },
            offset: 0
        }
    }
}

impl<S: Io> Io for PrefixedWriter<S> {
    fn poll_read(&mut self) -> Async<()> {
        if self.prefix.is_none() {
            self.inner.poll_read()
        } else {
            Async::Ready( () )
        }
    }
    
    fn poll_write(&mut self) -> Async<()> {
        self.inner.poll_write()
    }
}

impl<S: Read> Read for PrefixedWriter<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (ret, done) = match self.prefix {
            None => return self.inner.read(buf),
            Some(ref xs) => {
                let can_write = min(xs.len() - self.offset, buf.len());
                
                buf[..can_write].copy_from_slice(&xs[self.offset..self.offset + can_write]);
                
                self.offset += can_write;
                
                (Ok(can_write), self.offset == xs.len())
            }
        };
        
        if done {
            self.prefix = None;
        }
        
        ret
    }
}

impl<S: Write> Write for PrefixedWriter<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
