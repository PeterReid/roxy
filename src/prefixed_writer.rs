use futures::{Poll};
use std::io::{self, Read, Write};
use std::cmp::min;
use tokio_io::{AsyncRead, AsyncWrite};
use bytes::Buf;

/// PrefixedWriter wraps a `Read`able object but prefixes the bytes read
/// from it by some byte string.
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

impl<S: Read> AsyncRead for PrefixedWriter<S> {
}


impl<S: AsyncWrite> AsyncWrite for PrefixedWriter<S> {
    fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error>
        where Self: Sized {
        
        self.inner.write_buf(buf)
    }
    
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.inner.shutdown()
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
