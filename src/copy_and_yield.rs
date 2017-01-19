use std::io::{self, Read, Write};
use futures::{Future, Poll, Async};
use closable::Closable;
use tokio_core::io::Io;

struct StreamState {
    read_done: bool,
    pos: usize,
    cap: usize,
    buf: Box<[u8]>,
}

impl StreamState {
    fn new() -> StreamState {
        StreamState {
            read_done: false,
            pos: 0,
            cap: 0,
            buf: Box::new([0; 2048]),
        }
    }
    
    fn pump<A: Read, B: Write+Closable>(&mut self, from: &mut A, to: &mut B) -> Poll<(), io::Error> {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let n = try_nb!(from.read(&mut self.buf));
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let i = try_nb!(to.write(&self.buf[self.pos..self.cap]));
                self.pos += i;
            }

            // If we've written al the data and we've seen EOF, flush out the
            // data and finish the transfer.
            // done with the entire transfer.
            if self.pos == self.cap && self.read_done {
                try_nb!(to.flush());
                return Ok(().into())
            }
        }
    }
}

pub struct BiPipe<A, B> {
    a: A,
    b: B,
    a_to_b: StreamState,
    b_to_a: StreamState,
}

pub fn bipipe<A, B>(a: A, b: B) -> BiPipe<A, B>
    where A: Io + Closable,
          B: Io + Closable,
{
    BiPipe {
        a: a,
        b: b,
        a_to_b: StreamState::new(),
        b_to_a: StreamState::new(),
    }
}


impl<A: Closable, B: Closable> BiPipe<A, B> {
    
    fn close_both(&mut self) {
        self.a.close();
        self.b.close();
    }
    
}

impl<A, B> Future for BiPipe<A, B>
    where A: Io + Closable,
          B: Io + Closable,
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        match self.a_to_b.pump(&mut self.a, &mut self.b) {
            Err(e) => {
                self.close_both();
                return Err(e);
            },
            Ok(Async::Ready(())) => {
                self.close_both();
                return Ok(Async::Ready(()))
            },
            Ok(Async::NotReady) => {
                
            }
        }
        
        match self.b_to_a.pump(&mut self.b, &mut self.a) {
            Err(e) => {
                self.close_both();
                return Err(e);
            },
            Ok(Async::Ready(())) => {
                self.close_both();
                return Ok(Async::Ready(()))
            },
            Ok(Async::NotReady) => {
                return Ok(Async::NotReady)
            }
        }
    }
}