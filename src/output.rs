use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static FAILURE_RECORDED: AtomicBool = AtomicBool::new(false);

pub fn record_failure() {
    FAILURE_RECORDED.store(true, Ordering::Relaxed);
}

pub fn exit_closed_pipe_keeping_failure() -> ! {
    std::process::exit(i32::from(FAILURE_RECORDED.load(Ordering::Relaxed)))
}

pub fn write_or_exit_on_closed_pipe(
    writer: &mut impl Write,
    args: std::fmt::Arguments<'_>,
) -> anyhow::Result<()> {
    match write_unless_closed(writer, args)? {
        Reader::Open => Ok(()),
        Reader::Closed => exit_closed_pipe_keeping_failure(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Reader {
    Open,
    Closed,
}

pub fn write_unless_closed(
    writer: &mut impl Write,
    args: std::fmt::Arguments<'_>,
) -> anyhow::Result<Reader> {
    match writer.write_fmt(args) {
        Ok(()) => Ok(Reader::Open),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(Reader::Closed),
        Err(e) => Err(e.into()),
    }
}

pub struct ClosedPipeIsEarlyStop<W> {
    inner: W,
    closed: bool,
}

impl<W: Write> ClosedPipeIsEarlyStop<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            closed: false,
        }
    }

    #[cfg(test)]
    pub fn closed(&self) -> bool {
        self.closed
    }
}

impl<W: Write> Write for ClosedPipeIsEarlyStop<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Ok(buf.len());
        }
        match self.inner.write(buf) {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                self.closed = true;
                Ok(buf.len())
            }
            other => other,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        match self.inner.flush() {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                self.closed = true;
                Ok(())
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn a_closed_reader_is_an_early_stop_not_an_error_and_not_an_exit() {
        let mut w = ClosedPipeIsEarlyStop::new(Closed);
        w.write_all(b"hello")
            .expect("a closed pipe is not an error");
        w.flush().expect("nor is the flush");
        assert!(w.closed(), "but the caller can see it happened");
    }

    #[test]
    fn a_closed_reader_is_reported_to_the_caller_not_acted_on() {
        assert_eq!(
            write_unless_closed(&mut Closed, format_args!("x")).expect("not an error"),
            Reader::Closed
        );
        let mut open = Vec::new();
        assert_eq!(
            write_unless_closed(&mut open, format_args!("x")).expect("written"),
            Reader::Open
        );
        assert_eq!(open, b"x");
    }

    #[test]
    fn other_write_errors_still_reach_the_caller() {
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::StorageFull))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut w = ClosedPipeIsEarlyStop::new(Full);
        assert!(w.write_all(b"x").is_err());
        assert!(!w.closed());
    }
}
