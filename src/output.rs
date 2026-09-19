//! Shared output handling for CLI renderers.
use std::io::{self, Write};

/// Write output, treating a reader closing its pipe as a successful early stop.
/// Other output failures are returned to the caller.
pub fn write_output(writer: &mut impl Write, args: std::fmt::Arguments<'_>) -> anyhow::Result<()> {
    match writer.write_fmt(args) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => std::process::exit(0),
        Err(e) => Err(e.into()),
    }
}

/// A writer that treats the reader closing the pipe as an early stop —
/// without deciding the exit code, which is the caller's to keep.
///
/// The report path needs this: by the time the overview is written the run
/// may already have failed (a failed source, `--fail-on-pattern`, an
/// unconfirmed directory fsync), and a consumer closing its end of the pipe
/// must not turn that determined non-zero exit into a success. Both the
/// writes and the final flush are handled here, and the report on disk is
/// untouched either way.
pub struct PipeTolerant<W> {
    inner: W,
    closed: bool,
}

impl<W: Write> PipeTolerant<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            closed: false,
        }
    }

    /// Did the reader close its end?
    pub fn closed(&self) -> bool {
        self.closed
    }
}

impl<W: Write> Write for PipeTolerant<W> {
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
        let mut w = PipeTolerant::new(Closed);
        w.write_all(b"hello")
            .expect("a closed pipe is not an error");
        w.flush().expect("nor is the flush");
        assert!(w.closed(), "but the caller can see it happened");
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
        let mut w = PipeTolerant::new(Full);
        assert!(w.write_all(b"x").is_err());
        assert!(!w.closed());
    }
}
