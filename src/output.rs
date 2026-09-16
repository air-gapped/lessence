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
