use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

#[test]
fn closed_output_pipe_is_a_successful_early_stop() {
    let input = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(input.path(), "worker finished\n").unwrap();
    for args in [vec!["-q"], vec!["-q", "--top", "1"]] {
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(reader);
        let writer: OwnedFd = writer.into();
        let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
            .args(&args)
            .stdin(File::open(input.path()).unwrap())
            .stdout(Stdio::from(writer))
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{args:?}: {output:?}");
        assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn full_output_device_is_an_error_not_a_closed_pipe() {
    let input = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(input.path(), "worker finished\n").unwrap();
    for args in [vec!["-q"], vec!["-q", "--top", "1"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
            .args(&args)
            .stdin(File::open(input.path()).unwrap())
            .stdout(OpenOptions::new().write(true).open("/dev/full").unwrap())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(!output.stderr.is_empty(), "failure must be reported");
    }
}
