use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::Stdio;

#[test]
fn closed_output_pipe_is_a_successful_early_stop() {
    let input = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(input.path(), "worker finished\n").unwrap();
    for args in [vec!["-q"], vec!["-q", "--top", "1"]] {
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(reader);
        let writer: OwnedFd = writer.into();
        let output = crate::common::lessence()
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

/// Every mode that streams to stdout instead of saving a report.
const STREAMING_MODES: [&[&str]; 5] = [
    &["--no-report"],
    &["--format", "json"],
    &["--summary"],
    &["--top", "1"],
    &["--preflight"],
];

/// Run lessence with the reader of its stdout already gone, so the first
/// write of any mode meets a closed pipe.
fn run_with_closed_stdout(args: &[&str], stdin: Stdio) -> std::process::Output {
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);
    let writer: OwnedFd = writer.into();
    crate::common::lessence()
        .args(args)
        .stdin(stdin)
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn invented_log() -> tempfile::NamedTempFile {
    let log = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        log.path(),
        "courier 11 picked parcel north\n\
         courier 12 picked parcel north\n\
         courier 13 picked parcel north\n\
         courier 14 picked parcel north\n\
         ledger mismatch on drawer seven\n",
    )
    .unwrap();
    log
}

#[test]
fn a_closed_reader_never_erases_a_failure_the_run_already_found() {
    let log = invented_log();
    let path = log.path().to_str().unwrap();
    for mode in STREAMING_MODES {
        let gated = [mode, &["--fail-on-pattern", "ledger mismatch"]].concat();
        let out = run_with_closed_stdout(&gated, Stdio::from(File::open(log.path()).unwrap()));
        assert_eq!(
            out.status.code(),
            Some(1),
            "{gated:?}: a --fail-on-pattern match must survive the closed pipe: {out:?}"
        );

        let missing = [mode, &[path, "no/such/source.log"]].concat();
        let out = run_with_closed_stdout(&missing, Stdio::null());
        assert_eq!(
            out.status.code(),
            Some(1),
            "{missing:?}: a source that could not be read must survive the closed pipe: {out:?}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("Broken pipe"), "{missing:?}: {stderr}");
    }
}

#[test]
fn a_closed_reader_alone_stays_exit_0_on_every_streaming_path() {
    let log = invented_log();
    let empty = tempfile::NamedTempFile::new().unwrap();
    for input in [log.path(), empty.path()] {
        for mode in STREAMING_MODES {
            let out = run_with_closed_stdout(mode, Stdio::from(File::open(input).unwrap()));
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{mode:?} on {input:?}: {stderr}"
            );
            assert!(
                !stderr.contains("Broken pipe"),
                "{mode:?} on {input:?}: a closed reader is no error: {stderr}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn full_output_device_is_an_error_not_a_closed_pipe() {
    let input = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(input.path(), "worker finished\n").unwrap();
    for args in [vec!["-q"], vec!["-q", "--top", "1"]] {
        let output = crate::common::lessence()
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
