//! The saved report: where a default run puts the complete folded JSON of
//! the run, and how that file is brought to a durable, named state.
//!
//! The default text run streams the same schema-1 JSON records `--format
//! json` emits into `report.jsonl.partial` inside a fresh run directory,
//! writes the summary record at input EOF, then flushes, fsyncs, closes,
//! renames to `report.jsonl` and fsyncs the directory. Only the renamed
//! file is complete: a `.partial` left behind by SIGKILL or power loss is
//! incomplete by definition and recognizable by its name. Nothing beyond
//! that is promised.
//!
//! Filesystem policy: for automatic placement (no `--report-dir`) the
//! directory must sit on a filesystem whose statfs magic is in the
//! documented list below. tmpfs and ramfs are rejected; anything unknown
//! (fuse, overlay, a magic we do not know) is rejected as unknown backing,
//! never described as tmpfs. The classification is conservative — it is
//! never proof of physical storage. An explicit `--report-dir` together
//! with an explicit positive `--report-max-bytes` is the bounded,
//! acknowledged exception and accepts any filesystem.

use anyhow::{Context, Result, anyhow, bail};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// Per-run quota when `--report-max-bytes` is not given. Nothing bounds
/// accumulated disk use across runs; the directory grows until deleted.
pub const DEFAULT_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// statfs magics accepted for automatic placement. Local-backing types
/// first, then remote-backing ones, which are accepted as "remote backing"
/// and not as proven disk.
const LOCAL_BACKING: &[(u64, &str)] = &[
    (0xEF53, "ext2/3/4"),
    (0x5846_5342, "xfs"),
    (0x9123_683E, "btrfs"),
    (0xF2F5_2010, "f2fs"),
    (0x2FC1_2FC1, "zfs"),
];
const REMOTE_BACKING: &[(u64, &str)] = &[
    (0x6969, "nfs"),
    (0xFF53_4D42, "cifs"),
    (0xFE53_4D42, "smb2"),
];
/// Explicitly named so the rejection message can say "tmpfs", which is the
/// one case where naming the filesystem helps the caller fix it.
const MEMORY_BACKED: &[(u64, &str)] = &[(0x0102_1994, "tmpfs"), (0x8584_58F6, "ramfs")];

/// How the report directory was chosen, which decides whether the
/// filesystem policy applies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Placement {
    /// `--report-dir` was given.
    Explicit,
    /// `$LESSENCE_REPORT_DIR` or the XDG state default.
    Automatic,
}

/// Where the report goes, before the run directory exists.
pub fn resolve_dir(explicit: Option<&Path>) -> Result<(PathBuf, Placement)> {
    if let Some(dir) = explicit {
        return Ok((dir.to_path_buf(), Placement::Explicit));
    }
    if let Some(dir) = std::env::var_os("LESSENCE_REPORT_DIR").filter(|d| !d.is_empty()) {
        return Ok((PathBuf::from(dir), Placement::Automatic));
    }
    let state = if let Some(state) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        PathBuf::from(state)
    } else {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .ok_or_else(|| {
                anyhow!("no $XDG_STATE_HOME and no $HOME to derive a report directory from")
            })?;
        PathBuf::from(home).join(".local/state")
    };
    Ok((state.join("lessence/reports"), Placement::Automatic))
}

/// Classify the backing filesystem of the nearest existing ancestor of
/// `dir`. The ancestor rather than `dir` itself so a rejected filesystem is
/// never written to, not even an empty directory.
///
/// Linux and Android only: `statfs` magic numbers are a Linux interface, and
/// every constant above is one. Elsewhere the policy does not apply.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn classify(dir: &Path) -> Result<(u64, &'static str)> {
    let mut probe = dir;
    loop {
        if probe.exists() {
            break;
        }
        probe = probe
            .parent()
            .ok_or_else(|| anyhow!("no existing ancestor of {} to check", dir.display()))?;
        if probe.as_os_str().is_empty() {
            probe = Path::new(".");
            break;
        }
    }
    let stat = nix::sys::statfs::statfs(probe)
        .with_context(|| format!("statfs {} failed", probe.display()))?;
    #[allow(clippy::cast_sign_loss, clippy::useless_conversion)]
    let magic = u64::from(stat.filesystem_type().0 as u64);
    for (m, name) in LOCAL_BACKING.iter().chain(REMOTE_BACKING) {
        if *m == magic {
            return Ok((magic, name));
        }
    }
    for (m, name) in MEMORY_BACKED {
        if *m == magic {
            return Ok((magic, name));
        }
    }
    Ok((magic, "unknown"))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn classify(_dir: &Path) -> Result<(u64, &'static str)> {
    Ok((0, "unchecked"))
}

/// Apply the filesystem policy. `bounded_exception` is true only when both
/// `--report-dir` and a positive `--report-max-bytes` were given.
pub fn check_filesystem(dir: &Path, placement: Placement, bounded_exception: bool) -> Result<()> {
    if placement == Placement::Explicit && bounded_exception {
        return Ok(());
    }
    if cfg!(not(any(target_os = "linux", target_os = "android"))) {
        return Ok(());
    }
    let (magic, name) = classify(dir)?;
    if LOCAL_BACKING
        .iter()
        .chain(REMOTE_BACKING)
        .any(|(m, _)| *m == magic)
    {
        return Ok(());
    }
    if MEMORY_BACKED.iter().any(|(m, _)| *m == magic) {
        bail!(
            "{} is on {name}, which is memory, not storage; pass --report-dir DIR on a disk-backed \
             filesystem, or --report-dir DIR --report-max-bytes N to accept it, or --no-report",
            dir.display()
        );
    }
    bail!(
        "backing filesystem unknown (statfs magic {magic:#x}) for {}; pass --report-dir DIR on a \
         known disk-backed filesystem, or --report-dir DIR --report-max-bytes N to accept it, or \
         --no-report",
        dir.display()
    );
}

/// The open spool for one run: `report.jsonl.partial` in a freshly created
/// run directory, with the per-run quota applied to every write.
pub struct Spool {
    dir: PathBuf,
    partial: PathBuf,
    final_path: PathBuf,
    run_id: String,
    writer: Option<BufWriter<File>>,
    written: u64,
    max_bytes: u64,
    /// The overview's pass 1, filled as records are written. Dropped if a
    /// record cannot be indexed; the overview then reads the file instead.
    index: Option<crate::overview::Index>,
    /// Failure-injection seam, compiled in only under the `test-hooks`
    /// feature (see Cargo.toml): `LESSENCE_TEST_FAIL_WRITE=n` makes the
    /// n-th record write fail and `LESSENCE_TEST_FAIL_DIR_FSYNC` fails the
    /// directory fsync, so the contract's failure paths can be exercised
    /// with a controlled fixture instead of `/dev/full`. A distributed
    /// build has neither the fields nor the environment reads.
    #[cfg(feature = "test-hooks")]
    fail_at_write: Option<u64>,
    writes: u64,
    #[cfg(feature = "test-hooks")]
    fail_dir_fsync: bool,
}

fn random_suffix() -> Result<String> {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no OS randomness for the run id: {e}"))?;
    let mut hex = String::with_capacity(8);
    for b in bytes {
        use std::fmt::Write as _;
        write!(hex, "{b:02x}").expect("writing to a String cannot fail");
    }
    Ok(hex)
}

#[cfg(unix)]
fn create_dir_0700(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_dir_0700(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().create(path)
}

/// Create missing parents 0700. Existing directories keep their
/// permissions: an already-present parent is never chmod'ed.
fn create_parents(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
    {
        create_parents(parent)?;
    }
    match create_dir_0700(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(anyhow!("cannot create {}: {e}", dir.display())),
    }
}

#[cfg(unix)]
fn open_0600(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_0600(path: &Path) -> std::io::Result<File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

impl Spool {
    /// Create the run directory exclusively and open the partial file.
    /// Any failure here happens before a single input line is read.
    pub fn create(base: &Path, max_bytes: u64) -> Result<Self> {
        create_parents(base)?;
        let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let mut last_err = None;
        for _ in 0..8 {
            let run_id = format!("run-{stamp}-{}", random_suffix()?);
            let dir = base.join(&run_id);
            // create_dir, not create_dir_all: the leaf must be ours alone.
            match create_dir_0700(&dir) {
                Ok(()) => {
                    let partial = dir.join("report.jsonl.partial");
                    let file = open_0600(&partial).map_err(|e| {
                        let _ = fs::remove_dir(&dir);
                        anyhow!("cannot create {}: {e}", partial.display())
                    })?;
                    return Ok(Self {
                        final_path: dir.join("report.jsonl"),
                        dir,
                        partial,
                        run_id,
                        writer: Some(BufWriter::new(file)),
                        written: 0,
                        index: None,
                        max_bytes,
                        #[cfg(feature = "test-hooks")]
                        fail_at_write: std::env::var("LESSENCE_TEST_FAIL_WRITE")
                            .ok()
                            .and_then(|v| v.parse().ok()),
                        writes: 0,
                        #[cfg(feature = "test-hooks")]
                        fail_dir_fsync: std::env::var_os("LESSENCE_TEST_FAIL_DIR_FSYNC").is_some(),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => bail!("cannot create {}: {e}", dir.display()),
            }
        }
        bail!(
            "cannot create a fresh run directory under {} after 8 attempts{}",
            base.display(),
            last_err.map_or(String::new(), |e| format!(": {e}"))
        )
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    /// Index every record written from here on for an overview of `want`
    /// entries.
    pub fn index_for_overview(&mut self, want: usize) {
        self.index = Some(crate::overview::Index::new(want));
    }

    pub fn take_index(&mut self) -> Option<crate::overview::Index> {
        self.index.take()
    }

    /// Append one JSON record and its newline. Returns an error on quota
    /// exhaustion or any write failure; the caller then removes the partial.
    pub fn write_record(&mut self, record: &str) -> Result<()> {
        self.writes += 1;
        #[cfg(feature = "test-hooks")]
        if self.fail_at_write == Some(self.writes) {
            bail!(
                "injected write failure at record {} (LESSENCE_TEST_FAIL_WRITE)",
                self.writes
            );
        }
        let len = record.len() as u64 + 1;
        if self.written + len > self.max_bytes {
            bail!(
                "report would exceed --report-max-bytes {} (record {} needs {} more bytes)",
                self.max_bytes,
                self.writes,
                len
            );
        }
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| anyhow!("report spool already closed"))?;
        writer
            .write_all(record.as_bytes())
            .and_then(|()| writer.write_all(b"\n"))
            .with_context(|| format!("writing {}", self.partial.display()))?;
        if let Some(index) = self.index.as_mut()
            && index.record(record, self.written).is_err()
        {
            self.index = None;
        }
        self.written += len;
        Ok(())
    }

    /// Flush, fsync, close, rename, fsync the directory. On success the
    /// report is complete; `Ok(Some(error))` means the content is complete
    /// and renamed but its durability could not be confirmed.
    pub fn finish(&mut self) -> Result<Option<String>> {
        let mut writer = self
            .writer
            .take()
            .ok_or_else(|| anyhow!("report spool already closed"))?;
        writer
            .flush()
            .with_context(|| format!("flushing {}", self.partial.display()))?;
        let file = writer
            .into_inner()
            .map_err(|e| anyhow!("flushing {}: {}", self.partial.display(), e.into_error()))?;
        file.sync_all()
            .with_context(|| format!("fsync {}", self.partial.display()))?;
        drop(file);
        fs::rename(&self.partial, &self.final_path).with_context(|| {
            format!(
                "renaming {} to {}",
                self.partial.display(),
                self.final_path.display()
            )
        })?;
        // Directory fsync: the rename is what makes the report complete,
        // and only this makes the rename itself durable.
        #[cfg(not(feature = "test-hooks"))]
        let dir_fsync = File::open(&self.dir).and_then(|d| d.sync_all());
        #[cfg(feature = "test-hooks")]
        let dir_fsync = if self.fail_dir_fsync {
            Err(std::io::Error::other(
                "injected directory fsync failure (LESSENCE_TEST_FAIL_DIR_FSYNC)",
            ))
        } else {
            File::open(&self.dir).and_then(|d| d.sync_all())
        };
        Ok(dir_fsync.err().map(|e| e.to_string()))
    }

    /// Remove the partial and the run directory, best effort. Called on
    /// every handled failure; never touches a renamed `report.jsonl`.
    pub fn discard(&mut self) {
        self.writer.take();
        let _ = fs::remove_file(&self.partial);
        let _ = fs::remove_dir(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_dir_wins_over_environment_and_default() {
        let (dir, placement) = resolve_dir(Some(Path::new("/tmp/x"))).unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/x"));
        assert_eq!(placement, Placement::Explicit);
    }

    #[test]
    fn a_record_that_exactly_fills_the_quota_is_written() {
        let tmp = tempfile::tempdir().unwrap();
        let mut spool = Spool::create(tmp.path(), 11).unwrap();
        spool
            .write_record("0123456789")
            .expect("10 bytes and a newline are exactly the quota");
        assert_eq!(spool.bytes_written(), 11);
    }

    #[cfg(unix)]
    #[test]
    fn a_run_directory_that_cannot_be_created_fails_on_the_first_attempt() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("locked");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o500)).unwrap();
        let err = Spool::create(&base, DEFAULT_MAX_BYTES);
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let Err(err) = err else {
            eprintln!("skipping: this user can write into a 0500 directory");
            return;
        };
        let err = err.to_string();
        assert!(
            err.starts_with("cannot create "),
            "a permission error is reported as itself: {err}"
        );
        assert!(
            !err.contains("8 attempts"),
            "only an already-taken name is retried: {err}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn an_unknown_backing_filesystem_is_not_described_as_memory() {
        let probe = Path::new("/proc");
        let Ok((_magic, "unknown")) = classify(probe) else {
            eprintln!("skipping: /proc is not an unknown-magic filesystem here");
            return;
        };
        let err = check_filesystem(probe, Placement::Automatic, false)
            .expect_err("an unknown backing filesystem is rejected");
        assert!(
            err.to_string().contains("backing filesystem unknown"),
            "{err}"
        );
        assert!(
            !err.to_string().contains("which is memory"),
            "only the memory magics are named as memory: {err}"
        );
    }

    #[test]
    fn a_run_id_is_a_timestamp_and_eight_hex_digits() {
        let suffix = random_suffix().unwrap();
        assert_eq!(suffix.len(), 8, "{suffix}");
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "{suffix}");
        assert_ne!(suffix, random_suffix().unwrap(), "suffixes must differ");
    }

    #[test]
    fn quota_refuses_the_record_that_would_cross_it_and_keeps_the_earlier_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let mut spool = Spool::create(tmp.path(), 16).unwrap();
        spool
            .write_record("0123456789")
            .expect("11 bytes fit in 16");
        let err = spool
            .write_record("0123456789")
            .expect_err("a second 11 bytes must not fit");
        assert!(err.to_string().contains("--report-max-bytes 16"), "{err}");
        assert_eq!(spool.bytes_written(), 11);
    }

    #[test]
    fn finish_renames_the_partial_and_leaves_nothing_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let mut spool = Spool::create(tmp.path(), DEFAULT_MAX_BYTES).unwrap();
        spool.write_record("{}").unwrap();
        let partial = spool.partial.clone();
        let final_path = spool.final_path().to_path_buf();
        assert_eq!(spool.finish().unwrap(), None);
        assert!(!partial.exists(), "the partial must be gone");
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "{}\n");
    }

    #[test]
    fn discard_removes_the_partial_and_the_run_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let mut spool = Spool::create(tmp.path(), DEFAULT_MAX_BYTES).unwrap();
        spool.write_record("{}").unwrap();
        let dir = spool.dir.clone();
        spool.discard();
        assert!(!dir.exists(), "{} must be gone", dir.display());
    }

    #[cfg(unix)]
    #[test]
    fn the_run_directory_is_0700_and_the_file_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let mut spool = Spool::create(tmp.path(), DEFAULT_MAX_BYTES).unwrap();
        spool.write_record("{}").unwrap();
        assert_eq!(
            fs::metadata(&spool.dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&spool.partial).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn tmpfs_is_rejected_by_name_for_automatic_placement_and_accepted_for_the_bounded_pair() {
        let shm = Path::new("/dev/shm");
        if !shm.is_dir() {
            eprintln!("skipping: no /dev/shm on this machine");
            return;
        }
        let err = check_filesystem(shm, Placement::Automatic, false)
            .expect_err("tmpfs must be rejected for automatic placement");
        assert!(err.to_string().contains("tmpfs"), "{err}");
        check_filesystem(shm, Placement::Explicit, true)
            .expect("the explicit dir + explicit quota pair accepts any filesystem");
        assert!(
            check_filesystem(shm, Placement::Explicit, false).is_err(),
            "an explicit dir alone is not the exception"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_known_disk_backed_directory_passes_the_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let (_magic, name) = classify(tmp.path()).unwrap();
        if name == "tmpfs" || name == "unknown" {
            eprintln!("skipping: TMPDIR is on {name}, not a disk-backed filesystem");
            return;
        }
        check_filesystem(tmp.path(), Placement::Automatic, false).expect("{name} must be accepted");
    }
}
