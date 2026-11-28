use anyhow::{Context, Result, anyhow, bail};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub const DEFAULT_PER_RUN_MAX_BYTES: u64 = 1024 * 1024 * 1024;

const LOCAL_BACKING: &[(u64, &str)] = &[
    (0xEF53, "ext2/3/4"),
    (0x5846_5342, "xfs"),
    (0x9123_683E, "btrfs"),
    (0xF2F5_2010, "f2fs"),
    (0x2FC1_2FC1, "zfs"),
    (0x794C_7630, "overlayfs"),
];
const REMOTE_BACKING: &[(u64, &str)] = &[
    (0x6969, "nfs"),
    (0xFF53_4D42, "cifs"),
    (0xFE53_4D42, "smb2"),
];
const NAMED_MEMORY_BACKED_REJECTS: &[(u64, &str)] =
    &[(0x0102_1994, "tmpfs"), (0x8584_58F6, "ramfs")];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Placement {
    FromFlag,
    FromEnvOrXdg,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilesystemPolicy {
    Applies,
    WaivedForExplicitDirAndPositiveQuota,
}

impl Placement {
    pub fn policy(self, positive_quota_given: bool) -> FilesystemPolicy {
        if self == Self::FromFlag && positive_quota_given {
            FilesystemPolicy::WaivedForExplicitDirAndPositiveQuota
        } else {
            FilesystemPolicy::Applies
        }
    }
}

pub fn resolve_dir(explicit: Option<&Path>) -> Result<(PathBuf, Placement)> {
    if let Some(dir) = explicit {
        return Ok((dir.to_path_buf(), Placement::FromFlag));
    }
    if let Some(dir) = std::env::var_os("LESSENCE_REPORT_DIR").filter(|d| !d.is_empty()) {
        return Ok((PathBuf::from(dir), Placement::FromEnvOrXdg));
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
    Ok((state.join("lessence/reports"), Placement::FromEnvOrXdg))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn classify_nearest_existing_ancestor(dir: &Path) -> Result<(u64, &'static str)> {
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
    #[allow(clippy::unnecessary_cast)]
    let magic = filesystem_magic(stat.filesystem_type().0 as i64);
    for (m, name) in LOCAL_BACKING.iter().chain(REMOTE_BACKING) {
        if *m == magic {
            return Ok((magic, name));
        }
    }
    for (m, name) in NAMED_MEMORY_BACKED_REJECTS {
        if *m == magic {
            return Ok((magic, name));
        }
    }
    Ok((magic, "unknown"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn filesystem_magic(raw: i64) -> u64 {
    u64::from(raw as u32)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn classify_nearest_existing_ancestor(_dir: &Path) -> Result<(u64, &'static str)> {
    Ok((0, "unchecked"))
}

/// POSIX only: Windows cannot open a directory as a file.
fn make_rename_durable(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    return File::open(dir).and_then(|d| d.sync_all());
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

pub fn check_filesystem(dir: &Path, policy: FilesystemPolicy) -> Result<()> {
    if policy == FilesystemPolicy::WaivedForExplicitDirAndPositiveQuota {
        return Ok(());
    }
    if cfg!(not(any(target_os = "linux", target_os = "android"))) {
        return Ok(());
    }
    let (magic, name) = classify_nearest_existing_ancestor(dir)?;
    accept_backing(dir, magic, name)
}

fn accept_backing(dir: &Path, magic: u64, name: &str) -> Result<()> {
    if LOCAL_BACKING
        .iter()
        .chain(REMOTE_BACKING)
        .any(|(m, _)| *m == magic)
    {
        return Ok(());
    }
    if NAMED_MEMORY_BACKED_REJECTS.iter().any(|(m, _)| *m == magic) {
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

pub struct Spool {
    dir: PathBuf,
    dirs_to_sync: Vec<PathBuf>,
    partial: PathBuf,
    final_path: PathBuf,
    run_id: String,
    writer: Option<BufWriter<File>>,
    written: u64,
    max_bytes: u64,
    index: OverviewIndex,
    writes: u64,
    #[cfg(feature = "test-hooks")]
    faults: FaultInjection,
}

enum OverviewIndex {
    NotRequested,
    Indexing(crate::overview::Index),
    AbandonedOverviewRereadsTheFile,
}

#[cfg(feature = "test-hooks")]
struct FaultInjection {
    fail_at_write: Option<u64>,
    fail_dir_fsync: bool,
}

#[cfg(feature = "test-hooks")]
impl FaultInjection {
    fn from_env() -> Self {
        Self {
            fail_at_write: std::env::var("LESSENCE_TEST_FAIL_WRITE")
                .ok()
                .and_then(|v| v.parse().ok()),
            fail_dir_fsync: std::env::var_os("LESSENCE_TEST_FAIL_DIR_FSYNC").is_some(),
        }
    }
}

const PARTIAL_NAME: &str = "report.jsonl.partial";
const COMPLETE_NAME: &str = "report.jsonl";

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Finished {
    Durable,
    DurabilityUnconfirmed(String),
}

impl Finished {
    pub fn is_durability_unconfirmed(&self) -> bool {
        matches!(self, Self::DurabilityUnconfirmed(_))
    }
}

impl std::fmt::Display for Finished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Durable => f.write_str("complete"),
            Self::DurabilityUnconfirmed(e) => write!(f, "complete, durability unconfirmed ({e})"),
        }
    }
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
fn create_exclusive_dir_0700(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_exclusive_dir_0700(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().create(path)
}

fn create_missing_parents_0700(dir: &Path, created: &mut Vec<PathBuf>) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
    {
        create_missing_parents_0700(parent, created)?;
    }
    match create_exclusive_dir_0700(dir) {
        Ok(()) => {
            created.push(dir.to_path_buf());
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(anyhow!("cannot create {}: {e}", dir.display())),
    }
}

/// The directories whose entries a finished report depends on: the run
/// directory (the rename), the base (the run directory's entry), and the
/// parent of every ancestor this run created.
fn dirs_holding_new_entries(run_dir: &Path, base: &Path, created: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = vec![run_dir.to_path_buf(), base.to_path_buf()];
    for dir in created {
        let parent = match dir.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        if !dirs.contains(&parent) {
            dirs.push(parent);
        }
    }
    dirs
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
    pub fn create(base: &Path, max_bytes: u64) -> Result<Self> {
        let mut created = Vec::new();
        create_missing_parents_0700(base, &mut created)?;
        let stamp = jiff::Timestamp::now().strftime("%Y%m%d-%H%M%S").to_string();
        let mut last_err = None;
        for _ in 0..8 {
            let run_id = format!("run-{stamp}-{}", random_suffix()?);
            let dir = base.join(&run_id);
            match create_exclusive_dir_0700(&dir) {
                Ok(()) => {
                    let partial = dir.join(PARTIAL_NAME);
                    let file = open_0600(&partial).map_err(|e| {
                        let _ = fs::remove_dir(&dir);
                        anyhow!("cannot create {}: {e}", partial.display())
                    })?;
                    return Ok(Self {
                        final_path: dir.join(COMPLETE_NAME),
                        dirs_to_sync: dirs_holding_new_entries(&dir, base, &created),
                        dir,
                        partial,
                        run_id,
                        writer: Some(BufWriter::new(file)),
                        written: 0,
                        index: OverviewIndex::NotRequested,
                        max_bytes,
                        writes: 0,
                        #[cfg(feature = "test-hooks")]
                        faults: FaultInjection::from_env(),
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

    pub fn index_for_overview(&mut self, want: usize) {
        self.index = OverviewIndex::Indexing(crate::overview::Index::new(want));
    }

    pub fn take_index(&mut self) -> Option<crate::overview::Index> {
        match std::mem::replace(&mut self.index, OverviewIndex::NotRequested) {
            OverviewIndex::Indexing(index) => Some(index),
            OverviewIndex::NotRequested | OverviewIndex::AbandonedOverviewRereadsTheFile => None,
        }
    }

    pub fn write_record(&mut self, record: &str) -> Result<()> {
        self.writes += 1;
        #[cfg(feature = "test-hooks")]
        if self.faults.fail_at_write == Some(self.writes) {
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
        if let OverviewIndex::Indexing(index) = &mut self.index
            && index.record(record, self.written).is_err()
        {
            self.index = OverviewIndex::AbandonedOverviewRereadsTheFile;
        }
        self.written += len;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<Finished> {
        let writer = self
            .writer
            .take()
            .ok_or_else(|| anyhow!("report spool already closed"))?;
        self.flush_fsync_and_close(writer)?;
        self.rename_partial_to_complete()?;
        Ok(match self.fsync_dir_to_make_rename_durable() {
            Ok(()) => Finished::Durable,
            Err(e) => Finished::DurabilityUnconfirmed(e.to_string()),
        })
    }

    fn flush_fsync_and_close(&self, mut writer: BufWriter<File>) -> Result<()> {
        writer
            .flush()
            .with_context(|| format!("flushing {}", self.partial.display()))?;
        let file = writer
            .into_inner()
            .map_err(|e| anyhow!("flushing {}: {}", self.partial.display(), e.into_error()))?;
        file.sync_all()
            .with_context(|| format!("fsync {}", self.partial.display()))?;
        drop(file);
        Ok(())
    }

    fn rename_partial_to_complete(&self) -> Result<()> {
        fs::rename(&self.partial, &self.final_path).with_context(|| {
            format!(
                "renaming {} to {}",
                self.partial.display(),
                self.final_path.display()
            )
        })
    }

    #[cfg(not(feature = "test-hooks"))]
    fn fsync_dir_to_make_rename_durable(&self) -> std::io::Result<()> {
        self.dirs_to_sync
            .iter()
            .try_for_each(|d| make_rename_durable(d))
    }

    #[cfg(feature = "test-hooks")]
    fn fsync_dir_to_make_rename_durable(&self) -> std::io::Result<()> {
        if self.faults.fail_dir_fsync {
            Err(std::io::Error::other(
                "injected directory fsync failure (LESSENCE_TEST_FAIL_DIR_FSYNC)",
            ))
        } else {
            self.dirs_to_sync
                .iter()
                .try_for_each(|d| make_rename_durable(d))
        }
    }

    pub fn discard_partial(&mut self) {
        self.writer.take();
        let _ = fs::remove_file(&self.partial);
        let _ = fs::remove_dir(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_sign_extended_32_bit_filesystem_type_still_names_btrfs() {
        let btrfs = LOCAL_BACKING.iter().find(|(_, n)| *n == "btrfs").unwrap().0;
        let raw_on_32_bit = i64::from(u32::try_from(btrfs).unwrap().cast_signed());
        assert!(raw_on_32_bit < 0);
        assert_eq!(filesystem_magic(raw_on_32_bit), btrfs);
    }

    #[test]
    fn finishing_syncs_the_base_and_the_parent_of_every_directory_this_run_created() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("made").join("base");
        let spool = Spool::create(&base, DEFAULT_PER_RUN_MAX_BYTES).unwrap();
        let run_dir = spool.final_path().parent().unwrap().to_path_buf();
        assert_eq!(
            spool
                .dirs_to_sync
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                run_dir,
                base.clone(),
                tmp.path().join("made"),
                tmp.path().to_path_buf()
            ])
        );

        let again = Spool::create(&base, DEFAULT_PER_RUN_MAX_BYTES).unwrap();
        assert_eq!(
            again.dirs_to_sync.len(),
            2,
            "an existing base adds no ancestors"
        );
    }

    #[test]
    fn explicit_dir_wins_over_environment_and_default() {
        let (dir, placement) = resolve_dir(Some(Path::new("/tmp/x"))).unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/x"));
        assert_eq!(placement, Placement::FromFlag);
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
        let err = Spool::create(&base, DEFAULT_PER_RUN_MAX_BYTES);
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
        let Ok((_magic, "unknown")) = classify_nearest_existing_ancestor(probe) else {
            eprintln!("skipping: /proc is not an unknown-magic filesystem here");
            return;
        };
        let err = check_filesystem(probe, FilesystemPolicy::Applies)
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
        let mut spool = Spool::create(tmp.path(), DEFAULT_PER_RUN_MAX_BYTES).unwrap();
        spool.write_record("{}").unwrap();
        let partial = spool.partial.clone();
        let final_path = spool.final_path().to_path_buf();
        assert_eq!(spool.finish().unwrap(), Finished::Durable);
        assert!(!partial.exists(), "the partial must be gone");
        assert_eq!(fs::read_to_string(&final_path).unwrap(), "{}\n");
    }

    #[test]
    fn discard_removes_the_partial_and_the_run_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let mut spool = Spool::create(tmp.path(), DEFAULT_PER_RUN_MAX_BYTES).unwrap();
        spool.write_record("{}").unwrap();
        let dir = spool.dir.clone();
        spool.discard_partial();
        assert!(!dir.exists(), "{} must be gone", dir.display());
    }

    #[cfg(unix)]
    #[test]
    fn the_run_directory_is_0700_and_the_file_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let mut spool = Spool::create(tmp.path(), DEFAULT_PER_RUN_MAX_BYTES).unwrap();
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
        let err = check_filesystem(shm, Placement::FromEnvOrXdg.policy(false))
            .expect_err("tmpfs must be rejected for automatic placement");
        assert!(err.to_string().contains("tmpfs"), "{err}");
        check_filesystem(shm, Placement::FromFlag.policy(true))
            .expect("the explicit dir + explicit quota pair accepts any filesystem");
        assert!(
            check_filesystem(shm, Placement::FromFlag.policy(false)).is_err(),
            "an explicit dir alone is not the exception"
        );
    }

    #[test]
    fn overlayfs_is_accepted_because_it_is_the_root_of_every_container() {
        let (magic, name) = LOCAL_BACKING
            .iter()
            .copied()
            .find(|&(_, name)| name == "overlayfs")
            .expect("overlayfs is a local backing");
        accept_backing(Path::new("/"), magic, name)
            .expect("rejecting overlayfs fails every default run inside Docker or Podman");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_known_disk_backed_directory_passes_the_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let (_magic, name) = classify_nearest_existing_ancestor(tmp.path()).unwrap();
        if name == "tmpfs" || name == "unknown" {
            eprintln!("skipping: TMPDIR is on {name}, not a disk-backed filesystem");
            return;
        }
        check_filesystem(tmp.path(), FilesystemPolicy::Applies).expect("{name} must be accepted");
    }
}
