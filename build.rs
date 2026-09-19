//! Embeds build identity into `--version`.
//!
//! Two binaries reporting the same semver can behave differently: any commit
//! between releases changes behaviour without changing `version` in
//! Cargo.toml. `--version` therefore also reports the commit it was built
//! from, whether the tree was dirty, and the target triple — the last because
//! the musl and glibc builds of this crate differ in allocator (see the
//! comment on `mimalloc` in Cargo.toml) and are routinely mistaken for each
//! other during benchmarking.
//!
//! Precedence: `LESSENCE_BUILD_ID` (set by the release workflow, and the only
//! source that works inside the cross-rs containers, which have no git) → the
//! local git checkout → `unknown` (crates.io tarballs carry no `.git`).

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn main() {
    println!("cargo:rerun-if-env-changed=LESSENCE_BUILD_ID");
    // Watch the source tree so the dirty flag stays honest, and enough of git
    // that a commit refreshes the hash even when no source file changed.
    // `--git-path` resolves correctly inside worktrees, where `.git` is a file.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    // `--skill` embeds these (src/skill.rs): a skill-only edit must refresh
    // the dirty marker the printed provenance carries.
    println!("cargo:rerun-if-changed=.claude/skills/lessence/SKILL.md");
    println!("cargo:rerun-if-changed=.claude/skills/lessence/references/flags.md");
    for path in ["HEAD", "index"] {
        if let Some(resolved) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={resolved}");
        }
    }
    // HEAD only records which branch is checked out; committing rewrites the
    // branch's ref file, not HEAD. Without watching the ref too, a commit that
    // touches no source leaves the embedded hash pointing at its parent — the
    // exact stale-identity problem this whole file exists to prevent.
    if let Some(branch) = git(&["symbolic-ref", "--quiet", "HEAD"])
        && let Some(resolved) = git(&["rev-parse", "--git-path", &branch])
    {
        println!("cargo:rerun-if-changed={resolved}");
    }

    let build_id = std::env::var("LESSENCE_BUILD_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        // CI passes the full 40-char sha; show the same 9 chars git does.
        .map(|s| {
            if s.len() > 9 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                s[..9].to_string()
            } else {
                s
            }
        })
        .or_else(|| {
            let hash = git(&["rev-parse", "--short=9", "HEAD"])?;
            // `--porcelain` prints one line per modified path; empty means clean.
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_some();
            Some(if dirty { format!("{hash}-dirty") } else { hash })
        })
        .unwrap_or_else(|| "unknown".to_string());

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=LESSENCE_BUILD_ID={build_id}");
    println!("cargo:rustc-env=LESSENCE_TARGET={target}");
}
