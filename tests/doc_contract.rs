//! Doc-contract tests — the release gate that makes shipped doc surfaces
//! (README, agent skill) physically unable to drift from the binary.
//!
//! Mechanism: README sections between `<!-- gen:NAME:begin -->` /
//! `<!-- gen:NAME:end -->` markers are GENERATED from the clap command
//! definition and from running the binary on a committed fixture. The tests
//! fail when the committed region differs from what the binary produces.
//!
//! Regenerate stale regions with `make docs`
//! (= `LESSENCE_UPDATE_DOCS=1 cargo test --release --test doc_contract`).
//!
//! These tests run in the default suite, so they fire in `make ci`, the
//! pre-push hook, and the required `test (ubuntu-latest)` CI check — drift
//! is caught at the commit that introduces it, on every path to a release.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_path(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// Assert that the `<!-- gen:{name}:begin/end -->` region in `rel_path`
/// matches `want`. With `LESSENCE_UPDATE_DOCS` set, rewrite the region
/// instead (and pass).
fn assert_generated_region(rel_path: &str, name: &str, want: &str) {
    let begin_marker = format!("<!-- gen:{name}:begin -->");
    let end_marker = format!("<!-- gen:{name}:end -->");
    let content = read(rel_path);
    let lines: Vec<&str> = content.lines().collect();

    let begins: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim() == begin_marker)
        .map(|(i, _)| i)
        .collect();
    let ends: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim() == end_marker)
        .map(|(i, _)| i)
        .collect();
    assert!(
        begins.len() == 1 && ends.len() == 1 && begins[0] < ends[0],
        "{rel_path}: expected exactly one {begin_marker} ... {end_marker} region \
         (found {} begin, {} end markers)",
        begins.len(),
        ends.len()
    );
    let (b, e) = (begins[0], ends[0]);

    let current = lines[b + 1..e].join("\n");
    let want_trimmed = want.trim_matches('\n');
    let current_trimmed = current.trim_matches('\n');

    if std::env::var_os("LESSENCE_UPDATE_DOCS").is_some() {
        let mut out: Vec<String> = Vec::new();
        out.extend(lines[..=b].iter().map(|s| (*s).to_string()));
        out.push(want_trimmed.to_string());
        out.extend(lines[e..].iter().map(|s| (*s).to_string()));
        let mut text = out.join("\n");
        if content.ends_with('\n') {
            text.push('\n');
        }
        std::fs::write(repo_path(rel_path), text)
            .unwrap_or_else(|e| panic!("cannot write {rel_path}: {e}"));
        println!("updated {rel_path} gen:{name}");
        return;
    }

    assert!(
        current_trimmed == want_trimmed,
        "{rel_path} gen:{name} region is stale — docs no longer match the binary.\n\
         --- committed\n{current_trimmed}\n+++ generated\n{want_trimmed}\n\
         FIX: run `make docs` (= LESSENCE_UPDATE_DOCS=1 cargo test --test doc_contract),\n\
         review the rewritten regions (a diff here can also mean the CODE regressed —\n\
         check which side is right), and commit them WITH your change."
    );
}

/// Built (realized) clap command for inspection.
fn built_command() -> clap::Command {
    let mut cmd = lessence::cli::command();
    cmd.build();
    cmd
}

/// Render the flags reference from clap — one line per long flag, in
/// declaration order, plus the positional.
fn render_flags() -> String {
    let cmd = built_command();
    let mut out = Vec::new();
    for arg in cmd.get_arguments() {
        if arg.is_hide_set() {
            continue;
        }
        let Some(long) = arg.get_long() else { continue };
        if long == "help" || long == "version" {
            continue;
        }
        let mut line = format!("--{long}");
        for alias in arg.get_all_aliases().unwrap_or_default() {
            line.push_str(&format!(" (alias: --{alias})"));
        }
        if let Some(c) = arg.get_short() {
            line.push_str(&format!(" (-{c})"));
        }
        let takes_value = arg.get_num_args().is_some_and(|r| r.takes_values());
        if takes_value {
            let value_name = arg
                .get_value_names()
                .and_then(|v| v.first().map(std::string::ToString::to_string))
                .unwrap_or_else(|| arg.get_id().as_str().to_uppercase());
            line.push_str(&format!(" <{value_name}>"));
        }
        let help = arg
            .get_help()
            .map(|h| h.to_string().lines().next().unwrap_or("").to_string())
            .unwrap_or_default();
        line.push_str(&format!("    {help}"));
        let defaults = arg.get_default_values();
        if !defaults.is_empty() {
            let v: Vec<String> = defaults
                .iter()
                .map(|d| d.to_string_lossy().into_owned())
                .collect();
            line.push_str(&format!(" [default: {}]", v.join(",")));
        }
        out.push(line);
    }
    for arg in cmd.get_positionals() {
        if arg.is_hide_set() {
            continue;
        }
        let value_name = arg
            .get_value_names()
            .and_then(|v| v.first().map(std::string::ToString::to_string))
            .unwrap_or_else(|| arg.get_id().as_str().to_uppercase());
        let help = arg
            .get_help()
            .map(|h| h.to_string().lines().next().unwrap_or("").to_string())
            .unwrap_or_default();
        out.push(format!("{value_name}...    {help}"));
    }
    format!("```\n{}\n```", out.join("\n"))
}

fn thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[test]
fn readme_flags_block() {
    assert_generated_region("README.md", "flags", &render_flags());
}

#[test]
fn readme_pattern_names() {
    let patterns = lessence::cli::VALID_PATTERNS;
    let want = format!(
        "lessence recognizes {} pattern groups (the valid `--disable-patterns` names):\n\n\
         ```\n{}\n```",
        patterns.len(),
        patterns.join(", ")
    );
    assert_generated_region("README.md", "patterns", &want);
}

#[test]
fn readme_headline_example() {
    let fixture = repo_path("tests/fixtures/kubelet_2k.log");
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["-q"])
        .arg(&fixture)
        .output()
        .expect("failed to run lessence");
    assert!(
        output.status.success(),
        "lessence -q {} failed: {}",
        fixture.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let out_lines: Vec<&str> = stdout.lines().collect();
    let in_count = read("tests/fixtures/kubelet_2k.log").lines().count();
    let out_count = out_lines.len();
    let reduction = (1.0 - out_count as f64 / in_count as f64) * 100.0;

    let mut block = String::from("$ lessence kubelet.log\n\n");
    for line in out_lines.iter().take(6) {
        block.push_str(line);
        block.push('\n');
    }
    if out_count > 6 {
        block.push_str("...\n");
    }
    block.push('\n');
    block.push_str(&format!(
        "Original: {} lines → {} lines ({reduction:.1}% reduction)",
        thousands(in_count),
        out_count
    ));
    let want = format!("```\n{block}\n```");
    assert_generated_region("README.md", "example", &want);
}

/// Extract the contents of all fenced code blocks in a markdown document.
fn fenced_blocks(markdown: &str) -> String {
    let mut inside = false;
    let mut out = String::new();
    for line in markdown.lines() {
        if line.trim_start().starts_with("```") {
            inside = !inside;
            continue;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[test]
fn no_impossible_rollup_counts() {
    let cap = lessence::folder::ROLLUP_DISTINCT_CAP;
    let re = regex::Regex::new(r"[a-z_0-9]+×([0-9]+)(\+?)").unwrap();
    for rel in ["README.md", ".claude/skills/lessence/SKILL.md"] {
        let blocks = fenced_blocks(&read(rel));
        for cap_match in re.captures_iter(&blocks) {
            if &cap_match[2] == "+" {
                continue; // documented capped marker, e.g. hash×64+
            }
            let n: usize = cap_match[1].parse().unwrap();
            assert!(
                n <= cap,
                "{rel}: example shows `{}` but per-token distinct rollup caps at {cap} \
                 since 0.4.0 — this example cannot come from the binary; paste a real run",
                &cap_match[0]
            );
        }
    }
}

#[test]
fn skill_flags_coverage() {
    let cmd = built_command();
    let mut primary: Vec<String> = Vec::new();
    let mut known: HashSet<String> = HashSet::new();
    known.insert("--help".to_string());
    known.insert("--version".to_string());
    for arg in cmd.get_arguments() {
        let Some(long) = arg.get_long() else { continue };
        if long == "help" || long == "version" {
            continue;
        }
        known.insert(format!("--{long}"));
        if !arg.is_hide_set() {
            primary.push(format!("--{long}"));
        }
        for alias in arg.get_all_aliases().unwrap_or_default() {
            known.insert(format!("--{alias}"));
        }
    }
    // Flags of OTHER tools that legitimately appear in doc examples
    // (cargo invocations etc.) — not lessence flags, not drift.
    let foreign: HashSet<&str> = ["--release", "--since"].into_iter().collect();

    let flags_md = read(".claude/skills/lessence/references/flags.md");

    // (a) every primary flag is documented in the agent skill
    for flag in &primary {
        assert!(
            flags_md.contains(flag.as_str()),
            "agent skill references/flags.md does not mention `{flag}` — a new or \
             renamed flag must be documented in the skill before release"
        );
    }

    // (b) no stale flag names anywhere in the skill flags doc or the README
    let flag_re = regex::Regex::new(r"--[a-z][a-z0-9-]*").unwrap();
    for (rel, text) in [
        (".claude/skills/lessence/references/flags.md", &flags_md),
        ("README.md", &read("README.md")),
    ] {
        for m in flag_re.find_iter(text) {
            let found = m.as_str();
            assert!(
                known.contains(found) || foreign.contains(found),
                "{rel} mentions `{found}` which is not a flag the binary accepts — \
                 stale or misspelled flag name"
            );
        }
    }

    // every pattern name must be documented in the skill
    for name in lessence::cli::VALID_PATTERNS {
        assert!(
            flags_md.contains(name),
            "agent skill references/flags.md does not mention pattern name `{name}`"
        );
    }
}

#[test]
fn readme_doc_links_exist() {
    let readme = read("README.md");
    let link_re = regex::Regex::new(r"\]\(([^)]+)\)").unwrap();
    for cap in link_re.captures_iter(&readme) {
        let target = &cap[1];
        if target.starts_with("http://")
            || target.starts_with("https://")
            || target.starts_with('#')
            || target.starts_with("mailto:")
        {
            continue;
        }
        let path = target.split('#').next().unwrap();
        let status = Command::new("git")
            .args(["ls-files", "--error-unmatch", path])
            .current_dir(repo_path(""))
            .output()
            .expect("failed to run git");
        assert!(
            status.status.success(),
            "README links to {path} which is not committed — broken on crates.io, \
             where the README is frozen at the tag"
        );
    }
}
