use std::io::Write;
use std::process::{Command, Stdio};
use std::str;
use std::sync::LazyLock;

#[path = "../fixtures/log_generator.rs"]
mod log_generator;

#[test]
fn test_constitutional_compliance_generated() {
    // Constitutional compliance test using generated synthetic logs.
    // Verifies that lessence maintains high compression on repetitive
    // kubelet-style patterns. This runs on all builds (debug + release)
    // and doesn't depend on gitignored corpus files.
    //
    // The generator produces 1000 lines across 5 patterns exercising
    // all major token types (UUID, IP, Hash, Path, PodName, Namespace,
    // PID, Timestamp, Duration, QuotedString).
    let input = log_generator::generate_log(1000);
    let input_lines = input.lines().count();

    let mut child = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats", "--threads", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn lessence");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child
        .wait_with_output()
        .expect("Failed to wait for lessence");
    assert!(output.status.success(), "lessence execution failed");

    let compressed = str::from_utf8(&output.stdout).expect("Invalid UTF-8");
    let output_lines = compressed.lines().count();
    let ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Constitutional compliance (generated 1000 lines):");
    println!("  Input: {input_lines}, Output: {output_lines}, Ratio: {ratio:.1}%");

    // 1000 lines with 5 repeating patterns should compress to ≤30 lines.
    // The generator is deterministic so this is a stable assertion.
    assert!(
        output_lines <= 30,
        "Compression regression: {output_lines} > 30 lines from {input_lines} input"
    );
    assert!(
        ratio >= 95.0,
        "Compression ratio {ratio:.1}% < 95.0% on generated kubelet-style logs"
    );

    // Lower bound: too few output lines means over-aggressive folding
    // (merging patterns that shouldn't be merged)
    assert!(
        output_lines >= 5,
        "Over-compression: {output_lines} < 5 lines — patterns are being merged incorrectly"
    );
}

#[test]
fn test_constitutional_compliance_kubelet() {
    // Bonus test against real kubelet.log when available (gitignored).
    // Skipped in debug builds and when the file is missing.
    if cfg!(debug_assertions) {
        eprintln!("Skipping kubelet.log test: debug build (use --release)");
        return;
    }

    let Some(file) = crate::common::require_example("examples/distilled/kubelet.log") else {
        return;
    };

    // This used to assert `output_lines <= 700`. A line count is a proxy
    // for "did the fold get worse" from a time when nothing could say WHAT
    // got worse. It fails both ways: 98.5% of a log in one group passes it,
    // and a correct split of one blob into three real events breaks it.
    //
    // --explain can say what got worse. A singleton whose nearest group
    // scores at or above the threshold, with no anchor keeping them apart,
    // is a line lessence itself reports as "should have joined". Every one
    // of those is an under-fold with a cause. The gate is therefore: the
    // set of such near-miss shapes may only shrink, and every shape still
    // present must name the bead that owns it.
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--explain", "--threads", "1"])
        .stdin(file)
        .output()
        .expect("Failed to execute lessence");
    assert!(output.status.success(), "lessence execution failed");
    let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let mut groups = 0usize;
    let mut inventory: Vec<String> = Vec::new();
    let mut near_misses: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::default();
    for record in stdout.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(record) else {
            continue;
        };
        if v["type"] != "group" {
            continue;
        }
        groups += 1;
        let count = v["count"].as_u64().unwrap_or(0) as usize;
        inventory.push(format!(
            "{count}\t{}",
            v["normalized"].as_str().unwrap_or("")
        ));
        let nearest = &v["nearest"];
        if count != 1 || nearest.is_null() {
            continue;
        }
        // Anchors are matched, never scored: that split is on purpose.
        if nearest["anchor_mismatch"] == true {
            continue;
        }
        // Just under the threshold is the fingerprint of a missing shape
        // rule, not of a distinct event. 75 leaves headroom below 83 so a
        // rule that pushes a shape from 80 down to 78 still counts as open.
        let score = nearest["score"].as_f64().unwrap_or(0.0);
        if score < 75.0 {
            continue;
        }
        // Reduce the differing token to its shape so 98 pod names with
        // different suffixes count as ONE cause.
        let ours = nearest["first_diff"]["ours"].as_str().unwrap_or("");
        *near_misses.entry(shape_of(ours)).or_default() += 1;
    }
    // The golden inventory is the volume property of the corpus: every
    // template with its count. A line count of the corpus is a
    // distillation choice, not a test property.
    let golden_text = std::fs::read_to_string("examples/distilled/kubelet.golden")
        .expect("Failed to read examples/distilled/kubelet.golden");
    let mut golden: Vec<String> = golden_text.lines().map(str::to_string).collect();
    inventory.sort();
    golden.sort();
    if inventory != golden {
        let inv_set: std::collections::BTreeSet<&String> = inventory.iter().collect();
        let gold_set: std::collections::BTreeSet<&String> = golden.iter().collect();
        let extra: Vec<_> = inv_set.difference(&gold_set).take(20).collect();
        let missing: Vec<_> = gold_set.difference(&inv_set).take(20).collect();
        panic!(
            "kubelet.log fold does not match examples/distilled/kubelet.golden\n\
             + in fold, not in golden\n{}\n\
             - in golden, not in fold\n{}\n\
             run: make distill   (BLESS=1 make distill to re-bless after an intended change)",
            extra
                .iter()
                .map(|s| format!("  {s}"))
                .collect::<Vec<_>>()
                .join("\n"),
            missing
                .iter()
                .map(|s| format!("  {s}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    println!(
        "Constitutional compliance (kubelet.log): {groups} groups, {} near-miss shapes",
        near_misses.len()
    );
    for (shape, n) in &near_misses {
        println!("  {n:>4}  {shape}");
    }

    // Known under-folds, each owned by a bead. A new shape appearing here
    // is a regression: name it and its bead, or fix it. A shape vanishing
    // is progress: delete its line.
    let known: &[(&str, &str)] = &[
        // `err="Patch` vs `err="Post`, `err="container` vs `err="init`: the
        // first word of a quoted error sentence differs. Different causes;
        // correctly apart. Sits here only because the score is high.
        ("<W>=\"<W>", "distinct error cause, by design"),
        // `unexpected` (EOF) vs `read` (connection reset): two error tails.
        ("<W>", "distinct error cause, by design"),
        // `for \"config\"` vs `for \"litellm\"`: the container named inside
        // a quoted error sentence. Since lessence-t8q the sentence keeps its
        // words, so which container crash-looped is visible — distinct
        // containers, by design.
        (
            "\\\"<W>\\\"",
            "distinct container, by design (lessence-t8q)",
        ),
        // A quoted error sentence whose words differ in two places — the
        // verb and the cause — no longer folds into a group founded on
        // another sentence (lessence-a8t): `"<W>` opens one, `<W>"` closes
        // one, `<W>=[<NAME>],` is a struct field naming a different volume.
        ("\"<W>", "another sentence, by design (lessence-a8t)"),
        ("<W>\"", "another sentence, by design (lessence-a8t)"),
        ("<W>=[<NAME>],", "another volume, by design (lessence-a8t)"),
        // `err="container &Container{Name:litellm,Image:…}`: a Go struct
        // dump names its container and image. Distinct, by design (t8q).
        (
            "<W>=\"<NAME>,<W>:<W>{<W>:<W>,<W>:<NAME>,<W>:<NAME>,<W>:<NAME>,<W>:<W>,<W>:<NAME>,<W>:<W>{<NAME>},},<W>:<W>,<W>:<W>",
            "distinct container and image, by design (lessence-t8q)",
        ),
    ];
    let unexplained: Vec<_> = near_misses
        .keys()
        .filter(|shape| !known.iter().any(|(k, _)| *k == shape.as_str()))
        .collect();
    assert!(
        unexplained.is_empty(),
        "CONSTITUTIONAL VIOLATION: near-miss singleton shapes with no owning bead: {unexplained:#?}\n\
         Each is a line lessence reports it should have folded (nearest.score >= 75, no anchor).\n\
         Fix the shape, or add it to `known` with the bead that tracks it."
    );
}

/// Collapse a differing token to its shape. A hyphenated name with its
/// placeholders — `harbor/backup-<NUMBER>-x9k2m`, `vllm/vllm-<HASH>-q1w2e` —
/// is one shape, `<NAME>`, because the cause of the near-miss is the name
/// as a whole, not how many hyphens it happens to have. Anything else keeps
/// its punctuation so `file.go:<LINE>]` and `err="EOF"` stay distinct.
fn shape_of(token: &str) -> String {
    let mut out = String::new();
    let mut name = String::new();
    let flush = |name: &mut String, out: &mut String| {
        if name.is_empty() {
            return;
        }
        // A bare word stays a word; a word containing a hyphen or a
        // placeholder is a name.
        if name.contains('-') || name.contains('<') {
            out.push_str("<NAME>");
        } else {
            out.push_str("<W>");
        }
        name.clear();
    };
    let mut depth = 0u8;
    for c in token.chars() {
        let in_name =
            c.is_alphanumeric() || matches!(c, '_' | '.' | '-' | '/' | '<' | '>') || depth > 0;
        if in_name {
            if c == '<' {
                depth += 1;
            } else if c == '>' {
                depth = depth.saturating_sub(1);
            }
            name.push(c);
        } else {
            flush(&mut name, &mut out);
            out.push(c);
        }
    }
    flush(&mut name, &mut out);
    out
}

#[test]
fn test_processing_speed_requirement() {
    // Speed test only makes sense with release binary + real corpus.
    if cfg!(debug_assertions) {
        eprintln!("Skipping speed test: debug build (use --release)");
        return;
    }

    use std::time::Instant;

    let Some(file) = crate::common::require_example("examples/distilled/kubelet.log") else {
        return;
    };

    let start = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats"])
        .stdin(file)
        .output()
        .expect("Failed to execute lessence");
    let duration = start.elapsed();

    assert!(output.status.success(), "lessence execution failed");

    println!("Speed: {:.2}s (limit: ≤30s)", duration.as_secs_f64());
    assert!(
        duration.as_secs() <= 30,
        "SPEED VIOLATION: {:.2}s > 30s",
        duration.as_secs_f64()
    );
}

// An anchor (`normalize::anchor_hash`) is matched, never scored: two lines
// whose anchor differs are forced into different groups however alike they
// read otherwise. That split is only honest when it is VISIBLE on the shown
// line (CLAUDE.local.md principle 1/2/3) — an anchor that separates groups
// while normalization erases the very field that separated them produces two
// groups printing the identical template, which reads as one event silently
// repeated rather than the distinct endpoints/devices it actually is.
//
// `nearest.anchor_mismatch == true` on a group whose `normalized` matches
// another group's `normalized` is exactly that: an anchor split with nothing
// on the line to show for it. A group re-founded after a flush window
// legitimately repeats a template with no anchor involved — that case has
// `anchor_mismatch == false` (or no `nearest` at all) and is not a
// violation.
//
// Runs `lessence --explain` on one corpus and returns every offending
// template (printed by more than one anchor-mismatched group) as
// (template, how many groups share it), worst offender first.
fn anchor_split_offenders(corpus: &std::path::Path) -> Vec<(String, usize)> {
    offender_groups(corpus)
        .into_iter()
        .map(|(template, lines)| (template, lines.len()))
        .collect()
}

/// Same offenders, but with each group's sample raw line kept alongside —
/// `a_route_split_is_visible` needs the raw text to tell a route split from
/// a status-class split; `anchor_split_offenders` above throws it away for
/// callers that only want the count.
fn offender_groups(corpus: &std::path::Path) -> Vec<(String, Vec<String>)> {
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--explain", "--threads", "1"])
        .stdin(std::fs::File::open(corpus).expect("corpus just listed by caller"))
        .output()
        .expect("Failed to execute lessence");
    assert!(
        output.status.success(),
        "lessence execution failed on {}",
        corpus.display()
    );
    let stdout = str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // normalized -> (sample lines of groups sharing it, saw an anchor_mismatch)
    let mut by_template: std::collections::HashMap<String, (Vec<String>, bool)> =
        std::collections::HashMap::new();
    for record in stdout.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(record) else {
            continue;
        };
        if v["type"] != "group" {
            continue;
        }
        let normalized = v["normalized"].as_str().unwrap_or("").to_string();
        let anchor_mismatch = v["nearest"]["anchor_mismatch"] == true;
        let sample = v["first"]["line"].as_str().unwrap_or("").to_string();
        let entry = by_template.entry(normalized).or_insert((Vec::new(), false));
        entry.0.push(sample);
        entry.1 |= anchor_mismatch;
    }

    let mut offenders: Vec<(String, Vec<String>)> = by_template
        .into_iter()
        .filter(|(_, (lines, saw_mismatch))| lines.len() > 1 && *saw_mismatch)
        .map(|(template, (lines, _))| (template, lines))
        .collect();
    offenders.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    offenders
}

/// Sweeps every distilled corpus and reports invisible-anchor-splits still
/// open. This is the full-repo picture, not a gate — PCI addresses, klog
/// call sites, systemd units, program fields and status fields are anchor
/// classes the route and kubectl-prefix fixes did not touch, and each
/// becomes a `##CASE` (and moves out of this report) as it is fixed.
/// `a_route_split_is_visible` and `a_pod_prefix_split_is_visible` below
/// carry the two classes already fixed.
///
///     cargo test --release --test integration invisible_anchor_splits -- --ignored --nocapture
#[test]
#[ignore = "documents open invisible-anchor splits; each class becomes a ##CASE as it is fixed"]
fn invisible_anchor_splits() {
    let Some(dir) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(dir); // require_example only proves the directory exists here.

    let mut corpora: Vec<std::path::PathBuf> = std::fs::read_dir("examples/distilled")
        .expect("examples/distilled must be readable once require_example confirmed it exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "log"))
        .collect();
    corpora.sort();
    assert!(
        !corpora.is_empty(),
        "examples/distilled/*.log must be non-empty — a gate fails loudly on an absent corpus, never passes by omission"
    );

    let mut total = 0usize;
    for corpus in &corpora {
        let offenders = anchor_split_offenders(corpus);
        if offenders.is_empty() {
            continue;
        }
        total += offenders.len();
        let (example, count) = &offenders[0];
        let cut: String = example.chars().take(160).collect();
        eprintln!(
            "{}: {} template(s) printed by >1 anchor-mismatched group; worst shared by {count}: {cut}",
            corpus.display(),
            offenders.len(),
        );
    }
    eprintln!(
        "\n{total} invisible anchor split(s) total across {} corpora\n",
        corpora.len()
    );
    // Deliberately no assert: this test reports, it does not gate.
}

/// HTTP status identity, in the same order the anchor reads it. A set of
/// digits would lose the difference between (downstream=2xx, upstream=5xx)
/// and (downstream=5xx, upstream=2xx).
fn http_status_signature(line: &str) -> Vec<char> {
    static STATUS_CLASS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?i)"?[a-z_.]*status(?:_?code)?"?\s*[:=]\s*"?([1-5])\d\d\b"#)
            .expect("status-class regex must compile")
    });
    static REQUEST_CLASS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#" HTTP/[0-9.]+" ([1-5])\d\d\b"#)
            .expect("request status-class regex must compile")
    });
    let mut classes = Vec::new();
    for pattern in [
        line.contains("HTTP/").then_some(&*REQUEST_CLASS),
        (line.contains("tatus") || line.contains("TATUS")).then_some(&*STATUS_CLASS),
    ]
    .into_iter()
    .flatten()
    {
        classes.extend(
            pattern
                .captures_iter(line)
                .filter_map(|c| c.get(1))
                .map(|m| m.as_str().chars().next().expect("regex captured one digit")),
        );
    }
    classes
}

#[test]
fn an_http_status_class_split_is_visible() {
    let Some(dir) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(dir);
    let mut corpora: Vec<_> = std::fs::read_dir("examples/distilled")
        .expect("distilled corpora must be readable")
        .map(|entry| entry.expect("read corpus entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == "log"))
        .collect();
    corpora.sort();
    assert!(!corpora.is_empty(), "missing distilled corpora");
    let mut checked = 0;
    for corpus in corpora {
        let text = std::fs::read_to_string(&corpus).expect("read distilled corpus");
        if !text
            .lines()
            .any(|line| !http_status_signature(line).is_empty())
        {
            continue;
        }
        checked += 1;
        let offenders: Vec<_> = offender_groups(&corpus)
            .into_iter()
            .filter(|(_, lines)| {
                lines
                    .iter()
                    .map(|line| http_status_signature(line))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    > 1
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "{} hides HTTP status identities: {offenders:?}",
            corpus.display()
        );
    }
    assert!(checked > 0, "missing HTTP status corpora");
}

/// These corpora exercise klog call sites, Python traceback frames and
/// structured program fields. Each used to contain distinct anchored
/// groups whose visible templates were identical. No exceptions remain.
#[test]
fn call_site_traceback_and_program_splits_are_visible() {
    let Some(dir) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(dir);
    for name in [
        "apiserver_production.log",
        "k8s_grafana.log",
        "k8s_json_sample.log",
        "k8s_tetragon.log",
    ] {
        let path = std::path::Path::new("examples/distilled").join(name);
        assert!(path.exists(), "missing corpus {}", path.display());
        let offenders = offender_groups(&path);
        assert!(
            offenders.is_empty(),
            "{} hides event identities: {offenders:?}",
            path.display()
        );
    }
}

#[test]
fn systemd_unit_splits_are_visible() {
    let Some(dir) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(dir);
    for name in [
        "epyc_7days_journalctl.log",
        "host_fedora_journal.log",
        "host_fedora_user_journal.log",
        "host_pi_dmesg.log",
    ] {
        let path = std::path::Path::new("examples/distilled").join(name);
        assert!(path.exists(), "missing corpus {}", path.display());
        let offenders: Vec<_> = offender_groups(&path)
            .into_iter()
            .filter(|(_, lines)| lines.iter().any(|line| line.contains("systemd[")))
            .collect();
        assert!(
            offenders.is_empty(),
            "{} hides systemd units: {offenders:?}",
            path.display()
        );
    }
}

/// The hardware corpora had dozens of different PCI identities hidden
/// behind the same numeric/path templates. They must all stay visible.
#[test]
fn pci_address_splits_are_visible() {
    static PCI: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"\b[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\b")
            .expect("PCI address regex must compile")
    });
    let Some(dir) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(dir);
    for name in ["epyc_7days_journalctl.log", "nas_dmesg.log"] {
        let path = std::path::Path::new("examples/distilled").join(name);
        assert!(path.exists(), "missing corpus {}", path.display());
        // Systemd and other open anchor classes share these corpora.
        // Compare ordered PCI identities rather than exempting templates.
        let offenders: Vec<_> = offender_groups(&path)
            .into_iter()
            .filter(|(_, lines)| {
                lines
                    .iter()
                    .map(|line| PCI.find_iter(line).map(|m| m.as_str()).collect::<Vec<_>>())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    > 1
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "{} hides PCI identities: {offenders:?}",
            path.display()
        );
    }
}

/// The route-anchor fix's gate: on the two HTTP access-log corpora whose
/// anchor is the request route (`normalize::anchor_hash`'s route-skeleton
/// arm), an anchor split must never print the same template twice. This is
/// `invisible_anchor_splits` above carries other classes. Status-class
/// visibility is now fixed too, so these corpora need no exclusions.
#[test]
fn a_route_split_is_visible() {
    for name in ["k8s_traefik.log", "nginx_sample.log"] {
        let path = std::path::Path::new("examples/distilled").join(name);
        let Some(dir) = crate::common::require_example("examples/distilled") else {
            return;
        };
        drop(dir);
        assert!(path.exists(), "missing corpus {}", path.display());
        let offenders = offender_groups(&path);
        assert!(
            offenders.is_empty(),
            "{}: {} route-anchor split(s) invisible on the shown line: {:?}",
            path.display(),
            offenders.len(),
            offenders
                .iter()
                .take(5)
                .map(|(t, lines)| format!(
                    "{}x {}",
                    lines.len(),
                    t.chars().take(160).collect::<String>()
                ))
                .collect::<Vec<_>>()
        );
    }
}

/// A `[pod/<pod>/<container>]` kubectl prefix's identity — a small local
/// reader mirroring `normalize::pod_skeleton`'s stripping heuristic, rather
/// than exporting internals (the precedent set by `status_class` above).
/// Two sampled lines with different identities here are two different
/// workloads or containers, not one event under two names.
fn pod_identity(line: &str) -> Option<(String, String)> {
    static PREFIX: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^\[pod/([^/\]]+)/([^\]]+)\]").expect("prefix regex"));
    const RAND: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";
    let caps = PREFIX.captures(line)?;
    let pod = caps.get(1)?.as_str();
    let container = caps.get(2)?.as_str();
    let generated = |seg: &str| {
        let b = seg.as_bytes();
        (!b.is_empty() && b.iter().all(u8::is_ascii_digit))
            || (b.len() <= 2 && b.iter().all(u8::is_ascii_lowercase))
            || (b.len() == 5 && b.iter().all(|c| RAND.contains(c)))
            || ((8..=10).contains(&b.len())
                && b.iter().all(|c| RAND.contains(c) || c.is_ascii_digit()))
    };
    let mut keep = pod;
    for _ in 0..3 {
        match keep.rsplit_once('-') {
            Some((head, tail)) if generated(tail) => keep = head,
            _ => break,
        }
    }
    Some((keep.to_string(), container.to_string()))
}

/// The kubectl-prefix-anchor fix's gate: on every `k8s_*` distilled corpus,
/// an anchor split forced by the `[pod/<pod>/<container>]` prefix must never
/// print the same template twice for two different pod identities. This is
/// the second anchor class this fix closed (the first is
/// `a_route_split_is_visible` above); `invisible_anchor_splits` carries
/// every class not yet fixed. An offender is kept only when its sampled
/// lines actually disagree on pod identity — a template repeated for some
/// other, still-open anchor class is not this test's failure to report.
#[test]
fn a_pod_prefix_split_is_visible() {
    let Some(dir) = crate::common::require_example("examples/distilled") else {
        return;
    };
    drop(dir);

    let mut corpora: Vec<std::path::PathBuf> = std::fs::read_dir("examples/distilled")
        .expect("examples/distilled must be readable once require_example confirmed it exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|f| f.starts_with("k8s_") && f.ends_with(".log"))
        })
        .collect();
    corpora.sort();
    assert!(
        !corpora.is_empty(),
        "examples/distilled/k8s_*.log must be non-empty — a gate fails loudly on an absent corpus, never passes by omission"
    );

    for path in &corpora {
        let offenders: Vec<(String, Vec<String>)> = offender_groups(path)
            .into_iter()
            .filter(|(_, lines)| {
                let identities: std::collections::BTreeSet<(String, String)> =
                    lines.iter().filter_map(|l| pod_identity(l)).collect();
                identities.len() > 1
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "{}: {} pod-prefix-anchor split(s) invisible on the shown line: {:?}",
            path.display(),
            offenders.len(),
            offenders
                .iter()
                .take(5)
                .map(|(t, lines)| format!(
                    "{}x {}",
                    lines.len(),
                    t.chars().take(160).collect::<String>()
                ))
                .collect::<Vec<_>>()
        );
    }
}
