use std::io::Write;
use std::process::Stdio;

fn stamp(seconds_after_nine: u64) -> String {
    let s = 9 * 3600 + seconds_after_nine;
    format!(
        "2026-09-09T{:02}:{:02}:{:02}Z",
        s / 3600,
        s / 60 % 60,
        s % 60
    )
}

fn steady_heartbeat_and_bunched_refusal_log() -> String {
    let mut lines: Vec<(u64, String)> = Vec::new();
    for i in 0..480u64 {
        let t = 60 * i + 2;
        lines.push((
            t,
            format!("{} INFO poller heartbeat ok from node-7", stamp(t)),
        ));
    }
    for (n, t) in [0u64, 3 * 3600]
        .into_iter()
        .chain((0..98).map(|i| 7 * 3600 + 55 * 60 + i * 2))
        .enumerate()
    {
        lines.push((
            t,
            format!(
                "{} ERROR upstream refused connection from 10.1.2.{}",
                stamp(t),
                n % 4 + 1
            ),
        ));
    }
    lines.sort();
    let mut out = String::new();
    for (_, l) in lines {
        out.push_str(&l);
        out.push('\n');
    }
    out
}

fn run(args: &[&str], input: &str) -> String {
    let mut child: std::process::Child = crate::common::lessence()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lessence");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "lessence {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn records(args: &[&str], input: &str) -> Vec<serde_json::Value> {
    run(args, input)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn groups(recs: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    recs.iter().filter(|r| r["type"] == "group").collect()
}

fn group_matching<'a>(recs: &'a [serde_json::Value], word: &str) -> &'a serde_json::Value {
    let found: Vec<_> = groups(recs)
        .into_iter()
        .filter(|g| g["normalized"].as_str().unwrap().contains(word))
        .collect();
    assert_eq!(found.len(), 1, "one group with {word:?}: {found:?}");
    found[0]
}

fn buckets(g: &serde_json::Value) -> Vec<u64> {
    g["time_range"]["buckets"]
        .as_array()
        .unwrap_or_else(|| panic!("no buckets: {g}"))
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect()
}

fn marker_with<'a>(text: &'a str, word: &str) -> &'a str {
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.contains(word))
        .unwrap_or_else(|| panic!("no line with {word:?}:\n{text}"));
    lines[at + 1]
}

#[test]
fn a_bursty_group_gets_the_clause_and_its_buckets() {
    let log = steady_heartbeat_and_bunched_refusal_log();
    let recs = records(&["--format", "json", "--threads", "1"], &log);
    let refused = group_matching(&recs, "refused");
    assert_eq!(refused["count"], 100);
    let tr = &refused["time_range"];
    assert_eq!(
        tr["bucket_seconds"], 1198,
        "lessence-sfu: a group's buckets sit on the briefing histogram's grid, eight hours on 24 buckets (span / 24 + 1)"
    );
    let b = buckets(refused);
    assert_eq!(b.len(), 24);
    assert_eq!(b[0], 1, "09:00:00");
    assert_eq!(b[9], 1, "12:00:00");
    assert_eq!(b[23], 98, "16:55:00-16:58:14");
    assert_eq!(b.iter().sum::<u64>(), 100);
    let bunched = &tr["bunched"];
    assert_eq!(bunched["pct"], 98);
    assert_eq!(bunched["members"], 98);
    assert_eq!(bunched["first_bucket"], 23);
    assert_eq!(bunched["last_bucket"], 23);
    assert_eq!(bunched["from"], "16:55");
    assert_eq!(bunched["to"], "16:58");

    let text = run(&["--no-report", "-q", "--threads", "1"], &log);
    let marker = marker_with(&text, "refused");
    assert!(
        marker.starts_with(
            "[+98 similar | 2026-09-09T09:00:00Z → 2026-09-09T16:58:14Z | 98% in 16:55\u{2013}16:58 | "
        ),
        "{marker}"
    );

    let overview = run(&["-q", "--threads", "1"], &log);
    assert!(
        overview.contains(
            "[100x] id=0 2026-09-09T09:00:00Z → 2026-09-09T16:58:14Z | 98% in 16:55\u{2013}16:58\n"
        ),
        "the default overview carries the same bunched clause on the group's line: {overview}"
    );
}

#[test]
fn a_steady_groups_marker_is_unchanged() {
    let log = steady_heartbeat_and_bunched_refusal_log();
    let recs = records(&["--format", "json", "--threads", "1"], &log);
    let beat = group_matching(&recs, "heartbeat");
    assert_eq!(buckets(beat), vec![20; 24]);
    assert!(beat["time_range"].get("bunched").is_none(), "{beat}");

    let text = run(&["--no-report", "-q", "--threads", "1"], &log);
    let marker = marker_with(&text, "heartbeat");
    assert_eq!(
        marker,
        "[+478 similar | 2026-09-09T09:00:02Z → 2026-09-09T16:59:02Z]"
    );
    let overview = run(&["-q", "--threads", "1"], &log);
    assert!(
        overview.contains("[480x] id=1 2026-09-09T09:00:02Z → 2026-09-09T16:59:02Z\n"),
        "{overview}"
    );
}

#[test]
fn a_group_under_the_thresholds_has_no_buckets() {
    let mut log = String::new();
    log.push_str(&format!("{} WARN disk nearly full on vol-a\n", stamp(0)));
    log.push_str(&format!("{} WARN disk nearly full on vol-b\n", stamp(7200)));
    log.push_str(&format!("{} INFO cache flush done\n", stamp(1)));
    log.push_str(&format!("{} INFO cache flush done\n", stamp(2)));
    log.push_str(&format!("{} INFO cache flush done\n", stamp(3)));
    log.push_str(&format!("{} DEBUG tick\n", stamp(4)));
    log.push_str(&format!("{} DEBUG tick\n", stamp(3600)));
    log.push_str(&format!("{} DEBUG tick\n", stamp(14_400)));
    let recs = records(&["--format", "json", "--threads", "1"], &log);
    for word in ["disk", "cache"] {
        let g = group_matching(&recs, word);
        let tr = g["time_range"].as_object().unwrap();
        assert!(
            !tr.contains_key("buckets") && !tr.contains_key("bucket_seconds"),
            "two members, or three in one bucket, are under the thresholds: {word}: {g}"
        );
    }
    let tick = group_matching(&recs, "tick");
    assert_eq!(
        buckets(tick).iter().sum::<u64>(),
        3,
        "three members across more than one bucket is the smallest group with a timeline"
    );
}

#[test]
fn a_group_without_timestamps_has_no_timeline() {
    let mut log = String::new();
    for i in 0..30 {
        log.push_str(&format!("{} INFO request served\n", stamp(i * 600)));
        log.push_str("worker pool resized\n");
    }
    let recs = records(&["--format", "json", "--threads", "1"], &log);
    let g = group_matching(&recs, "resized");
    assert_eq!(g["count"], 30);
    let tr = g["time_range"].as_object().unwrap();
    assert!(!tr.contains_key("buckets"), "{g}");
    assert!(!tr.contains_key("bunched"), "{g}");
    assert!(group_matching(&recs, "served")["time_range"]["buckets"].is_array());
}

#[test]
fn group_buckets_sum_to_their_members_and_never_exceed_the_log() {
    let log = steady_heartbeat_and_bunched_refusal_log();
    let recs = records(&["--format", "json", "--threads", "1"], &log);
    let summary = recs.iter().find(|r| r["type"] == "summary").unwrap();
    let hist = &summary["briefing"]["histogram"];
    let log_wide: Vec<u64> = hist["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    let mut summed = vec![0u64; log_wide.len()];
    let gs = groups(&recs);
    assert!(gs.len() >= 2);
    for g in gs {
        assert_eq!(g["time_range"]["bucket_seconds"], hist["bucket_seconds"]);
        let b = buckets(g);
        assert_eq!(b.len(), log_wide.len(), "same grid, index by index");
        assert_eq!(
            b.iter().sum::<u64>(),
            g["count"].as_u64().unwrap(),
            "every member of these groups carries a timestamp"
        );
        for (i, (&mine, &all)) in b.iter().zip(&log_wide).enumerate() {
            assert!(mine <= all, "bucket {i}: group {mine} > log {all}");
            summed[i] += mine;
        }
    }
    assert_eq!(
        summed, log_wide,
        "every line is in exactly one group, so the groups add up to the log"
    );
}

#[test]
fn the_timeline_is_the_same_at_every_thread_count_and_mode() {
    let lines_past_the_10_000_line_parallel_batch = 30_000u64;
    let mut log = String::new();
    for i in 0..lines_past_the_10_000_line_parallel_batch {
        let t = i;
        if i % 3 == 0 {
            log.push_str(&format!(
                "{} INFO poller heartbeat ok from node-7\n",
                stamp(t)
            ));
        } else if i > 27_000 {
            log.push_str(&format!(
                "{} ERROR upstream refused connection from 10.1.2.{}\n",
                stamp(t),
                i % 4 + 1
            ));
        } else {
            log.push_str(&format!(
                "{} DEBUG queue depth {} on shard-{}\n",
                stamp(t),
                i % 97,
                i % 5
            ));
        }
        if i % 1000 == 7 {
            log.push_str(&format!(
                "{} ERROR upstream refused connection from 10.1.2.9\n",
                stamp(t)
            ));
        }
    }
    let timelines = |args: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = groups(&records(args, &log))
            .iter()
            .map(|g| format!("{} {} {}", g["normalized"], g["count"], g["time_range"]))
            .collect();
        v.sort();
        v
    };
    let one = timelines(&["--format", "json", "--threads", "1"]);
    assert!(
        one.iter().any(|l| l.contains("\"bunched\"")),
        "the refusal bunches: {one:?}"
    );
    for args in [
        &["--format", "json", "--threads", "2"][..],
        &["--format", "json", "--threads", "4"][..],
        &["--format", "json"][..],
        &["--explain", "--threads", "1"][..],
        &["--explain", "--threads", "3"][..],
    ] {
        assert_eq!(timelines(args), one, "{args:?}");
    }
    let text = |threads: &str| run(&["--no-report", "-q", "--threads", threads], &log);
    let t1 = text("1");
    assert!(t1.contains("% in "), "{t1}");
    assert_eq!(text("4"), t1);
}
