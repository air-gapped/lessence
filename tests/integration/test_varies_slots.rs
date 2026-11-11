//! A template with several `<VARIES>` slots reports each slot's values
//! apart, in template order (lessence-a9l): the reader must be able to
//! tell which slot a value filled, and a slot with many values must not
//! crowd a rare value of another slot out of the rollup.
//!
//! Every line here is invented.

use std::io::Write;
use std::process::Stdio;

fn run(args: &[&str], input: &str) -> String {
    let mut child = crate::common::lessence()
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

fn groups(args: &[&str], input: &str) -> Vec<serde_json::Value> {
    run(args, input)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|r| r["type"] == "group")
        .collect()
}

fn marker(text: &str) -> &str {
    text.lines()
        .find(|l| l.starts_with("[+"))
        .unwrap_or_else(|| panic!("no marker in:\n{text}"))
}

/// Four members, two slots: a service and a node.
const TWO_SLOTS: &str = "\
failed to start \"db\" on node \"n1\"
failed to start \"db\" on node \"n2\"
failed to start \"cache\" on node \"n3\"
failed to start \"db\" on node \"n4\"
";

/// A node name from an index, letters only, so no detector claims it.
fn node(i: usize) -> String {
    let a = (b'a' + (i / 26) as u8) as char;
    let b = (b'a' + (i % 26) as u8) as char;
    format!("wk{a}{b}")
}

/// 301 members: `"db"` ×300 and `"cache"` ×1 in the first slot, 100 node
/// names in the second.
fn crowded() -> String {
    let mut out = String::new();
    for i in 0..301 {
        let service = if i == 150 { "cache" } else { "db" };
        out.push_str(&format!(
            "failed to start \"{service}\" on node \"{}\"\n",
            node(i % 100)
        ));
    }
    out
}

fn sample_counts(entry: &serde_json::Value) -> Vec<(String, u64)> {
    let samples = entry["samples"].as_array().expect("samples");
    let counts = entry["sample_counts"].as_array().expect("sample_counts");
    samples
        .iter()
        .zip(counts)
        .map(|(s, n)| (s.as_str().unwrap().to_string(), n.as_u64().unwrap()))
        .collect()
}

#[test]
fn two_slots_are_listed_apart_in_template_order_in_text() {
    let out = run(&["--no-report", "-q", "--threads", "1"], TWO_SLOTS);
    assert_eq!(
        marker(&out),
        "[+2 similar | varies×2 {\"db\"×3, \"cache\"×1}, \
         varies×4 {\"n1\"×1, \"n2\"×1, \"n3\"×1, \"n4\"×1}]",
        "{out}"
    );
}

#[test]
fn two_slots_are_listed_apart_in_template_order_in_json() {
    for flag in ["--explain", "--format=json"] {
        let gs = groups(&["--no-report", "--threads", "1", flag], TWO_SLOTS);
        assert_eq!(gs.len(), 1, "{gs:?}");
        let g = &gs[0];
        assert_eq!(
            g["normalized"]
                .as_str()
                .unwrap()
                .matches("<VARIES>")
                .count(),
            2,
            "{g}"
        );
        let varies = &g["variation"]["VARIES"];
        let slots = varies["slots"]
            .as_array()
            .expect("slots on a two-slot group");
        assert_eq!(slots.len(), 2, "{varies}");
        assert_eq!(
            sample_counts(&slots[0]),
            vec![("\"db\"".into(), 3), ("\"cache\"".into(), 1)],
            "{flag}: {varies}"
        );
        assert_eq!(slots[0]["distinct_count"], 2);
        assert_eq!(slots[0]["distinct_count_kind"], "exact");
        assert_eq!(slots[0]["samples_complete"], true);
        assert_eq!(slots[1]["distinct_count"], 4);
        assert_eq!(
            sample_counts(&slots[1]),
            ["\"n1\"", "\"n2\"", "\"n3\"", "\"n4\""]
                .iter()
                .map(|s| (s.to_string(), 1))
                .collect::<Vec<_>>(),
            "{flag}: {varies}"
        );
        // the pooled entry is what it always was
        assert_eq!(varies["distinct_count"], 6, "{varies}");
        assert!(slots.iter().all(|s| s.get("slots").is_none()), "{varies}");
    }
}

#[test]
fn a_one_slot_group_is_unchanged() {
    let input = "\
failed to start \"db\" on node \"n1\"
failed to start \"web\" on node \"n1\"
failed to start \"cache\" on node \"n1\"
failed to start \"db\" on node \"n1\"
failed to start \"db\" on node \"n1\"
";
    let out = run(&["--no-report", "-q", "--threads", "1"], input);
    assert_eq!(
        marker(&out),
        "[+3 similar | varies×3 {\"db\"×3, \"cache\"×1, \"web\"×1}]",
        "{out}"
    );
    let gs = groups(&["--no-report", "--threads", "1", "--format=json"], input);
    let varies = &gs[0]["variation"]["VARIES"];
    assert!(varies.get("slots").is_none(), "{varies}");
    assert_eq!(
        sample_counts(varies),
        vec![
            ("\"db\"".into(), 3),
            ("\"cache\"".into(), 1),
            ("\"web\"".into(), 1)
        ]
    );
}

#[test]
fn a_rare_value_stays_listed_beside_a_crowded_slot() {
    let input = crowded();
    let out = run(&["--no-report", "-q", "--threads", "1"], &input);
    let m = marker(&out);
    assert!(
        m.contains("varies×2 {\"db\"×300, \"cache\"×1}, varies×64+ {"),
        "{m}"
    );
    for flag in ["--explain", "--format=json"] {
        let gs = groups(&["--no-report", "--threads", "1", flag], &input);
        assert_eq!(gs.len(), 1, "{flag}: {gs:?}");
        let varies = &gs[0]["variation"]["VARIES"];
        let slots = varies["slots"].as_array().expect("slots");
        assert_eq!(
            sample_counts(&slots[0]),
            vec![("\"db\"".into(), 300), ("\"cache\"".into(), 1)],
            "{flag}: {varies}"
        );
        assert_eq!(slots[0]["samples_complete"], true);
        // the crowded slot declares what it left out
        assert_eq!(slots[1]["capped"], true, "{varies}");
        assert_eq!(slots[1]["distinct_count_kind"], "lower_bound");
        assert_eq!(slots[1]["samples_complete"], false);
        assert_eq!(slots[1]["omitted_sample_values"]["kind"], "lower_bound");
        assert_eq!(varies["capped"], true, "{varies}");
    }
}

#[test]
fn pooled_counts_are_the_sum_over_slots() {
    for input in [TWO_SLOTS.to_string(), crowded()] {
        let gs = groups(&["--no-report", "--threads", "1", "--format=json"], &input);
        let varies = &gs[0]["variation"]["VARIES"];
        let slots = varies["slots"].as_array().expect("slots");
        // every value the pooled entry shows counts what the slots count
        // for it together
        for (value, n) in sample_counts(varies) {
            let in_slots: u64 = slots
                .iter()
                .flat_map(sample_counts)
                .filter(|(v, _)| *v == value)
                .map(|(_, n)| n)
                .sum();
            let complete = slots.iter().all(|s| s["samples_complete"] == true);
            if complete {
                assert_eq!(n, in_slots, "{value}: {varies}");
            } else {
                assert!(n >= in_slots, "{value}: {varies}");
            }
        }
        let members = gs[0]["count"].as_u64().unwrap();
        for slot in slots {
            if slot["samples_complete"] == true {
                let total: u64 = sample_counts(slot).iter().map(|(_, n)| n).sum();
                assert_eq!(total, members, "{slot}");
            }
        }
        // a value pooled from both slots: the pooled distinct count is the
        // union, never more than the slots hold together
        let sum: u64 = slots
            .iter()
            .map(|s| s["distinct_count"].as_u64().unwrap())
            .sum();
        assert!(
            varies["distinct_count"].as_u64().unwrap() <= sum,
            "{varies}"
        );
    }
    let gs = groups(
        &["--no-report", "--threads", "1", "--format=json"],
        TWO_SLOTS,
    );
    let varies = &gs[0]["variation"]["VARIES"];
    let pooled: u64 = sample_counts(varies).iter().map(|(_, n)| n).sum();
    let slots: u64 = varies["slots"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(sample_counts)
        .map(|(_, n)| n)
        .sum();
    assert_eq!(pooled, slots);
    assert_eq!(pooled, 8);
}

#[test]
fn slots_are_the_same_at_every_thread_count() {
    let input = crowded();
    let json = |t: &str| {
        groups(&["--no-report", "--threads", t, "--format=json"], &input)
            .into_iter()
            .map(|g| g["variation"].clone())
            .collect::<Vec<_>>()
    };
    let text = |t: &str| run(&["--no-report", "-q", "--threads", t], &input);
    let (j1, t1) = (json("1"), text("1"));
    assert!(j1[0]["VARIES"].get("slots").is_some(), "{j1:?}");
    for t in ["2", "4", "8"] {
        assert_eq!(json(t), j1, "--threads {t}");
        assert_eq!(text(t), t1, "--threads {t}");
    }
}
