//! The bounded overview printed on stdout after a default run's report is
//! complete.
//!
//! The report file is the complete record; stdout is a byte-bounded view of
//! it that declares everything it leaves out. Two sequential passes over the
//! finished file: pass 1 reads only (id, count, byte offset) per record into
//! two bounded heaps — R rarest and N most frequent, at most 2N entries —
//! keeping no template, sample or timestamp text; pass 2 seeks to
//! the selected offsets in ascending id order and renders one record at a
//! time, cutting previews on the fly. `--overview all` streams records in
//! report order with no heap and no cuts.
//!
//! The reader is bounded: a record longer than [`RECORD_GUARD`] is never
//! allocated in full. The reader stops at the guard and the pass fails, the
//! report is retained, and stdout says so. The guard and the N limit are the
//! bound; a measured RSS number is not.

use anyhow::{Result, bail};
use serde::Deserialize;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashSet};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

/// No single report record is read into memory beyond this. 16 MiB.
pub const RECORD_GUARD: usize = 16 * 1024 * 1024;
/// Default stdout byte budget for the whole overview.
pub const DEFAULT_BYTES: usize = 16384;
/// Default number of entries selected.
pub const DEFAULT_ENTRIES: usize = 40;
/// Upper bound on `--overview N`, checked at the CLI boundary.
pub const MAX_ENTRIES: usize = 10_000;
/// A template longer than this is previewed, and the cut is declared.
const TEMPLATE_PREVIEW: usize = 1024;
/// A variation sample longer than this is previewed, and the cut is declared.
const SAMPLE_PREVIEW: usize = 80;
/// Samples shown per variation entry in a bounded overview.
const SAMPLES_SHOWN: usize = 3;

/// `--overview N | all`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Entries {
    Count(usize),
    All,
}

/// Everything the head and tail locator lines report, except the counts,
/// which the pass computes.
pub struct Locator<'a> {
    pub path: &'a Path,
    /// `complete`, or `complete, durability unconfirmed (…)`.
    pub file: String,
    /// `complete`, `degraded(<codes>)` or `incomplete (…)`.
    pub input: String,
    pub run_id: &'a str,
    pub size_bytes: u64,
}

impl Locator<'_> {
    fn render(&self, total: usize, selected: usize, printed: usize) -> String {
        format!(
            "report: {}  file: {}  input: {}  run: {}  size: {} bytes  groups: {total} total, \
             {selected} selected, {printed} printed, {} omitted\n",
            self.path.display(),
            self.file,
            self.input,
            self.run_id,
            self.size_bytes,
            total - printed,
        )
    }

    /// The worst-case rendered width of a locator line for this run: every
    /// count is at most `total`, so rendering with `total` everywhere is an
    /// upper bound on the final line's length. The reservation uses this so
    /// the budget can be settled before the printed count is known.
    fn reserved_len(&self, total: usize) -> usize {
        self.render(total, total, total).len()
    }
}

/// One record as pass 1 needs it: the discriminant, the id and the count.
/// No template, no samples, no timestamps — pass 2 re-reads the selected
/// records in full and takes the timestamps from there.
#[derive(Deserialize)]
struct Meta {
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    id: usize,
    #[serde(default)]
    count: usize,
}

#[derive(Deserialize, Default)]
struct TimeRange {
    first_seen: Option<String>,
    last_seen: Option<String>,
}

#[derive(Deserialize)]
struct Record {
    id: usize,
    count: usize,
    normalized: String,
    #[serde(default)]
    time_range: TimeRange,
    #[serde(default)]
    variation: BTreeMap<String, Variation>,
}

#[derive(Deserialize)]
struct Variation {
    distinct_count: usize,
    #[serde(default)]
    samples: Vec<String>,
}

/// (id, count, byte offset) — the whole of what
/// pass 1 keeps per record.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Entry {
    count: usize,
    id: usize,
    offset: u64,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Rarest-first order: ascending count, ties by ascending id.
        self.count.cmp(&other.count).then(self.id.cmp(&other.id))
    }
}
impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Read one line without ever allocating past `RECORD_GUARD`. Returns the
/// number of bytes consumed including the newline, or 0 at EOF.
fn read_bounded(reader: &mut impl BufRead, buf: &mut Vec<u8>, start: u64) -> Result<usize> {
    buf.clear();
    let mut consumed = 0usize;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(consumed);
        }
        let (take, done) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (i, true),
            None => (available.len(), false),
        };
        if buf.len() + take > RECORD_GUARD {
            // Do not drain the record to improve the message: the offset and
            // "> 16 MiB" are what is known without reading further.
            bail!("record too large: > 16 MiB at byte offset {start}");
        }
        buf.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(done));
        consumed += take + usize::from(done);
        if done {
            return Ok(consumed);
        }
    }
}

/// Pass 1 needs only `id` and `count`, and the renderer writes them as the
/// first two fields after the discriminant. Reading them off the front of
/// the record avoids parsing the whole of it — the templates and samples
/// are the bulk of a report, and pass 1 keeps none of them.
///
/// Conservative by construction: anything that is not exactly this shape,
/// including a record that does not end in `}` (a truncated last line),
/// returns `None` and is parsed properly by the caller. A damaged record
/// therefore still fails the pass instead of being counted and skipped.
fn group_head(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.last() != Some(&b'}') {
        return None;
    }
    let rest = buf.strip_prefix(br#"{"type":"group","id":"#)?;
    let (id, rest) = leading_usize(rest)?;
    let rest = rest.strip_prefix(br#","count":"#)?;
    let (count, _) = leading_usize(rest)?;
    Some((id, count))
}

fn leading_usize(buf: &[u8]) -> Option<(usize, &[u8])> {
    let end = buf.iter().position(|b| !b.is_ascii_digit())?;
    if end == 0 {
        return None;
    }
    let value = std::str::from_utf8(&buf[..end]).ok()?.parse().ok()?;
    Some((value, &buf[end..]))
}

/// Pass 1: the two bounded heaps plus the total group count.
#[derive(Debug)]
struct Pass1 {
    total: usize,
    rarest: Vec<Entry>,
    frequent: Vec<Entry>,
    /// Report order, only populated for `--overview all`.
    all: Vec<Entry>,
}

fn pass1(path: &Path, entries: Entries) -> Result<Pass1> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut buf = Vec::new();
    let mut offset = 0u64;
    let mut total = 0usize;
    let want = match entries {
        Entries::All => 0,
        Entries::Count(n) => n,
    };
    let rare_quota = want.div_ceil(2);
    // Max-heap bounded to `rare_quota`: the worst element is the largest
    // count, so popping it keeps the rarest.
    let mut rare: BinaryHeap<Entry> = BinaryHeap::new();
    // Min-heap bounded to `want`: popping the smallest keeps the frequent.
    let mut freq: BinaryHeap<Reverse<Entry>> = BinaryHeap::new();
    let mut all = Vec::new();
    loop {
        let start = offset;
        let n = read_bounded(&mut reader, &mut buf, start)?;
        if n == 0 {
            break;
        }
        offset += n as u64;
        if buf.is_empty() {
            continue;
        }
        let (id, count) = if let Some(pair) = group_head(&buf) {
            pair
        } else {
            // Not the shape this writer emits: parse it properly. A record
            // that fails here is a damaged report, and the pass fails
            // rather than omitting a group.
            let meta: Meta = serde_json::from_slice(&buf)
                .map_err(|e| anyhow::anyhow!("parse failed at byte offset {start}: {e}"))?;
            if meta.record_type != "group" {
                continue;
            }
            (meta.id, meta.count)
        };
        total += 1;
        let entry = Entry {
            count,
            id,
            offset: start,
        };
        match entries {
            Entries::All => all.push(entry),
            Entries::Count(_) => {
                if rare_quota > 0 {
                    rare.push(entry.clone());
                    if rare.len() > rare_quota {
                        rare.pop();
                    }
                }
                if want > 0 {
                    freq.push(Reverse(entry));
                    if freq.len() > want {
                        freq.pop();
                    }
                }
            }
        }
    }
    let mut rarest = rare.into_vec();
    rarest.sort_unstable();
    let mut frequent: Vec<Entry> = freq.into_vec().into_iter().map(|r| r.0).collect();
    // Descending count, ties by ascending id.
    frequent.sort_unstable_by(|a, b| b.count.cmp(&a.count).then(a.id.cmp(&b.id)));
    Ok(Pass1 {
        total,
        rarest,
        frequent,
        all,
    })
}

/// R = ceil(N/2) rarest, then the most frequent not already selected, up to
/// N in total. Display order is ascending id; selection order is separate.
fn select(pass: &Pass1, n: usize) -> Vec<Entry> {
    let rare_quota = n.div_ceil(2);
    let mut chosen: Vec<Entry> = pass.rarest.iter().take(rare_quota).cloned().collect();
    let taken: HashSet<usize> = chosen.iter().map(|e| e.id).collect();
    for entry in &pass.frequent {
        if chosen.len() >= n {
            break;
        }
        if !taken.contains(&entry.id) {
            chosen.push(entry.clone());
        }
    }
    chosen.sort_unstable_by_key(|e| e.id);
    chosen
}

/// Cut `s` at the last UTF-8 boundary at or before `max` bytes.
fn cut(s: &str, max: usize) -> (&str, bool) {
    if s.len() <= max {
        return (s, false);
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (&s[..end], true)
}

fn render_entry(record: &Record, bounded: bool) -> String {
    let stamp = |t: &Option<String>| t.clone().unwrap_or_else(|| "-".to_string());
    let mut out = format!(
        "[{}x] id={} {} → {}\n",
        record.count,
        record.id,
        stamp(&record.time_range.first_seen),
        stamp(&record.time_range.last_seen),
    );
    let mut cut_template = false;
    if bounded {
        let (head, was_cut) = cut(&record.normalized, TEMPLATE_PREVIEW);
        cut_template = was_cut;
        out.push_str(head);
        if was_cut {
            out.push_str(&format!(
                " …[template {} bytes; id={} in report]",
                record.normalized.len(),
                record.id
            ));
        }
    } else {
        out.push_str(&record.normalized);
    }
    out.push('\n');

    let mut cut_samples = false;
    if !record.variation.is_empty() {
        let mut facts = Vec::new();
        for (name, v) in &record.variation {
            let shown = if bounded {
                v.samples.len().min(SAMPLES_SHOWN)
            } else {
                v.samples.len()
            };
            let mut rendered: Vec<String> = Vec::with_capacity(shown);
            for sample in v.samples.iter().take(shown) {
                if bounded {
                    let (head, was_cut) = cut(sample, SAMPLE_PREVIEW);
                    if was_cut {
                        cut_samples = true;
                    }
                    rendered.push(head.to_string());
                } else {
                    rendered.push(sample.clone());
                }
            }
            let mut fact = format!("{name}={}", v.distinct_count);
            if !rendered.is_empty() {
                fact.push_str(&format!(" [{}]", rendered.join("|")));
            }
            // Only a cut made *here* is declared here. A report entry that
            // already carries fewer samples than distinct values declared
            // that omission itself, in its own record.
            if shown < v.samples.len() {
                cut_samples = true;
                fact.push_str(&format!(" …[{shown} of {} shown]", v.distinct_count));
            }
            facts.push(fact);
        }
        out.push_str(&format!("variation: {}\n", facts.join("  ")));
    }
    let previewed: Vec<&str> = [(cut_template, "template"), (cut_samples, "samples")]
        .into_iter()
        .filter_map(|(yes, name)| yes.then_some(name))
        .collect();
    if !previewed.is_empty() {
        out.push_str(&format!("previewed: {}\n", previewed.join(", ")));
    }
    out
}

/// The four recipes. None of them cats the file.
fn recipes(path: &Path) -> String {
    let p = path.display();
    format!(
        "recipes (the report is JSONL; none of these prints the whole file):\n  \
         overview, by count:  jq -r 'select(.type==\"group\")|\"\\(.count)\\t\\(.normalized[0:120])\"' {p} | sort -rn | head -40\n  \
         singletons:          jq -r 'select(.type==\"group\" and .count==1)|.normalized[0:120]' {p}\n  \
         what is missing:     jq 'select(.type==\"summary\")|{{completeness,degraded}}' {p}\n  \
         one group in full (potentially large: a full record can be arbitrarily long):\n                       jq 'select(.type==\"group\" and .id==ID)' {p}\n"
    )
}

/// Render the whole stdout overview. `briefing` is already-rendered text
/// (`None` under `-q`).
pub fn render(
    path: &Path,
    locator: &Locator<'_>,
    entries: Entries,
    budget: usize,
    briefing: Option<&str>,
) -> Result<String> {
    let pass = pass1(path, entries)?;
    let tail = recipes(path);
    let brief = briefing.unwrap_or("");

    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut buf = Vec::new();

    let read_at =
        |reader: &mut BufReader<std::fs::File>, buf: &mut Vec<u8>, offset: u64| -> Result<Record> {
            reader.seek(SeekFrom::Start(offset))?;
            let n = read_bounded(reader, buf, offset)?;
            if n == 0 {
                bail!("record at byte offset {offset} disappeared between passes");
            }
            serde_json::from_slice(buf)
                .map_err(|e| anyhow::anyhow!("parse failed at byte offset {offset}: {e}"))
        };

    if entries == Entries::All {
        // No byte budget, no cuts, one record at a time, report order.
        let mut body = String::new();
        for entry in &pass.all {
            let record = read_at(&mut reader, &mut buf, entry.offset)?;
            body.push_str(&render_entry(&record, false));
        }
        let head = locator.render(pass.total, pass.total, pass.total);
        return Ok(format!("{brief}{head}{body}{head}{tail}"));
    }

    let n = match entries {
        Entries::Count(n) => n,
        Entries::All => unreachable!(),
    };
    let chosen = select(&pass, n.min(pass.total));
    let selected = chosen.len();

    // Reserve the mandatory text first: briefing, head locator, tail
    // locator, recipes. The locator reservation uses its worst-case width
    // for this run, so the budget is settled before `printed` is known.
    let reserved = brief.len() + 2 * locator.reserved_len(pass.total) + tail.len();
    if reserved > budget {
        let over = reserved - budget;
        let head = format!(
            "overview: budget exceeded by mandatory text ({over} bytes over)\n{}",
            locator.render(pass.total, selected, 0)
        );
        return Ok(format!("{brief}{head}{tail}"));
    }
    let room = budget - reserved;

    let mut body = String::new();
    let mut printed = 0usize;
    for entry in &chosen {
        let record = read_at(&mut reader, &mut buf, entry.offset)?;
        let rendered = render_entry(&record, true);
        if body.len() + rendered.len() > room {
            // This entry and every later selected entry are "selected, not
            // printed" — the locator's printed < selected says so.
            break;
        }
        body.push_str(&rendered);
        printed += 1;
    }
    let head = locator.render(pass.total, selected, printed);
    Ok(format!("{brief}{head}{body}{head}{tail}"))
}

/// The head/tail-only output for a run whose report is complete but whose
/// overview pass failed. No group is silently omitted: the reason is named.
pub fn unavailable(locator: &Locator<'_>, error: &str) -> String {
    let head = locator.render(0, 0, 0);
    format!(
        "{head}overview: unavailable ({error})\n{head}{}",
        recipes(locator.path)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn corpus(records: &[(usize, usize)]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        for (id, count) in records {
            writeln!(
                f,
                r#"{{"type":"group","id":{id},"count":{count},"normalized":"t{id}","time_range":{{"first_seen":null,"last_seen":null}},"variation":{{}}}}"#
            )
            .unwrap();
        }
        writeln!(f, r#"{{"type":"summary","complete":true}}"#).unwrap();
        (dir, path)
    }

    fn locator(path: &Path) -> Locator<'_> {
        Locator {
            path,
            file: "complete".into(),
            input: "complete".into(),
            run_id: "run-x",
            size_bytes: 0,
        }
    }

    #[test]
    fn selection_takes_half_rarest_and_fills_with_the_most_frequent() {
        let (_d, path) = corpus(&[(0, 100), (1, 1), (2, 50), (3, 2), (4, 70)]);
        let pass = pass1(&path, Entries::Count(4)).unwrap();
        assert_eq!(pass.total, 5, "the summary record is not a group");
        let chosen = select(&pass, 4);
        let ids: Vec<usize> = chosen.iter().map(|e| e.id).collect();
        // Rarest 2: ids 1 (count 1) and 3 (count 2). Most frequent 2 left:
        // ids 0 (100) and 4 (70). Display order is ascending id.
        assert_eq!(ids, vec![0, 1, 3, 4]);
    }

    #[test]
    fn ties_are_broken_by_ascending_id_and_the_quotas_still_fill() {
        let (_d, path) = corpus(&[(0, 7), (1, 7), (2, 7), (3, 7)]);
        let pass = pass1(&path, Entries::Count(3)).unwrap();
        let ids: Vec<usize> = select(&pass, 3).iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), 3, "all-equal counts must not underfill");
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn n_at_or_above_the_total_selects_every_group() {
        let (_d, path) = corpus(&[(0, 1), (1, 2), (2, 3)]);
        let pass = pass1(&path, Entries::Count(40)).unwrap();
        assert_eq!(select(&pass, 3).len(), 3);
    }

    #[test]
    fn a_record_over_the_guard_fails_the_pass_naming_its_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"{{"type":"group","id":0,"count":1,"normalized":"x"}}"#).unwrap();
        let offset = f.metadata().unwrap().len();
        f.write_all(&vec![b'a'; RECORD_GUARD + 10]).unwrap();
        f.write_all(b"\n").unwrap();
        drop(f);
        let err = pass1(&path, Entries::Count(40)).expect_err("the guard must trip");
        assert_eq!(
            err.to_string(),
            format!("record too large: > 16 MiB at byte offset {offset}")
        );
    }

    #[test]
    fn the_fast_head_reads_only_what_this_writer_emits_and_refuses_anything_else() {
        assert_eq!(
            group_head(br#"{"type":"group","id":7,"count":42,"normalized":"x"}"#),
            Some((7, 42))
        );
        // A truncated record does not end in `}` — the caller must parse it
        // properly and fail, not count a damaged group and move on.
        assert_eq!(
            group_head(br#"{"type":"group","id":7,"count":42,"norm"#),
            None
        );
        assert_eq!(group_head(br#"{"type":"summary","complete":true}"#), None);
        // Field order or spacing this writer does not produce falls back too.
        assert_eq!(group_head(br#"{"id":7,"type":"group","count":42}"#), None);
        assert_eq!(group_head(br#"{"type":"group","id":,"count":42}"#), None);
    }

    #[test]
    fn a_truncated_report_fails_the_pass_with_a_parse_error_at_its_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.jsonl");
        std::fs::write(&path, "{\"type\":\"group\",\"id\":0,\"co\n").unwrap();
        let err = pass1(&path, Entries::Count(40)).expect_err("a half record must not parse");
        assert!(
            err.to_string().starts_with("parse failed at byte offset 0"),
            "{err}"
        );
    }

    #[test]
    fn the_budget_bounds_stdout_and_the_locator_reports_what_was_not_printed() {
        let records: Vec<(usize, usize)> = (0..200).map(|i| (i, i + 1)).collect();
        let (_d, path) = corpus(&records);
        let loc = locator(&path);
        let out = render(&path, &loc, Entries::Count(40), DEFAULT_BYTES, None).unwrap();
        assert!(out.len() <= DEFAULT_BYTES, "{} bytes", out.len());
        assert!(out.contains("200 total, 40 selected"), "{out}");
        assert!(out.starts_with("report: "), "head locator first");
        assert!(
            out.ends_with("jq 'select(.type==\"group\" and .id==ID)' ") || out.contains("recipes"),
            "tail last"
        );
    }

    #[test]
    fn a_tiny_budget_prints_the_mandatory_text_and_says_how_far_over_it_is() {
        let (_d, path) = corpus(&[(0, 1), (1, 2)]);
        let loc = locator(&path);
        let out = render(&path, &loc, Entries::Count(40), 1, None).unwrap();
        assert!(out.contains("budget exceeded by mandatory text"), "{out}");
        assert!(out.contains("0 printed"), "{out}");
        assert!(!out.contains("[1x] id=0"), "no entries follow: {out}");
    }

    #[test]
    fn overview_all_prints_every_group_in_report_order_with_no_budget() {
        let records: Vec<(usize, usize)> = (0..300).map(|i| (i, i + 1)).collect();
        let (_d, path) = corpus(&records);
        let loc = locator(&path);
        let out = render(&path, &loc, Entries::All, 1, None).unwrap();
        let bounded = render(&path, &loc, Entries::Count(40), DEFAULT_BYTES, None).unwrap();
        assert!(
            out.len() > bounded.len(),
            "a budget of 1 byte must not bound --overview all ({} vs {})",
            out.len(),
            bounded.len()
        );
        assert!(
            out.contains("300 total, 300 selected, 300 printed, 0 omitted"),
            "{out}"
        );
        for i in 0..300 {
            assert!(out.contains(&format!("id={i} ")), "group {i} missing");
        }
        let first = out.find("id=0 ").unwrap();
        let last = out.find("id=299 ").unwrap();
        assert!(first < last, "report order");
    }

    #[test]
    fn a_long_template_is_cut_on_a_boundary_and_the_cut_is_declared() {
        let record = Record {
            id: 7,
            count: 3,
            normalized: "é".repeat(2000),
            time_range: TimeRange::default(),
            variation: BTreeMap::new(),
        };
        let out = render_entry(&record, true);
        assert!(
            out.contains("…[template 4000 bytes; id=7 in report]"),
            "{out}"
        );
        assert!(out.contains("previewed: template"), "{out}");
        let line = out.lines().nth(1).unwrap();
        let shown = line.split(" …[").next().unwrap();
        assert!(shown.starts_with('é'), "still valid UTF-8");
        assert!(
            shown.len() <= 1024,
            "cut at or before 1024 bytes: {}",
            shown.len()
        );
        assert_eq!(shown.len() % 2, 0, "cut on a char boundary, not mid-é");
    }

    #[test]
    fn samples_are_capped_at_three_and_eighty_bytes_each_with_the_count_declared() {
        let mut variation = BTreeMap::new();
        variation.insert(
            "ip".to_string(),
            Variation {
                distinct_count: 9,
                samples: vec!["x".repeat(200), "b".into(), "c".into(), "d".into()],
            },
        );
        let record = Record {
            id: 1,
            count: 9,
            normalized: "t".into(),
            time_range: TimeRange::default(),
            variation,
        };
        let out = render_entry(&record, true);
        assert!(out.contains("ip=9"), "{out}");
        assert!(out.contains("…[3 of 9 shown]"), "{out}");
        assert!(!out.contains("|d"), "the fourth sample is cut: {out}");
        assert!(out.contains(&"x".repeat(80)), "{out}");
        assert!(!out.contains(&"x".repeat(81)), "cut at 80 bytes: {out}");
        assert!(out.contains("previewed: samples"), "{out}");
    }

    #[test]
    fn a_missing_timestamp_prints_a_dash() {
        let record = Record {
            id: 1,
            count: 2,
            normalized: "t".into(),
            time_range: TimeRange {
                first_seen: Some("12:00".into()),
                last_seen: None,
            },
            variation: BTreeMap::new(),
        };
        assert!(render_entry(&record, true).starts_with("[2x] id=1 12:00 → -\n"));
    }
}
