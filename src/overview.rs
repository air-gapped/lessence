use anyhow::{Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BinaryHeap, HashSet};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;

pub const RECORD_GUARD: usize = 16 * 1024 * 1024;
pub const DEFAULT_BYTES: usize = 16384;
pub const DEFAULT_ENTRIES: usize = 40;
pub const MAX_ENTRIES: usize = 10_000;
const TEMPLATE_PREVIEW: usize = 1024;
const SAMPLE_PREVIEW: usize = 80;
const SAMPLES_SHOWN: usize = 3;
const RECIPE_ROWS: usize = 40;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Entries {
    Count(usize),
    All,
}

#[derive(Clone, Copy)]
enum GroupCounts {
    Known(Counts),
    UnknownPassFailed,
}

#[derive(Clone, Copy)]
struct Counts {
    total: usize,
    selected: usize,
    printed: usize,
    omitted: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputState {
    Complete,
    Degraded(Vec<&'static str>),
}

impl InputState {
    pub fn from_degraded_codes(codes: Vec<&'static str>) -> Self {
        if codes.is_empty() {
            Self::Complete
        } else {
            Self::Degraded(codes)
        }
    }
}

impl std::fmt::Display for InputState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Complete => f.write_str("complete"),
            Self::Degraded(codes) => write!(f, "degraded({})", codes.join(",")),
        }
    }
}

pub struct Locator<'a> {
    pub path: &'a Path,
    pub file: crate::report::Finished,
    pub input: InputState,
    pub run_id: &'a str,
    pub size_bytes: u64,
}

impl Locator<'_> {
    fn line(&self, counts: GroupCounts) -> String {
        let groups = match counts {
            GroupCounts::Known(c) => format!(
                "{} total, {} selected, {} printed, {} omitted",
                c.total, c.selected, c.printed, c.omitted
            ),
            GroupCounts::UnknownPassFailed => {
                "unknown (the overview pass could not read the report)".to_string()
            }
        };
        format!(
            "report: {}  file: {}  input: {}  run: {}  size: {} bytes  groups: {groups}\n",
            self.path.display(),
            self.file,
            self.input,
            self.run_id,
            self.size_bytes,
        )
    }

    fn render(&self, total: usize, selected: usize, printed: usize) -> String {
        self.line(GroupCounts::Known(Counts {
            total,
            selected,
            printed,
            omitted: total - printed,
        }))
    }

    fn max_rendered_len(&self, total: usize) -> usize {
        self.line(GroupCounts::Known(Counts {
            total,
            selected: total,
            printed: total,
            omitted: total,
        }))
        .len()
    }
}

#[derive(Deserialize)]
struct ValidatedRecordHead {
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
    #[serde(default)]
    bunched: Option<Bunched>,
}

#[derive(Deserialize)]
struct Bunched {
    pct: u64,
    from: String,
    to: String,
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
    distinct_count_kind: Option<DistinctCountKind>,
    #[serde(default)]
    samples: Vec<String>,
    #[serde(default)]
    samples_complete: Option<bool>,
    #[serde(default)]
    capped: bool,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum DistinctCountKind {
    Exact,
    LowerBound,
    #[serde(other)]
    Unrecognised,
}

impl Variation {
    fn count_text(&self, name: &str) -> String {
        match self.distinct_count_kind {
            Some(DistinctCountKind::Exact) => format!("{name}={}", self.distinct_count),
            Some(DistinctCountKind::LowerBound) => format!("{name}>={}", self.distinct_count),
            _ if self.capped => format!("{name}>={}", self.distinct_count),
            Some(DistinctCountKind::Unrecognised) | None => {
                format!("{name}~{} (kind unstated)", self.distinct_count)
            }
        }
    }

    fn report_held_fewer_values(&self) -> bool {
        match self.samples_complete {
            Some(complete) => !complete,
            None => self.capped || self.samples.len() < self.distinct_count,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Entry {
    count: usize,
    id: usize,
    offset: u64,
}

fn rarest_first(a: &Entry, b: &Entry) -> std::cmp::Ordering {
    a.count.cmp(&b.count).then(a.id.cmp(&b.id))
}

fn most_frequent_first(a: &Entry, b: &Entry) -> std::cmp::Ordering {
    b.count.cmp(&a.count).then(a.id.cmp(&b.id))
}

fn rare_quota(want: usize) -> usize {
    want.div_ceil(2)
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        rarest_first(self, other)
    }
}
impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct FrequentHeapWorstFirst(Entry);

impl Ord for FrequentHeapWorstFirst {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        most_frequent_first(&self.0, &other.0)
    }
}
impl PartialOrd for FrequentHeapWorstFirst {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

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
            bail!(
                "record too large: > {} MiB at byte offset {start}",
                RECORD_GUARD >> 20
            );
        }
        buf.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(done));
        consumed += take + usize::from(done);
        if done {
            return Ok(consumed);
        }
    }
}

fn open(path: &Path) -> Result<BufReader<std::fs::File>> {
    Ok(BufReader::with_capacity(
        256 * 1024,
        std::fs::File::open(path)?,
    ))
}

#[derive(Debug)]
struct Pass1 {
    total: usize,
    rarest: Vec<Entry>,
    frequent: Vec<Entry>,
}

fn scan(
    path: &Path,
    mut visit: impl FnMut(&[u8], usize, usize, u64) -> Result<()>,
) -> Result<usize> {
    let mut reader = open(path)?;
    let mut buf = Vec::new();
    let mut offset = 0u64;
    let mut total = 0usize;
    let mut saw_summary = false;
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
        if saw_summary {
            bail!("report is damaged: a record follows the summary at byte offset {start}");
        }
        let meta: ValidatedRecordHead = serde_json::from_slice(&buf)
            .map_err(|e| anyhow::anyhow!("parse failed at byte offset {start}: {e}"))?;
        match meta.record_type.as_str() {
            "group" => {
                total += 1;
                visit(&buf, meta.id, meta.count, start)?;
            }
            "summary" => saw_summary = true,
            other => {
                bail!("report is damaged: unknown record type {other:?} at byte offset {start}")
            }
        }
    }
    if !saw_summary {
        bail!("report is damaged: no terminal summary record");
    }
    Ok(total)
}

#[derive(Debug)]
struct Heaps {
    want: usize,
    total: usize,
    rare: BinaryHeap<Entry>,
    freq: BinaryHeap<FrequentHeapWorstFirst>,
}

impl Heaps {
    fn new(want: usize) -> Self {
        Heaps {
            want,
            total: 0,
            rare: BinaryHeap::new(),
            freq: BinaryHeap::new(),
        }
    }

    fn push(&mut self, entry: Entry) {
        self.total += 1;
        let rare_quota = rare_quota(self.want);
        if rare_quota > 0 {
            self.rare.push(entry.clone());
            if self.rare.len() > rare_quota {
                self.rare.pop();
            }
        }
        if self.want > 0 {
            self.freq.push(FrequentHeapWorstFirst(entry));
            if self.freq.len() > self.want {
                self.freq.pop();
            }
        }
    }

    fn into_pass(self) -> Pass1 {
        let mut rarest = self.rare.into_vec();
        rarest.sort_unstable();
        let mut frequent: Vec<Entry> = self.freq.into_vec().into_iter().map(|w| w.0).collect();
        frequent.sort_unstable_by(most_frequent_first);
        Pass1 {
            total: self.total,
            rarest,
            frequent,
        }
    }
}

fn pass1(path: &Path, want: usize) -> Result<Pass1> {
    let mut heaps = Heaps::new(want);
    scan(path, |_, id, count, offset| {
        heaps.push(Entry { count, id, offset });
        Ok(())
    })?;
    Ok(heaps.into_pass())
}

#[derive(Debug)]
pub struct Index {
    heaps: Heaps,
    saw_summary: bool,
}

impl Index {
    pub fn new(want: usize) -> Self {
        Index {
            heaps: Heaps::new(want),
            saw_summary: false,
        }
    }

    pub fn record(&mut self, record: &str, offset: u64) -> Result<()> {
        let (kind, id, count) = if let Some((id, count)) = writer_group_head(record) {
            ("group", id, count)
        } else {
            let meta: ValidatedRecordHead = serde_json::from_str(record)
                .map_err(|e| anyhow::anyhow!("parse failed at byte offset {offset}: {e}"))?;
            match meta.record_type.as_str() {
                "group" => ("group", meta.id, meta.count),
                "summary" => ("summary", 0, 0),
                other => bail!("unknown record type {other:?} at byte offset {offset}"),
            }
        };
        if self.saw_summary {
            bail!("a record follows the summary at byte offset {offset}");
        }
        if kind == "summary" {
            self.saw_summary = true;
        } else {
            self.heaps.push(Entry { count, id, offset });
        }
        Ok(())
    }
}

pub(crate) fn writer_group_head(record: &str) -> Option<(usize, usize)> {
    let rest = record.strip_prefix(r#"{"type":"group","id":"#)?;
    let (id, rest) = rest.split_once(',')?;
    let (count, _) = rest.strip_prefix(r#""count":"#)?.split_once(',')?;
    Some((id.parse().ok()?, count.parse().ok()?))
}

fn select(pass: &Pass1, n: usize) -> Vec<Entry> {
    let mut chosen: Vec<Entry> = pass.rarest.iter().take(rare_quota(n)).cloned().collect();
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

fn cut_at_char_boundary(s: &str, max: usize) -> (&str, bool) {
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
    let bunched = record
        .time_range
        .bunched
        .as_ref()
        .map(|b| {
            format!(
                " | {}",
                crate::briefing::bunched_clause(b.pct, &b.from, &b.to)
            )
        })
        .unwrap_or_default();
    let mut out = format!(
        "[{}x] id={} {} → {}{bunched}{}\n",
        record.count,
        record.id,
        stamp(&record.time_range.first_seen),
        stamp(&record.time_range.last_seen),
        if record.variation.is_empty() {
            "  variation: not recorded (not computed for this group, or none)"
        } else {
            ""
        },
    );
    let mut cut_template = false;
    if bounded {
        let (head, was_cut) = cut_at_char_boundary(&record.normalized, TEMPLATE_PREVIEW);
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
    let mut sampled_in_report: Vec<&str> = Vec::new();
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
                    let (head, was_cut) = cut_at_char_boundary(sample, SAMPLE_PREVIEW);
                    if was_cut {
                        cut_samples = true;
                    }
                    rendered.push(head.to_string());
                } else {
                    rendered.push(sample.clone());
                }
            }
            let mut fact = v.count_text(name);
            if !rendered.is_empty() {
                fact.push_str(&format!(" [{}]", rendered.join("|")));
            }
            if shown < v.samples.len() {
                cut_samples = true;
                fact.push_str(&format!(" …[showing {shown} of {}]", v.samples.len()));
            }
            if v.report_held_fewer_values() {
                sampled_in_report.push(name);
                fact.push_str(&format!(" …[report kept {}]", v.samples.len()));
            }
            facts.push(fact);
        }
        let sampled = if sampled_in_report.is_empty() {
            String::new()
        } else {
            format!(
                "  (report-sampled: {} — the report itself holds fewer values than the group had)",
                sampled_in_report.join(", ")
            )
        };
        out.push_str(&format!("variation: {}{sampled}\n", facts.join("  ")));
    }
    let previewed: Vec<&str> = [(cut_template, "template"), (cut_samples, "samples")]
        .into_iter()
        .filter_map(|(yes, name)| yes.then_some(name))
        .collect();
    if !previewed.is_empty() {
        out.push_str(&format!("previewed here: {}\n", previewed.join(", ")));
    }
    out
}

fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

fn recipes(path: &Path) -> String {
    let p = sh_quote(path);
    format!(
        "recipes (the report is JSONL; none of these prints the whole file):\n  \
         top {RECIPE_ROWS} by count:   jq -r 'select(.type==\"group\")|\"\\(.count)\\t\\(.id)\\t\\(.normalized[0:120])\"' -- {p} | sort -rn | head -{RECIPE_ROWS}\n  \
         first {RECIPE_ROWS} singletons: jq -r 'select(.type==\"group\" and .count==1)|\"\\(.id)\\t\\(.normalized[0:120])\"' -- {p} | head -{RECIPE_ROWS}\n  \
         (both stop at {RECIPE_ROWS} rows and preview 120 characters; drop the head or the slice for the rest)\n  \
         what is missing:      jq 'select(.type==\"summary\")|{{completeness,degraded}}' -- {p}\n  \
         one group in full by id (potentially large: a full record can be arbitrarily long):\n                        jq 'select(.type==\"group\" and .id==ID)' -- {p}\n"
    )
}

fn over_budget_message(mandatory: usize, budget: usize) -> String {
    let mut over = mandatory.saturating_sub(budget);
    loop {
        let msg = format!("overview: budget exceeded by mandatory text ({over} bytes over)\n");
        let actual = (mandatory + msg.len()).saturating_sub(budget);
        if actual == over {
            return msg;
        }
        over = actual;
    }
}

pub fn render(
    out: &mut impl Write,
    path: &Path,
    locator: &Locator<'_>,
    entries: Entries,
    budget: usize,
    briefing: Option<&str>,
    index: Option<Index>,
) -> Result<()> {
    let tail = recipes(path);
    let brief = briefing.unwrap_or("");

    if entries == Entries::All {
        return render_all(out, path, locator, brief, &tail);
    }

    let n = match entries {
        Entries::Count(n) => n,
        Entries::All => unreachable!(),
    };
    let pass = match index {
        Some(index) => {
            if !index.saw_summary {
                bail!("report is damaged: no terminal summary record");
            }
            let on_disk = std::fs::metadata(path)?.len();
            if on_disk != locator.size_bytes {
                bail!(
                    "report is damaged: {on_disk} bytes on disk, {} written",
                    locator.size_bytes
                );
            }
            index.heaps.into_pass()
        }
        None => pass1(path, n)?,
    };
    let chosen = select(&pass, n.min(pass.total));
    let selected = chosen.len();

    let reserved = brief.len() + 2 * locator.max_rendered_len(pass.total) + tail.len();
    let head_zero = locator.render(pass.total, selected, 0);
    let mandatory = brief.len() + 2 * head_zero.len() + tail.len();
    if mandatory > budget {
        let message = over_budget_message(mandatory, budget);
        let head = head_zero;
        out.write_all(brief.as_bytes())?;
        out.write_all(message.as_bytes())?;
        out.write_all(head.as_bytes())?;
        out.write_all(head.as_bytes())?;
        out.write_all(tail.as_bytes())?;
        return Ok(());
    }
    let room = budget.saturating_sub(reserved);

    let mut reader = open(path)?;
    let mut buf = Vec::new();
    let mut body = String::new();
    let mut printed = 0usize;
    for entry in &chosen {
        let record = read_at(&mut reader, &mut buf, entry.offset)?;
        let rendered = render_entry(&record, true);
        if body.len() + rendered.len() > room {
            break;
        }
        body.push_str(&rendered);
        printed += 1;
    }
    let head = locator.render(pass.total, selected, printed);
    out.write_all(brief.as_bytes())?;
    out.write_all(head.as_bytes())?;
    out.write_all(body.as_bytes())?;
    out.write_all(head.as_bytes())?;
    out.write_all(tail.as_bytes())?;
    Ok(())
}

fn read_at(
    reader: &mut BufReader<std::fs::File>,
    buf: &mut Vec<u8>,
    offset: u64,
) -> Result<Record> {
    reader.seek(SeekFrom::Start(offset))?;
    let n = read_bounded(reader, buf, offset)?;
    if n == 0 {
        bail!("record at byte offset {offset} disappeared between passes");
    }
    serde_json::from_slice(buf)
        .map_err(|e| anyhow::anyhow!("parse failed at byte offset {offset}: {e}"))
}

fn render_all(
    out: &mut impl Write,
    path: &Path,
    locator: &Locator<'_>,
    brief: &str,
    tail: &str,
) -> Result<()> {
    let total = scan(path, |bytes, _, _, offset| {
        serde_json::from_slice::<Record>(bytes)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("parse failed at byte offset {offset}: {e}"))
    })?;
    let head = locator.render(total, total, total);
    out.write_all(brief.as_bytes())?;
    out.write_all(head.as_bytes())?;

    let mut reader = open(path)?;
    let mut buf = Vec::new();
    let mut offset = 0u64;
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
        let record: Record = match serde_json::from_slice(&buf) {
            Ok(record) => record,
            Err(_) if is_summary(&buf) => continue,
            Err(e) => bail!("parse failed at byte offset {start}: {e}"),
        };
        out.write_all(render_entry(&record, false).as_bytes())?;
    }
    out.write_all(head.as_bytes())?;
    out.write_all(tail.as_bytes())?;
    Ok(())
}

fn is_summary(record: &[u8]) -> bool {
    serde_json::from_slice::<ValidatedRecordHead>(record)
        .is_ok_and(|head| head.record_type == "summary")
}

pub fn unavailable(locator: &Locator<'_>, error: &str) -> String {
    let head = locator.line(GroupCounts::UnknownPassFailed);
    format!(
        "{head}overview: unavailable ({error})\n{head}{}",
        recipes(locator.path)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
            file: crate::report::Finished::Durable,
            input: InputState::Complete,
            run_id: "run-x",
            size_bytes: 0,
        }
    }

    fn rendered(path: &Path, entries: Entries, budget: usize) -> String {
        let loc = locator(path);
        let mut out = Vec::new();
        render(&mut out, path, &loc, entries, budget, None, None).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn index_of(path: &Path, want: usize) -> Index {
        let mut index = Index::new(want);
        let mut offset = 0u64;
        for line in std::fs::read_to_string(path).unwrap().lines() {
            index.record(line, offset).unwrap();
            offset += line.len() as u64 + 1;
        }
        index
    }

    fn rendered_with(path: &Path, want: usize, index: Option<Index>) -> Result<String> {
        let mut loc = locator(path);
        loc.size_bytes = std::fs::metadata(path).unwrap().len();
        let mut out = Vec::new();
        render(
            &mut out,
            path,
            &loc,
            Entries::Count(want),
            DEFAULT_BYTES,
            None,
            index,
        )?;
        Ok(String::from_utf8(out).unwrap())
    }

    #[test]
    fn an_index_built_while_writing_renders_what_a_read_back_renders() {
        let counts: Vec<(usize, usize)> = (0..60).map(|id| (id, (id * 7919) % 23 + 1)).collect();
        let (_dir, path) = corpus(&counts);
        for want in [0, 1, 5, 40, 60, 100] {
            assert_eq!(
                rendered_with(&path, want, Some(index_of(&path, want))).unwrap(),
                rendered_with(&path, want, None).unwrap(),
                "want={want}"
            );
        }
    }

    #[test]
    fn an_index_refuses_a_report_whose_size_on_disk_is_not_what_was_written() {
        let (_dir, path) = corpus(&[(0, 3), (1, 1)]);
        let index = index_of(&path, 5);
        let mut loc = locator(&path);
        loc.size_bytes = std::fs::metadata(&path).unwrap().len() + 1;
        let err = render(
            &mut Vec::new(),
            &path,
            &loc,
            Entries::Count(5),
            DEFAULT_BYTES,
            None,
            Some(index),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("report is damaged: "), "{err}");
        assert!(err.contains(" bytes on disk, "), "{err}");
    }

    #[test]
    fn an_index_refuses_a_report_without_its_summary() {
        let (_dir, path) = corpus(&[(0, 3)]);
        let mut index = Index::new(5);
        let first = std::fs::read_to_string(&path).unwrap();
        index.record(first.lines().next().unwrap(), 0).unwrap();
        let err = rendered_with(&path, 5, Some(index))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no terminal summary record"), "{err}");
    }

    #[test]
    fn the_head_of_a_group_record_gives_its_id_and_count() {
        assert_eq!(
            writer_group_head(r#"{"type":"group","id":12,"count":3456,"token_types":[]}"#),
            Some((12, 3456))
        );
        assert_eq!(
            writer_group_head(r#"{"type":"summary","id":1,"count":2,"x":0}"#),
            None
        );
        assert_eq!(
            writer_group_head(r#"{"type":"group","count":2,"id":1,"x":0}"#),
            None
        );
    }

    #[test]
    fn a_record_the_head_cannot_read_is_parsed_in_full() {
        let mut index = Index::new(2);
        index
            .record(r#"{"count":9,"type":"group","id":4}"#, 0)
            .unwrap();
        index.record(r#"{"type":"summary"}"#, 40).unwrap();
        assert!(
            index
                .record(r#"{"type":"group","id":5,"count":1,"x":0}"#, 60)
                .is_err()
        );
        let pass = index.heaps.into_pass();
        assert_eq!(pass.total, 1);
        assert_eq!(
            pass.frequent,
            vec![Entry {
                count: 9,
                id: 4,
                offset: 0
            }]
        );
    }

    #[test]
    fn the_record_guard_is_sixteen_mebibytes() {
        assert_eq!(
            RECORD_GUARD, 16_777_216,
            "the guard is the documented single-record bound"
        );
    }

    #[test]
    fn a_capped_variation_without_a_kind_reads_as_a_lower_bound() {
        let mut v = Variation {
            distinct_count: 5,
            distinct_count_kind: None,
            samples: Vec::new(),
            samples_complete: None,
            capped: true,
        };
        assert_eq!(
            v.count_text("host"),
            "host>=5",
            "a capped rollup is a floor"
        );
        v.distinct_count_kind = Some(DistinctCountKind::LowerBound);
        assert_eq!(v.count_text("host"), "host>=5");
        v.distinct_count_kind = Some(DistinctCountKind::Exact);
        assert_eq!(v.count_text("host"), "host=5");
        v.distinct_count_kind = None;
        v.capped = false;
        assert_eq!(
            v.count_text("host"),
            "host~5 (kind unstated)",
            "without a kind and without a cap the count is unstated"
        );
    }

    #[test]
    fn a_cut_lands_on_the_last_boundary_at_or_below_the_limit() {
        assert_eq!(
            cut_at_char_boundary("ééé", 3),
            ("é", true),
            "ééé has boundaries 0,2,4,6; limit 3 must walk back to 2"
        );
        assert_eq!(cut_at_char_boundary("ééé", 6), ("ééé", false));
    }

    #[test]
    fn selection_takes_half_rarest_and_fills_with_the_most_frequent() {
        let (_d, path) = corpus(&[(0, 100), (1, 1), (2, 50), (3, 2), (4, 70)]);
        let pass = pass1(&path, 4).unwrap();
        assert_eq!(pass.total, 5, "the summary record is not a group");
        let chosen = select(&pass, 4);
        let ids: Vec<usize> = chosen.iter().map(|e| e.id).collect();
        assert_eq!(
            ids,
            vec![0, 1, 3, 4],
            "rarest 2 are ids 1,3; most frequent 2 are ids 0,4; shown in id order"
        );
    }

    #[test]
    fn ties_are_broken_by_ascending_id_and_the_quotas_still_fill() {
        let (_d, path) = corpus(&[(0, 7), (1, 7), (2, 7), (3, 7)]);
        let pass = pass1(&path, 3).unwrap();
        let ids: Vec<usize> = select(&pass, 3).iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), 3, "all-equal counts must not underfill");
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn a_tied_population_larger_than_both_heaps_keeps_the_smallest_ids() {
        let (_d, path) = corpus(&[(0, 7), (1, 7), (2, 7), (3, 7), (4, 7)]);
        let pass = pass1(&path, 2).unwrap();
        assert_eq!(
            pass.frequent.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![0, 1],
            "the frequent heap must retain the smallest ids at a tied cutoff"
        );
        let ids: Vec<usize> = select(&pass, 2).iter().map(|e| e.id).collect();
        assert_eq!(
            ids,
            vec![0, 1],
            "evicting by count asc, id asc would select [0, 3]"
        );
    }

    #[test]
    fn n_at_or_above_the_total_selects_every_group() {
        let (_d, path) = corpus(&[(0, 1), (1, 2), (2, 3)]);
        let pass = pass1(&path, 40).unwrap();
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
        let err = pass1(&path, 40).expect_err("the guard must trip");
        assert_eq!(
            err.to_string(),
            format!("record too large: > 16 MiB at byte offset {offset}")
        );
    }

    #[test]
    fn a_truncated_report_fails_the_pass_with_a_parse_error_at_its_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.jsonl");
        std::fs::write(&path, "{\"type\":\"group\",\"id\":0,\"co\n").unwrap();
        let err = pass1(&path, 40).expect_err("a half record must not parse");
        assert!(
            err.to_string().starts_with("parse failed at byte offset 0"),
            "{err}"
        );
    }

    #[test]
    fn a_malformed_middle_in_an_unselected_record_still_fails_the_pass() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"{{"type":"group","id":0,"count":1,"normalized":"x" garbage "y":}}"#
        )
        .unwrap();
        writeln!(f, r#"{{"type":"summary","complete":true}}"#).unwrap();
        drop(f);
        let err = pass1(&path, 40).expect_err("a damaged record must fail the pass");
        assert!(
            err.to_string().contains("parse failed"),
            "a prefix check would count this group and move on: {err}"
        );
    }

    #[test]
    fn a_report_cut_at_a_group_boundary_has_no_summary_and_is_damaged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.jsonl");
        std::fs::write(
            &path,
            "{\"type\":\"group\",\"id\":0,\"count\":1,\"normalized\":\"x\"}\n",
        )
        .unwrap();
        let err = pass1(&path, 40).expect_err("no terminal summary is a damaged report");
        assert_eq!(
            err.to_string(),
            "report is damaged: no terminal summary record"
        );
    }

    #[test]
    fn an_empty_report_is_damaged_not_an_empty_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.jsonl");
        std::fs::write(&path, "").unwrap();
        assert!(pass1(&path, 40).is_err(), "an empty report is damaged");
    }

    #[test]
    fn an_unavailable_overview_never_invents_a_total() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.jsonl");
        let out = unavailable(&locator(&path), "record too large");
        assert!(out.contains("groups: unknown"), "{out}");
        assert!(!out.contains("0 total"), "{out}");
    }

    #[test]
    fn the_budget_bounds_stdout_and_the_locator_reports_what_was_not_printed() {
        let records: Vec<(usize, usize)> = (0..200).map(|i| (i, i + 1)).collect();
        let (_d, path) = corpus(&records);
        let out = rendered(&path, Entries::Count(40), DEFAULT_BYTES);
        assert!(out.len() <= DEFAULT_BYTES, "{} bytes", out.len());
        assert!(out.contains("200 total, 40 selected"), "{out}");
        assert!(out.starts_with("report: "), "head locator first");
        assert!(out.contains("recipes"), "tail last");
    }

    #[test]
    fn the_written_bytes_never_exceed_the_budget_at_any_size() {
        let records: Vec<(usize, usize)> = (0..120).map(|i| (i, i % 9 + 1)).collect();
        let (_d, path) = corpus(&records);
        let loc = locator(&path);
        let tail = recipes(&path).len();
        let exact = 2 * loc.max_rendered_len(120) + tail;
        for budget in [
            1,
            9,
            10,
            99,
            100,
            999,
            1000,
            1024,
            4096,
            16384,
            65535,
            exact - 1,
            exact,
            exact + 1,
            exact + 200,
        ] {
            let out = rendered(&path, Entries::Count(40), budget);
            if out.contains("budget exceeded") {
                let over: usize = out
                    .split("mandatory text (")
                    .nth(1)
                    .unwrap()
                    .split(' ')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(
                    out.len(),
                    budget + over,
                    "the stated overrun must be exact at budget {budget}"
                );
            } else {
                assert!(
                    out.len() <= budget,
                    "budget {budget} (reservation exactly {exact}, probed at ±1 and across digit-width boundaries): wrote {} bytes",
                    out.len()
                );
            }
        }
    }

    #[test]
    fn a_tiny_budget_prints_both_locators_and_says_exactly_how_far_over_it_is() {
        let (_d, path) = corpus(&[(0, 1), (1, 2)]);
        let out = rendered(&path, Entries::Count(40), 1);
        assert!(out.contains("budget exceeded by mandatory text"), "{out}");
        assert_eq!(
            out.matches("report: ").count(),
            2,
            "both locators must print: {out}"
        );
        assert!(!out.contains("[1x] id=0"), "no entries follow: {out}");
    }

    #[test]
    fn overview_all_prints_every_group_in_report_order_with_no_budget() {
        let records: Vec<(usize, usize)> = (0..300).map(|i| (i, i + 1)).collect();
        let (_d, path) = corpus(&records);
        let out = rendered(&path, Entries::All, 1);
        let bounded = rendered(&path, Entries::Count(40), DEFAULT_BYTES);
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
        assert!(out.contains("previewed here: template"), "{out}");
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

    fn variation(
        distinct_count: usize,
        kind: Option<DistinctCountKind>,
        samples: Vec<String>,
        samples_complete: Option<bool>,
        capped: bool,
    ) -> Variation {
        Variation {
            distinct_count,
            distinct_count_kind: kind,
            samples,
            samples_complete,
            capped,
        }
    }

    #[test]
    fn samples_are_capped_at_three_and_eighty_bytes_each_with_the_count_declared() {
        let mut vars = BTreeMap::new();
        vars.insert(
            "ip".to_string(),
            variation(
                9,
                Some(DistinctCountKind::Exact),
                vec!["x".repeat(200), "b".into(), "c".into(), "d".into()],
                Some(false),
                false,
            ),
        );
        let record = Record {
            id: 1,
            count: 9,
            normalized: "t".into(),
            time_range: TimeRange::default(),
            variation: vars,
        };
        let out = render_entry(&record, true);
        assert!(out.contains("ip=9"), "{out}");
        assert!(out.contains("…[showing 3 of 4]"), "{out}");
        assert!(!out.contains("|d"), "the fourth sample is cut: {out}");
        assert!(out.contains(&"x".repeat(80)), "{out}");
        assert!(!out.contains(&"x".repeat(81)), "cut at 80 bytes: {out}");
        assert!(out.contains("previewed here: samples"), "{out}");
    }

    #[test]
    fn a_capped_count_is_never_shown_as_exact_and_report_sampling_is_its_own_fact() {
        let mut vars = BTreeMap::new();
        vars.insert(
            "name".to_string(),
            variation(
                64,
                Some(DistinctCountKind::LowerBound),
                vec!["a".into(), "b".into()],
                Some(false),
                true,
            ),
        );
        let record = Record {
            id: 4,
            count: 900,
            normalized: "t".into(),
            time_range: TimeRange::default(),
            variation: vars,
        };
        for bounded in [true, false] {
            let out = render_entry(&record, bounded);
            assert!(out.contains("name>=64"), "bounded={bounded}: {out}");
            assert!(!out.contains("name=64"), "bounded={bounded}: {out}");
            assert!(
                out.contains("report kept 2") && out.contains("report-sampled: name"),
                "bounded={bounded}: the report's own sampling must survive --overview all: {out}"
            );
            assert!(
                !out.contains("previewed here"),
                "bounded={bounded}: nothing was cut here: {out}"
            );
        }
    }

    #[test]
    fn a_record_without_a_variation_map_says_so_instead_of_staying_silent() {
        let record = Record {
            id: 2,
            count: 1,
            normalized: "t".into(),
            time_range: TimeRange::default(),
            variation: BTreeMap::new(),
        };
        assert!(
            render_entry(&record, true)
                .lines()
                .next()
                .unwrap()
                .contains("variation: not recorded"),
            "an uncomputed rollup must not read as 'no variation'"
        );
    }

    #[test]
    fn an_unstated_count_kind_is_labelled_unstated_not_exact() {
        let mut vars = BTreeMap::new();
        vars.insert(
            "ip".to_string(),
            variation(5, None, vec!["a".into()], None, false),
        );
        let record = Record {
            id: 0,
            count: 5,
            normalized: "t".into(),
            time_range: TimeRange::default(),
            variation: vars,
        };
        let out = render_entry(&record, true);
        assert!(out.contains("ip~5 (kind unstated)"), "{out}");
        assert!(out.contains("report-sampled: ip"), "1 of 5 kept: {out}");
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
                bunched: None,
            },
            variation: BTreeMap::new(),
        };
        assert!(
            render_entry(&record, true).starts_with("[2x] id=1 12:00 → -  variation: not recorded")
        );
    }

    #[test]
    fn a_path_with_shell_metacharacters_is_quoted_in_every_recipe() {
        let path = Path::new("/tmp/re port$(x)/it's/report.jsonl");
        let text = recipes(path);
        assert!(
            text.contains(r"'/tmp/re port$(x)/it'\''s/report.jsonl'"),
            "{text}"
        );
        assert_eq!(text.matches("jq").count(), 4, "four recipes: {text}");
        assert_eq!(text.matches(" -- ").count(), 4, "jq -- before the file");
    }
}
