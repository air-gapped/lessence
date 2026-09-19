//! The bounded overview printed on stdout after a default run's report is
//! complete.
//!
//! The report file is the complete record; stdout is a byte-bounded view of
//! it that declares everything it leaves out. Two sequential passes over the
//! finished file: pass 1 reads only (id, count, byte offset) per record into
//! two bounded heaps — R rarest and N most frequent, at most 2N entries —
//! keeping no template, sample or timestamp text; pass 2 seeks to
//! the selected offsets in ascending id order and renders one record at a
//! time, cutting previews on the fly. `--overview all` streams records to
//! the writer in report order, one at a time, with no heap, no offset list
//! and no assembled output string.
//!
//! The reader is bounded: a record longer than [`RECORD_GUARD`] is never
//! allocated in full. The reader stops at the guard and the pass fails, the
//! report is retained, and stdout says so. The guard and the N limit are the
//! bound; a measured RSS number is not.
//!
//! Every record is validated, not just the selected ones: a damaged record
//! anywhere in the file fails the pass instead of being counted and skipped,
//! and a report without its terminal summary record is damaged by
//! definition. Validation deserializes into a small fixed struct, so an
//! unread field is skipped by the parser rather than materialised into a
//! tree.

use anyhow::{Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BinaryHeap, HashSet};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
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
/// Rows the bounded jq recipes stop at, named in the recipe text itself.
const RECIPE_ROWS: usize = 40;

/// `--overview N | all`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Entries {
    Count(usize),
    All,
}

/// The four group counts a locator line carries. `None` means the overview
/// pass never got far enough to know them — they are printed as `unknown`,
/// never invented as zeroes.
#[derive(Clone, Copy)]
struct Counts {
    total: usize,
    selected: usize,
    printed: usize,
    omitted: usize,
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
    fn line(&self, counts: Option<Counts>) -> String {
        let groups = match counts {
            Some(c) => format!(
                "{} total, {} selected, {} printed, {} omitted",
                c.total, c.selected, c.printed, c.omitted
            ),
            None => "unknown (the overview pass could not read the report)".to_string(),
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
        self.line(Some(Counts {
            total,
            selected,
            printed,
            omitted: total - printed,
        }))
    }

    /// A true upper bound on the rendered width of this run's locator line:
    /// every one of the four counts is at most `total`, so rendering all
    /// four at `total`'s width is at least as wide as any final line. The
    /// reservation uses this, so the budget is settled before `printed` is
    /// known without ever under-reserving.
    fn reserved_len(&self, total: usize) -> usize {
        self.line(Some(Counts {
            total,
            selected: total,
            printed: total,
            omitted: total,
        }))
        .len()
    }
}

/// One record as pass 1 needs it: the discriminant, the id and the count.
/// Deserializing into this validates the whole record — serde_json parses
/// the fields it does not keep rather than building a tree of them — so a
/// malformed record anywhere fails the pass.
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

/// The report's own uncertainty about a variation entry, kept as the report
/// states it. `distinct_count` alone would read as exact even when the
/// rollup hit its cap, and a report that already sampled its own values is
/// a different fact from this renderer cutting a preview.
#[derive(Deserialize)]
struct Variation {
    distinct_count: usize,
    #[serde(default)]
    distinct_count_kind: Option<String>,
    #[serde(default)]
    samples: Vec<String>,
    #[serde(default)]
    samples_complete: Option<bool>,
    #[serde(default)]
    capped: bool,
}

impl Variation {
    /// `=n` when the report calls the count exact, `>=n` when it calls it a
    /// lower bound, `~n` when the record does not say.
    fn count_text(&self, name: &str) -> String {
        match self.distinct_count_kind.as_deref() {
            Some("exact") => format!("{name}={}", self.distinct_count),
            Some("lower_bound") => format!("{name}>={}", self.distinct_count),
            _ if self.capped => format!("{name}>={}", self.distinct_count),
            Some(_) | None => format!("{name}~{} (kind unstated)", self.distinct_count),
        }
    }

    /// Did the *report* hold fewer values than the group had? Distinct from
    /// anything this renderer cuts for the screen.
    fn report_sampled(&self) -> bool {
        match self.samples_complete {
            Some(complete) => !complete,
            None => self.capped || self.samples.len() < self.distinct_count,
        }
    }
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

/// Retention order for the frequent heap. The frequent ranking is count
/// descending, ties by *ascending* id, so the entry to evict at a tied
/// cutoff is the one with the largest id — not the smallest, which is what
/// `Reverse<Entry>` would pop. `Ord` here puts that worst candidate at the
/// top of a max-heap.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Worst(Entry);

impl Ord for Worst {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .0
            .count
            .cmp(&self.0.count)
            .then(self.0.id.cmp(&other.0.id))
    }
}
impl PartialOrd for Worst {
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

fn open(path: &Path) -> Result<BufReader<std::fs::File>> {
    Ok(BufReader::with_capacity(
        256 * 1024,
        std::fs::File::open(path)?,
    ))
}

/// Pass 1: the two bounded heaps plus the total group count.
#[derive(Debug)]
struct Pass1 {
    total: usize,
    rarest: Vec<Entry>,
    frequent: Vec<Entry>,
}

/// Walk every record in the report, validating each one and the required
/// terminal summary. `visit` sees (bytes, id, count, offset) for each group
/// record; the bytes are the pass's one buffer, reused for the next record.
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
        // Full-document validation of every record, not a prefix check: a
        // malformed middle in a record this pass does not select is still a
        // damaged report, and a damaged report never renders as a success.
        let meta: Meta = serde_json::from_slice(&buf)
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

fn pass1(path: &Path, want: usize) -> Result<Pass1> {
    let rare_quota = want.div_ceil(2);
    // Max-heap bounded to `rare_quota`: the worst element is the largest
    // count, so popping it keeps the rarest.
    let mut rare: BinaryHeap<Entry> = BinaryHeap::new();
    // Bounded to `want` by the frequent ranking itself: the top of this heap
    // is the lowest count and, among ties, the largest id.
    let mut freq: BinaryHeap<Worst> = BinaryHeap::new();
    let total = scan(path, |_, id, count, offset| {
        let entry = Entry { count, id, offset };
        if rare_quota > 0 {
            rare.push(entry.clone());
            if rare.len() > rare_quota {
                rare.pop();
            }
        }
        if want > 0 {
            freq.push(Worst(entry));
            if freq.len() > want {
                freq.pop();
            }
        }
        Ok(())
    })?;
    let mut rarest = rare.into_vec();
    rarest.sort_unstable();
    let mut frequent: Vec<Entry> = freq.into_vec().into_iter().map(|w| w.0).collect();
    // Descending count, ties by ascending id.
    frequent.sort_unstable_by(|a, b| b.count.cmp(&a.count).then(a.id.cmp(&b.id)));
    Ok(Pass1 {
        total,
        rarest,
        frequent,
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
        "[{}x] id={} {} → {}{}\n",
        record.count,
        record.id,
        stamp(&record.time_range.first_seen),
        stamp(&record.time_range.last_seen),
        // Honest about not knowing: a record carries no flag saying whether
        // the rollup was skipped for this group or the group simply had
        // nothing to vary. Said on this line, not a line of its own — the
        // overview is a byte budget.
        if record.variation.is_empty() {
            "  variation: not recorded (not computed for this group, or none)"
        } else {
            ""
        },
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
                    let (head, was_cut) = cut(sample, SAMPLE_PREVIEW);
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
            // A cut made *here* is a display omission. A report that already
            // held fewer values than the group had is a different fact, and
            // it is named on its own line below — in every mode, including
            // `--overview all`, which cuts nothing of its own.
            if shown < v.samples.len() {
                cut_samples = true;
                fact.push_str(&format!(" …[showing {shown} of {}]", v.samples.len()));
            }
            if v.report_sampled() {
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

/// Single-quote a path for a shell recipe. A report directory with a space,
/// a `$` or a quote in it must not change the command the caller pastes.
fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

/// The four recipes. None of them cats the file, and the two listing ones
/// are bounded by row count and carry ids for drill-down.
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

/// The over-budget message, whose own length counts toward the overrun it
/// states. The digits of `n` can widen `n`, so settle it by iteration — two
/// rounds at most in practice, and it always terminates because the width
/// only ever grows.
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

/// Render the whole stdout overview into `out`. `briefing` is
/// already-rendered text (`None` under `-q`).
///
/// A bounded overview is at most `budget` bytes and is assembled before it
/// is written, so a failed pass writes nothing. `--overview all` has no
/// budget and streams: every record it will print has already been
/// validated by pass 1, so the streaming half fails only on the writer.
pub fn render(
    out: &mut impl Write,
    path: &Path,
    locator: &Locator<'_>,
    entries: Entries,
    budget: usize,
    briefing: Option<&str>,
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
    let pass = pass1(path, n)?;
    let chosen = select(&pass, n.min(pass.total));
    let selected = chosen.len();

    // Reserve the mandatory text first: briefing, head locator, tail
    // locator, recipes. The locator reservation is a true upper bound on
    // this run's locator width, so the budget is settled before `printed`
    // is known and the final bytes can never exceed it.
    let reserved = brief.len() + 2 * locator.reserved_len(pass.total) + tail.len();
    let head_zero = locator.render(pass.total, selected, 0);
    let mandatory = brief.len() + 2 * head_zero.len() + tail.len();
    if mandatory > budget {
        // Both locators still print — the head and the tail are placed
        // where a truncated capture keeps one of them — and the stated
        // overrun counts every byte written, this message included.
        let message = over_budget_message(mandatory, budget);
        let head = head_zero;
        out.write_all(brief.as_bytes())?;
        out.write_all(message.as_bytes())?;
        out.write_all(head.as_bytes())?;
        out.write_all(head.as_bytes())?;
        out.write_all(tail.as_bytes())?;
        return Ok(());
    }
    // The reservation is an upper bound, so it can exceed the budget while
    // the mandatory text alone fits. Then there is simply no room for an
    // entry, and the output is the mandatory text — still inside B.
    let room = budget.saturating_sub(reserved);

    let mut reader = open(path)?;
    let mut buf = Vec::new();
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

/// `--overview all`: every group, report order, no budget and no cuts.
///
/// Nothing accumulates. Pass 1 counts and validates every record — it keeps
/// no entry list — and the second pass reads the file forward, rendering and
/// writing one record at a time. Peak memory is one record.
fn render_all(
    out: &mut impl Write,
    path: &Path,
    locator: &Locator<'_>,
    brief: &str,
    tail: &str,
) -> Result<()> {
    // Validate with the renderer's own shape, so the streaming half below
    // cannot fail halfway through a written overview. Each record is parsed
    // and dropped: nothing accumulates across the scan.
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
            // The summary record: already validated by the scan above.
            Err(_) => continue,
        };
        out.write_all(render_entry(&record, false).as_bytes())?;
    }
    out.write_all(head.as_bytes())?;
    out.write_all(tail.as_bytes())?;
    Ok(())
}

/// The head/tail-only output for a run whose report is complete but whose
/// overview pass failed. No group is silently omitted: the reason is named,
/// and the counts say `unknown` rather than inventing a total the pass never
/// established.
pub fn unavailable(locator: &Locator<'_>, error: &str) -> String {
    let head = locator.line(None);
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
            file: "complete".into(),
            input: "complete".into(),
            run_id: "run-x",
            size_bytes: 0,
        }
    }

    fn rendered(path: &Path, entries: Entries, budget: usize) -> String {
        let loc = locator(path);
        let mut out = Vec::new();
        render(&mut out, path, &loc, entries, budget, None).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn the_record_guard_is_sixteen_mebibytes() {
        // The guard is the documented bound on a single record; an
        // arithmetic slip here silently changes what the reader refuses.
        assert_eq!(RECORD_GUARD, 16_777_216);
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
        v.distinct_count_kind = Some("lower_bound".into());
        assert_eq!(v.count_text("host"), "host>=5");
        v.distinct_count_kind = Some("exact".into());
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
        // "ééé" is six bytes with boundaries at 0, 2, 4, 6. A limit of 3
        // must walk back to 2, not to 1 or 0, and must not slice mid-char.
        assert_eq!(cut("ééé", 3), ("é", true));
        assert_eq!(cut("ééé", 6), ("ééé", false));
    }

    #[test]
    fn selection_takes_half_rarest_and_fills_with_the_most_frequent() {
        let (_d, path) = corpus(&[(0, 100), (1, 1), (2, 50), (3, 2), (4, 70)]);
        let pass = pass1(&path, 4).unwrap();
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
        let pass = pass1(&path, 3).unwrap();
        let ids: Vec<usize> = select(&pass, 3).iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), 3, "all-equal counts must not underfill");
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn a_tied_population_larger_than_both_heaps_keeps_the_smallest_ids() {
        // Five groups, all count 7, N=2: the frequent heap retains two of
        // five ties. Evicting by "count asc, id asc" would keep ids 3 and 4
        // and select [0, 3]; the frequent ranking is count desc, id asc.
        let (_d, path) = corpus(&[(0, 7), (1, 7), (2, 7), (3, 7), (4, 7)]);
        let pass = pass1(&path, 2).unwrap();
        assert_eq!(
            pass.frequent.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![0, 1],
            "the frequent heap must retain the smallest ids at a tied cutoff"
        );
        let ids: Vec<usize> = select(&pass, 2).iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![0, 1]);
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
        // Prefix and trailing `}` are exactly what the writer emits; the
        // middle is not JSON. A prefix check would count this group and
        // move on.
        writeln!(
            f,
            r#"{{"type":"group","id":0,"count":1,"normalized":"x" garbage "y":}}"#
        )
        .unwrap();
        writeln!(f, r#"{{"type":"summary","complete":true}}"#).unwrap();
        drop(f);
        let err = pass1(&path, 40).expect_err("a damaged record must fail the pass");
        assert!(err.to_string().contains("parse failed"), "{err}");
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
        // An empty file is the same failure, not a successful empty run.
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
        // Digit boundaries on both the counts and the budget, plus budgets
        // sized to the exact reservation and one byte either side of it.
        let records: Vec<(usize, usize)> = (0..120).map(|i| (i, i % 9 + 1)).collect();
        let (_d, path) = corpus(&records);
        let loc = locator(&path);
        let tail = recipes(&path).len();
        let exact = 2 * loc.reserved_len(120) + tail;
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
                    "budget {budget}: wrote {} bytes",
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
        kind: Option<&str>,
        samples: Vec<String>,
        samples_complete: Option<bool>,
        capped: bool,
    ) -> Variation {
        Variation {
            distinct_count,
            distinct_count_kind: kind.map(str::to_string),
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
                Some("exact"),
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
                Some("lower_bound"),
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
