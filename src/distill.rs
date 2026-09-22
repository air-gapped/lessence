//! `--distill`: write the input back out as a small log that folds the way
//! the big one did.
//!
//! The folder already knows every shape a log holds. A distillation is that
//! knowledge expressed as a log again: a few members of every group it
//! formed, every line that did not fold, in the original order. Feed the
//! result back through lessence and the same templates come out — which is
//! not a hope but a check the command runs on itself before it exits 0.
//!
//! Development tooling. The flags are hidden and the output is a test
//! corpus, not a report for a reader.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::anonymize::{Anonymizer, at_token_boundary};
use crate::config::Config;
use crate::folder::{
    DISTILL_CHEAP_LINE_BYTES, DistillGroup, PatternFolder, ROLLUP_DISTINCT_CAP, VARIES_MARK,
};
use crate::ingest::{Event, IngestReport, Ingestor, InputReader};
use crate::normalize::Normalizer;
use crate::patterns::Token;

/// How many failures of one kind to print before summarising the rest.
/// A contract check that floods the terminal teaches nothing the first
/// twenty lines did not.
const MAX_REPORTED: usize = 20;

pub struct Options {
    /// `--distill`: select members. False means `--anonymize` alone, which
    /// keeps every line.
    pub distill: bool,
    /// `--members N`.
    pub members: usize,
    /// `--anonymize`, or `--anonymize-words` (which implies it).
    pub anonymize: bool,
    /// `--anonymize-words FILE`.
    pub words_file: Option<PathBuf>,
    /// `--seed N`; `None` draws one from the clock.
    pub seed: Option<u64>,
}

/// Run a distillation and its self-checks. Returns the process exit code:
/// 0 when every contract held, 1 when one did not.
pub fn run(
    config: &Config,
    ingestor: &Ingestor,
    readers: Vec<InputReader>,
    opts: &Options,
) -> Result<i32> {
    // The second pass needs the lines again and stdin cannot be rewound, so
    // the input is buffered here — under the same limits every other mode
    // reads through.
    let mut lines: Vec<String> = Vec::new();
    let report: IngestReport = ingestor.run(readers, |event| {
        if let Event::Line { text, .. } = event {
            lines.push(text.to_string());
        }
        Ok(())
    })?;

    let words = match &opts.words_file {
        Some(path) => read_vocabulary(path)?,
        None => Vec::new(),
    };
    let mut anonymizer = opts
        .anonymize
        .then(|| Anonymizer::new(opts.seed.unwrap_or_else(Anonymizer::random_seed), words));
    let normalizer = Normalizer::new(config.clone());

    // The whole input is anonymised, not just the lines that survive
    // selection. The contract is that the distilled file folds like the log
    // it came from — and after anonymisation the log it came from is the
    // anonymised one, so that is what the templates and shapes are taken
    // from. Comparing an anonymised output against a raw input would report
    // every invented value as a lost shape.
    let anonymized = match anonymizer.as_mut() {
        Some(a) => Some(anonymize_all(&lines, a, &normalizer)?),
        None => None,
    };
    let source: &[String] = anonymized.as_deref().unwrap_or(&lines);

    // Selection runs on the anonymised text, not the raw: inventing a value
    // can change how a line folds, and a distillation selected from a log
    // other than the one it emits would carry members for groups that no
    // longer exist.
    let source_fold = fold(config, source)?;

    // Whether a chosen pair really stays apart can only be answered by
    // folding the result: two groups the input kept apart may merge once
    // the thousands of lines between them are gone, and a corpus that
    // over-folds would teach every later gate that the over-fold is
    // correct. Where it happens the bucket picks a different partner and
    // the fold is tried again; the loop ends when nothing merged or when
    // no untried bucket is left to blame.
    let mut careful = Careful::new();
    let (kept, out_lines, output_fold) = loop {
        let kept = keep_set(source, opts, &source_fold, &careful);
        let out_lines: Vec<String> = kept.lines.iter().map(|&n| source[n - 1].clone()).collect();
        let output_fold = fold(config, &out_lines)?;
        let blame: Vec<Vec<&'static str>> = merged_templates(&kept, &output_fold)
            .iter()
            .filter_map(|t| source_fold.groups.iter().find(|g| &&g.template == t))
            .map(|g| g.token_types.clone())
            .filter(|k| careful.get(k).copied().unwrap_or(0) < SPLIT_GIVE_UP)
            .collect();
        if blame.is_empty() {
            break (kept, out_lines, output_fold);
        }
        for key in blame {
            *careful.entry(key).or_default() += 1;
        }
    };

    let mut stdout = io::stdout().lock();
    for line in &out_lines {
        match writeln!(stdout, "{line}") {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(0),
            Err(e) => return Err(e.into()),
        }
    }
    stdout.flush()?;

    let mut ok = true;
    ok &= compare_coverage(&source_fold, &output_fold, &kept);
    if let Some(a) = anonymizer.as_ref() {
        ok &= check_survivors(&a.replaced_originals(), &out_lines);
        ok &= check_vocabulary(a, &out_lines);
    }

    Ok(i32::from(!ok || report.fail_pattern_matched))
}

/// Learn every value the detectors find, then rewrite every line against
/// all of them. Two phases, because a value first seen on the last line must
/// still be invented on the first: consistency is "everywhere in the run",
/// not "everywhere after here". Detection is batched and parallel so a large
/// log never holds every line's tokens at once.
fn anonymize_all(
    lines: &[String],
    anonymizer: &mut Anonymizer,
    normalizer: &Normalizer,
) -> Result<Vec<String>> {
    const BATCH: usize = 10_000;
    for chunk in lines.chunks(BATCH) {
        let batch: Vec<Vec<Token>> = chunk
            .par_iter()
            .map(|line| {
                normalizer
                    .normalize_line(line.clone())
                    .map(|l| l.tokens)
                    .unwrap_or_default()
            })
            .collect();
        for (line, tokens) in chunk.iter().zip(&batch) {
            anonymizer.learn(tokens);
            anonymizer.learn_text(line);
        }
    }
    anonymizer.seal();
    Ok(lines.iter().map(|line| anonymizer.rewrite(line)).collect())
}

/// What one fold of an input yields: a record per group of what it can
/// prove and the lines that prove it.
struct Fold {
    groups: Vec<DistillGroup>,
}

impl Fold {
    /// Everything a distillation of this input must still prove.
    fn coverage(&self) -> Coverage {
        let mut c = Coverage::default();
        for g in &self.groups {
            c.structures.insert(g.token_types.clone());
            c.token_types.extend(g.all_types.iter().copied());
            c.folded |= g.kept.len() >= crate::config::DEFAULT_MIN_COLLAPSE;
            c.varies |= g.template.contains(VARIES_MARK);
            c.capped |= g.distinct_forms > ROLLUP_DISTINCT_CAP;
            c.capped_affordable |= !g.capping_extra.is_empty();
        }
        c
    }

    fn templates(&self) -> BTreeSet<&str> {
        self.groups.iter().map(|g| g.template.as_str()).collect()
    }
}

/// The properties a distilled log has to carry over from the log it came
/// from. Not every template — a hundred literal variations of one event
/// prove exactly what two of them prove, and the difference between those
/// two numbers is the whole size of the file. The templates that *were*
/// chosen are held separately, in [`Cover::templates`]: those must survive,
/// or the distillation merged two things the input kept apart.
#[derive(Default)]
struct Coverage {
    /// Every distinct token-type structure.
    structures: BTreeSet<Vec<&'static str>>,
    /// Every token type that fires anywhere.
    token_types: BTreeSet<&'static str>,
    /// Some group folds at all — below `min_collapse` no variation is
    /// computed, so a file of singletons proves no grouping.
    folded: bool,
    /// Some template carries a `<VARIES>` slot.
    varies: bool,
    /// Some rollup reports `capped`.
    capped: bool,
    /// Some group could show the capped state without costing a fortune
    /// in bytes. The state has to be visible somewhere across the corpus
    /// set, not in every corpus: a log of 23 KB Kubernetes events would
    /// pay megabytes for it, so there it is dropped on purpose and the
    /// contract does not ask for it back.
    capped_affordable: bool,
}

/// The chosen lines, and what choosing them promised.
#[derive(Default)]
struct Cover {
    lines: BTreeSet<usize>,
    /// The template of every group the cover kept. Each one must still be
    /// a group of its own after the output is folded: two of them landing
    /// in one group is an over-fold the input did not have.
    templates: BTreeSet<String>,
}

fn fold(config: &Config, lines: &[String]) -> Result<Fold> {
    let mut folder = PatternFolder::new(config.clone());
    for (i, line) in lines.iter().enumerate() {
        folder.process_line_at(line, None, i + 1)?;
    }
    folder.finish()?;
    Ok(Fold {
        groups: folder.take_distilled(),
    })
}

/// The input line numbers the output carries, in order.
///
/// `--anonymize` without `--distill` keeps everything. `--distill` keeps a
/// covering subset: for each distinct token-type structure the group that
/// shows it best, plus the group nearest to that one wherever the
/// structure split, plus whatever top-up the remaining properties need.
/// Everything else in the input is another literal spelling of a shape
/// already present.
fn keep_set(lines: &[String], opts: &Options, source: &Fold, careful: &Careful) -> Cover {
    if !opts.distill {
        return Cover {
            lines: (1..=lines.len()).collect(),
            templates: BTreeSet::new(),
        };
    }
    cover(&source.groups, careful)
}

/// How hard a structure has already been tried. A bucket starts by
/// pairing its busiest group with the nearest other one — the split worth
/// proving. If those two merge once the log between them is gone, the
/// most *distant* group in the bucket is paired instead; if that merges
/// too, the bucket keeps its primary alone and claims no split. Dropping
/// the partner costs no coverage: every group in a bucket carries the
/// same structure and the same token types.
type Careful = BTreeMap<Vec<&'static str>, u8>;

/// Longest common prefix, in bytes. Two templates that agree for a long
/// way and then disagree are the pair a fold came closest to merging, so
/// they are the pair worth keeping as the proof that it did not.
fn shared_prefix(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

/// The words of a template, as a set. Position-independent, which is the
/// whole point: a prefix score is decided by whatever comes first, and on
/// a structured line that is almost nothing. Measured on a Tetragon
/// export, `"binary"` first occurs at byte 116 of a 21,293-byte median
/// line — so once two templates diverge there, 99.5% of the line cannot
/// influence a prefix score at all, and a subtree appearing or vanishing
/// deep in the object reads as no distance at all.
fn word_set(template: &str) -> BTreeSet<&str> {
    template.split_whitespace().collect()
}

/// How much two templates say in common, 0..=1000. Jaccard — shared words
/// over total distinct words — in integer arithmetic, so the choice is
/// orderable and cannot move with float rounding between runs.
fn word_overlap(a: &BTreeSet<&str>, b: &BTreeSet<&str>) -> usize {
    let union = a.union(b).count();
    if union == 0 {
        return 1000;
    }
    a.intersection(b).count() * 1000 / union
}

/// Attempts per structure before the split is given up on.
const SPLIT_GIVE_UP: u8 = 2;

fn cover(groups: &[DistillGroup], careful: &Careful) -> Cover {
    let mut buckets: BTreeMap<&[&'static str], Vec<usize>> = BTreeMap::new();
    for (i, g) in groups.iter().enumerate() {
        buckets.entry(&g.token_types).or_default().push(i);
    }

    let mut chosen: BTreeSet<usize> = BTreeSet::new();
    for (key, members) in &buckets {
        // The busiest group shows the structure; ties go to the earliest so
        // the choice does not move between runs.
        let &primary = members
            .iter()
            .max_by_key(|&&i| (groups[i].count, std::cmp::Reverse(i)))
            .expect("a bucket is never empty");
        chosen.insert(primary);

        // Two kinds of split have to survive, and one group of each is
        // enough. A *literal* split is two groups that agree for a long
        // way and then say a different word — the pair a widened template
        // would swallow first, so the nearest one is taken. An *anchor*
        // split is two groups the folder promises never to merge whatever
        // they look like, `success=yes` against `success=no`; that promise
        // stops being tested the moment one side is dropped, so one group
        // from a different anchor comes too. Taking one of each rather
        // than every anchor value is what keeps a log of fifty pods from
        // costing fifty copies of the same event.
        let level = careful.get(key.to_vec().as_slice()).copied().unwrap_or(0);
        if level < SPLIT_GIVE_UP
            && let Some(&partner) = members
                .iter()
                .filter(|&&i| i != primary && groups[i].anchor == groups[primary].anchor)
                .max_by_key(|&&i| {
                    let shared = shared_prefix(&groups[i].template, &groups[primary].template);
                    // Where the nearest pair turns out to merge once the
                    // log around it is gone, the most *distant* group is
                    // taken instead: a split the file can prove beats a
                    // stronger one it cannot.
                    let rank = if level == 0 {
                        shared
                    } else {
                        usize::MAX - shared
                    };
                    (rank, std::cmp::Reverse(i))
                })
        {
            chosen.insert(partner);
        }
        // The nearest group proves the split; the *farthest* proves the
        // bucket is not uniform. A token-type structure is a coarse key on
        // a wide JSON line — twenty thousand characters of object can hold
        // an entirely different event and still tokenise the same way — so
        // without this the cover keeps three neighbours and calls a bucket
        // covered. Measured on a Tetragon export with the process-credential
        // and namespace subtrees on: four events whose templates shared
        // about a hundred of twenty-three thousand characters with anything
        // kept were dropped, among them the only lines carrying
        // `security_context.privileged` and the privilege-raise policy hits.
        // Two notions of "farthest", because neither subsumes the other and
        // each demonstrably catches shapes the other drops. By prefix: the
        // group that diverges earliest, which on a structured line means
        // early fields — it is what finds the kprobe policy-hit arguments.
        // By word set: the group with the least vocabulary in common,
        // position-independent — it is what finds a `security_context`
        // subtree buried deep in an otherwise ordinary event. Measured on
        // the Tetragon corpus: prefix alone reaches 98.7% of the input's
        // JSON paths but keeps no privileged container; word set alone
        // keeps the privileged containers and falls to 94.4%, losing the
        // whole `process_credentials_arg` subtree. Together they cover both.
        if level < SPLIT_GIVE_UP {
            let primary_words = word_set(&groups[primary].template);
            let others = || members.iter().filter(|&&i| i != primary);
            if let Some(&far) = others().min_by_key(|&&i| {
                (
                    shared_prefix(&groups[i].template, &groups[primary].template),
                    i,
                )
            }) {
                chosen.insert(far);
            }
            if let Some(&far) = others().min_by_key(|&&i| {
                (
                    word_overlap(&word_set(&groups[i].template), &primary_words),
                    i,
                )
            }) {
                chosen.insert(far);
            }
        }

        // Where the lines are small, every anchor value gets a group:
        // there is no telling from here which of them a gate cares about,
        // and `success=no` buried under a hundred busier anchors is
        // exactly the one worth having. Where the lines are large the
        // same completeness would cost megabytes, so one other anchor
        // proves the mechanism and the rest are dropped.
        let mut by_anchor: BTreeMap<u64, usize> = BTreeMap::new();
        for &i in members
            .iter()
            .filter(|&&i| groups[i].anchor != groups[primary].anchor)
        {
            by_anchor
                .entry(groups[i].anchor)
                .and_modify(|best| {
                    if (groups[i].count, std::cmp::Reverse(i))
                        > (groups[*best].count, std::cmp::Reverse(*best))
                    {
                        *best = i;
                    }
                })
                .or_insert(i);
        }
        let cheap = groups[primary].avg_bytes <= DISTILL_CHEAP_LINE_BYTES;
        let mut others: Vec<usize> = by_anchor.into_values().collect();
        if !cheap {
            others.sort_unstable_by_key(|&i| (std::cmp::Reverse(groups[i].count), i));
            others.truncate(1);
        }
        chosen.extend(others);
    }

    // Top-ups for the properties a per-structure choice does not imply.
    if !chosen
        .iter()
        .any(|&i| groups[i].template.contains(VARIES_MARK))
        && let Some(i) = cheapest(groups, |g| g.template.contains(VARIES_MARK))
    {
        chosen.insert(i);
    }
    if !chosen
        .iter()
        .any(|&i| groups[i].kept.len() >= crate::config::DEFAULT_MIN_COLLAPSE)
        && let Some(i) = cheapest(groups, |g| {
            g.kept.len() >= crate::config::DEFAULT_MIN_COLLAPSE
        })
    {
        chosen.insert(i);
    }

    let mut out = Cover::default();
    for &i in &chosen {
        out.lines.extend(groups[i].kept.iter().copied());
        out.templates.insert(groups[i].template.clone());
    }

    // `capped` costs sixty-odd extra lines, so it is taken once per input
    // and only from a group that offered it (small lines, reachable cap).
    // A chosen group having reached the cap in the *source* proves nothing
    // here: the output carries six of its forms unless the extra members
    // come with it.
    if let Some(i) = cheapest(groups, |g| !g.capping_extra.is_empty()) {
        out.lines.extend(groups[i].kept.iter().copied());
        out.lines.extend(groups[i].capping_extra.iter().copied());
        out.templates.insert(groups[i].template.clone());
    }
    out
}

/// The group satisfying `want` that costs the fewest lines to bring in.
fn cheapest(groups: &[DistillGroup], want: impl Fn(&DistillGroup) -> bool) -> Option<usize> {
    groups
        .iter()
        .enumerate()
        .filter(|(_, g)| want(g))
        .min_by_key(|(i, g)| (g.kept.len() + g.capping_extra.len(), *i))
        .map(|(i, _)| i)
}

/// Contract 1: everything the input proved, the output still proves.
///
/// Not template equality — `--distill` drops redundant spellings of a
/// shape on purpose, so the output's template set is a subset by design.
/// What may not shrink is the coverage: the structures, the token types,
/// the splits, and the three variation states.
/// A template's literal words — everything outside a `<PLACEHOLDER>`.
///
/// Two templates with the same literal words say the same thing and
/// differ only in what sits between the words, so folding them together
/// widens a placeholder and loses nothing. Two with different literal
/// words are different events, and folding them is the over-fold that
/// matters: `Server Reject` disappearing inside `Server Busy`.
fn literal_words(template: &str) -> Vec<&str> {
    let mut words: Vec<&str> = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('<') {
        words.extend(rest[..open].split_whitespace());
        match rest[open..].find('>') {
            Some(close) => rest = &rest[open + close + 1..],
            None => return words,
        }
    }
    words.extend(rest.split_whitespace());
    words
}

/// The groups the cover deliberately kept whose event is no longer shown
/// on a line of its own once the output is folded.
///
/// A distilled corpus is what every later gate reads as correct, so it
/// must never itself demonstrate an over-fold. It may, though, fold two
/// spellings of one event together — the input often keeps those apart
/// only because thousands of lines sat between them — and that is the
/// difference the literal words decide.
fn merged_templates<'a>(cover: &'a Cover, output: &Fold) -> Vec<&'a String> {
    let have = output.templates();
    let said: BTreeSet<Vec<&str>> = have.iter().map(|t| literal_words(t)).collect();
    cover
        .templates
        .iter()
        .filter(|t| !have.contains(t.as_str()) && !said.contains(&literal_words(t)))
        .collect()
}

fn compare_coverage(source: &Fold, output: &Fold, cover: &Cover) -> bool {
    let want = source.coverage();
    let have = output.coverage();

    let missing = |what: &str, items: Vec<String>| -> bool {
        let refs: Vec<&String> = items.iter().collect();
        report(what, &refs);
        items.is_empty()
    };

    let mut ok = missing(
        "token-type structure missing from the distilled output",
        want.structures
            .difference(&have.structures)
            .map(|s| s.join(","))
            .collect(),
    );
    ok &= missing(
        "token type missing from the distilled output",
        want.token_types
            .difference(&have.token_types)
            .map(|t| (*t).to_string())
            .collect(),
    );
    ok &= missing(
        "two groups the input kept apart merged in the distilled output",
        merged_templates(cover, output)
            .into_iter()
            .cloned()
            .collect(),
    );
    for (name, wanted, got) in [
        ("a folded group", want.folded, have.folded),
        ("a <VARIES> template", want.varies, have.varies),
        (
            "a capped rollup",
            want.capped && want.capped_affordable,
            have.capped,
        ),
    ] {
        if wanted && !got {
            eprintln!("lessence: the distilled output no longer shows {name}");
            ok = false;
        }
    }
    ok
}

/// Contract 2: no value the rewriter actually replaced survives in the
/// output. Only values whose invention differs from the original are asked
/// for: `fe80::` and a Kubernetes name of pure words are what the table says
/// they should be. Looked up at token boundaries — the same rule the rewriter used,
/// so a hostname `db` inside `dbus` is not reported as a survivor of a
/// replacement that never claimed to touch it.
fn check_survivors(values: &HashSet<String>, out_lines: &[String]) -> bool {
    if values.is_empty() {
        return true;
    }
    let lengths: BTreeSet<usize> = values.iter().map(String::len).collect();

    let mut survivors: BTreeSet<String> = BTreeSet::new();
    for line in out_lines {
        for word in line.split_whitespace() {
            let b = word.as_bytes();
            for start in 0..b.len() {
                if !word.is_char_boundary(start) {
                    continue;
                }
                for &len in &lengths {
                    let end = start + len;
                    if end > b.len() {
                        break;
                    }
                    if !word.is_char_boundary(end) || !at_token_boundary(word, start, end) {
                        continue;
                    }
                    if values.contains(&word[start..end]) {
                        survivors.insert(word[start..end].to_string());
                    }
                }
            }
        }
    }
    let refs: Vec<&String> = survivors.iter().collect();
    report("original value survived anonymisation", &refs);
    survivors.is_empty()
}

/// Contract 3: every listed word is gone. A word of 6 or more characters is
/// checked case-insensitively as a substring anywhere — long enough that a
/// coincidental host inside a longer token is not worth the exception. A
/// shorter word is checked case-insensitively only at token boundaries (the
/// same rule `at_token_boundary` applies to survivors): a short word glued
/// inside a longer run of letters or digits is not itself a survivor.
fn check_vocabulary(anonymizer: &Anonymizer, out_lines: &[String]) -> bool {
    let vocab = anonymizer.vocabulary();
    if vocab.is_empty() {
        return true;
    }
    let mut survivors: BTreeSet<String> = BTreeSet::new();
    for word in vocab {
        let needle = word.to_lowercase();
        let long = needle.chars().count() >= 6;
        let found = out_lines.iter().any(|line| {
            let lower = line.to_lowercase();
            if long {
                lower.contains(&needle)
            } else {
                lower
                    .match_indices(needle.as_str())
                    .any(|(start, m)| at_token_boundary(&lower, start, start + m.len()))
            }
        });
        if found {
            survivors.insert(word.clone());
        }
    }
    let refs: Vec<&String> = survivors.iter().collect();
    report("vocabulary word survived anonymisation", &refs);
    survivors.is_empty()
}

fn report(what: &str, items: &[&String]) {
    for item in items.iter().take(MAX_REPORTED) {
        eprintln!("lessence: {what}: {item}");
    }
    if items.len() > MAX_REPORTED {
        eprintln!(
            "lessence: {} more {what} not shown",
            items.len() - MAX_REPORTED
        );
    }
}

fn read_vocabulary(path: &PathBuf) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(members: usize) -> Config {
        Config {
            distill: Some(members),
            stats: false,
            thread_count: Some(1),
            ..Config::default()
        }
    }

    fn opts() -> Options {
        Options {
            distill: true,
            members: 3,
            anonymize: false,
            words_file: None,
            seed: None,
        }
    }

    /// Selection, end to end: fold, cover, emit.
    fn distilled(lines: &[String], members: usize) -> (Fold, Cover, Vec<String>) {
        let config = cfg(members);
        let source = fold(&config, lines).expect("fold");
        let cover = keep_set(lines, &opts(), &source, &Careful::new());
        let out = cover.lines.iter().map(|&n| lines[n - 1].clone()).collect();
        (source, cover, out)
    }

    /// A member that marks a template slot no earlier member marked is the
    /// only evidence that slot varies, so it is kept however late it sits —
    /// past the distinct-form bound and past `--members`.
    #[test]
    fn a_slot_first_marked_past_the_form_bound_is_still_kept() {
        let stem = "alpha bravo charlie delta echo foxtrot golf hotel";
        let word = |i: usize| {
            format!(
                "k{}{}",
                (b'a' + (i / 26) as u8) as char,
                (b'a' + (i % 26) as u8) as char
            )
        };
        let mut lines = vec![format!("{stem} india kzz")];
        for i in 0..64 {
            lines.push(format!("{stem} india {}", word(i)));
        }
        // The first member to differ in the `india` slot, long past the
        // point where the distinct-form bound stopped collecting.
        lines.push(format!("{stem} juliet kzz"));
        for _ in 0..4 {
            lines.push(format!("{stem} india kzz"));
        }
        assert_eq!(lines.len(), 70);

        let folded = fold(&cfg(2), &lines).expect("fold");
        assert_eq!(folded.groups.len(), 1, "one group");
        assert!(
            folded.groups[0].kept.contains(&66),
            "the second slot's first witness: {:?}",
            folded.groups[0].kept
        );
        assert!(
            folded.groups[0].template.matches(VARIES_MARK).count() >= 2,
            "both slots vary: {}",
            folded.groups[0].template
        );
    }

    /// Proportion is not a property a distillation carries. A group of
    /// twelve thousand and a group of twelve prove the same shapes, and
    /// the distilled file shows them at the same size.
    #[test]
    fn a_huge_group_and_a_small_one_cost_the_same() {
        let sizes = [12_000, 150, 6];
        let kept: Vec<usize> = sizes
            .iter()
            .map(|&n| {
                let lines: Vec<String> =
                    (1..=n).map(|_| "worker finished job".to_string()).collect();
                let folded = fold(&cfg(3), &lines).expect("fold");
                folded.groups[0].kept.len()
            })
            .collect();
        assert_eq!(kept, vec![3, 3, 3], "identical lines: {kept:?}");
    }

    /// `min_collapse` members at least, wherever a fold is claimed: below
    /// three lessence computes no variation at all, so a group shown with
    /// two members proves a template and nothing under it.
    #[test]
    fn a_folded_group_stays_visible_as_a_fold() {
        let mut lines: Vec<String> = (0..10)
            .map(|i| format!("Connection from 10.0.0.{i} accepted"))
            .collect();
        lines.push("a lone unrepeated sentence".to_string());

        let (source, _, out) = distilled(&lines, 3);
        assert!(source.coverage().folded, "the input folds");
        let after = fold(&cfg(3), &out).expect("fold");
        assert!(
            after.coverage().folded,
            "the distillation still folds: {out:?}"
        );
        assert!(
            out.iter().any(|l| l == "a lone unrepeated sentence"),
            "the singleton is not folded away, it is the log: {out:?}"
        );
    }

    /// One event in many literal spellings proves what two of them prove.
    /// The cover keeps two — the busiest, and the one nearest it — not all
    /// twenty.
    #[test]
    fn many_spellings_of_one_structure_cost_two_groups() {
        let spellings = [
            "payment declined for order 7",
            "kitchen light switched off 7",
            "train arrived at platform 7",
            "letter posted to recipient 7",
            "music playback paused after 7",
            "garden hose leaked litres 7",
        ];
        let mut lines: Vec<String> = Vec::new();
        for text in spellings {
            for _ in 0..5 {
                lines.push(text.to_string());
            }
        }
        let (source, cover, _) = distilled(&lines, 3);
        assert_eq!(
            source.groups.len(),
            spellings.len(),
            "one group per spelling in the input: {:?}",
            source
                .groups
                .iter()
                .map(|g| &g.template)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            source
                .groups
                .iter()
                .map(|g| g.token_types.clone())
                .collect::<BTreeSet<_>>()
                .len(),
            1,
            "all of them one structure"
        );
        assert_eq!(
            cover.templates.len(),
            2,
            "one structure, two groups kept: {:?}",
            cover.templates
        );
    }

    /// Every token type the input fires still fires in the distillation,
    /// including one that only ever appears on a late member.
    #[test]
    fn a_token_type_seen_once_late_still_fires() {
        let mut lines: Vec<String> = (0..40)
            .map(|i| format!("worker finished job {i} cleanly"))
            .collect();
        lines.push("worker finished job 99 cleanly at 10.0.0.7".to_string());

        let (source, _, out) = distilled(&lines, 3);
        assert!(
            source.coverage().token_types.contains("IPV4"),
            "the fixture must fire IPV4 for this test to mean anything"
        );
        let after = fold(&cfg(3), &out).expect("fold");
        assert!(
            compare_coverage(
                &source,
                &after,
                &keep_set(&lines, &opts(), &source, &Careful::new())
            ),
            "coverage must hold"
        );
        assert!(after.coverage().token_types.contains("IPV4"));
    }

    /// Nine events and a tenth that differs in one literal word.
    fn over_folded() -> Vec<String> {
        let mut lines: Vec<String> = (0..9)
            .map(|i| format!("worker {i} finished cleanly"))
            .collect();
        lines.push("worker 9 finished dirty".to_string());
        lines
    }

    /// The contract is coverage, not proportion — but a distillation that
    /// loses a token type, a structure or the fold itself must still fail.
    #[test]
    fn the_coverage_check_fires_when_a_property_is_dropped() {
        let lines = over_folded();
        let config = cfg(3);
        let folded = fold(&config, &lines).expect("fold");
        assert!(
            folded
                .groups
                .iter()
                .any(|g| g.template.contains(VARIES_MARK)),
            "the fixture must over-fold for this test to mean anything"
        );

        // A single line proves no fold and no variation.
        let naive: Vec<String> = lines[..1].to_vec();
        let cover = keep_set(&lines, &opts(), &folded, &Careful::new());
        assert!(
            !compare_coverage(&folded, &fold(&config, &naive).expect("fold"), &cover),
            "a distillation that no longer folds must not pass"
        );

        // What the cover actually keeps does pass.
        let honest: Vec<String> = cover.lines.iter().map(|&n| lines[n - 1].clone()).collect();
        assert!(
            compare_coverage(&folded, &fold(&config, &honest).expect("fold"), &cover),
            "the covered members must prove everything the input proved"
        );
    }

    /// Two events that merge only because the log between them is gone is
    /// the one thing a distilled corpus may never demonstrate: every later
    /// gate reads it as correct. Merging two spellings of the *same* event
    /// is not that — the literal words decide which is which.
    #[test]
    fn a_merge_across_a_literal_word_is_an_over_fold_and_one_across_a_value_is_not() {
        let cover = Cover {
            lines: BTreeSet::new(),
            templates: ["<TIMESTAMP> fs (<VARIES> unmounting volume <UUID>".to_string()]
                .into_iter()
                .collect(),
        };
        let surviving = |t: &str| Fold {
            groups: vec![DistillGroup {
                template: t.to_string(),
                token_types: Vec::new(),
                all_types: Vec::new(),
                anchor: 0,
                avg_bytes: 0,
                kept: Vec::new(),
                capping_extra: Vec::new(),
                count: 1,
                distinct_forms: 1,
            }],
        };
        assert_eq!(
            merged_templates(
                &cover,
                &surviving("<TIMESTAMP> fs (<VARIES> mounted volume <UUID>")
            )
            .len(),
            1,
            "unmounting swallowed by mounted is an over-fold"
        );
        assert!(
            merged_templates(
                &cover,
                &surviving("<TIMESTAMP> fs (<NAME> unmounting volume <VARIES>")
            )
            .is_empty(),
            "the same words with a wider placeholder is not"
        );
    }

    #[test]
    fn literal_words_ignore_every_placeholder() {
        assert_eq!(
            literal_words("<TIMESTAMP> host sshd[<PID>]: Failed for <NAME> from <IPV4>"),
            vec!["host", "sshd[", "]:", "Failed", "for", "from"]
        );
        assert_eq!(
            literal_words("a <UNCLOSED b c"),
            vec!["a"],
            "an unterminated placeholder ends the scan rather than panicking"
        );
    }

    #[test]
    fn the_survivor_check_fires_on_a_value_at_a_token_boundary() {
        let mut values = HashSet::new();
        values.insert("host7.example.com".to_string());
        assert!(
            !check_survivors(&values, &["url=https://host7.example.com/x".to_string()]),
            "a value inside a URL is still that value"
        );
        assert!(
            check_survivors(&values, &["host7.example.community".to_string()]),
            "a longer token that merely starts the same is not a survivor"
        );
    }

    #[test]
    fn a_short_vocabulary_word_inside_a_literal_is_not_a_survivor() {
        let a = Anonymizer::new(1, vec!["g8".to_string()]);
        assert!(
            check_vocabulary(
                &a,
                &["cfg80211 driver loaded".to_string(), "a8r8g8b8".to_string()]
            ),
            "a short vocabulary word glued inside a longer token is not a survivor"
        );
        assert!(
            !check_vocabulary(&a, &["seen on g8 today".to_string()]),
            "the same word as its own token is a survivor"
        );
    }

    #[test]
    fn a_long_vocabulary_word_glued_to_letters_is_a_survivor() {
        let a = Anonymizer::new(1, vec!["zorquid".to_string()]);
        assert!(
            !check_vocabulary(&a, &["node9zorquidfoo online".to_string()]),
            "a 6+ character vocabulary word is checked as a substring anywhere"
        );
    }
}
