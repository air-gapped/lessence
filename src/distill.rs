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

use crate::anonymize::{Anonymizer, at_token_boundary, word_shape};
use crate::config::Config;
use crate::folder::PatternFolder;
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
    let selected = fold(config, source)?.kept;
    let kept = keep_set(source, opts, &selected);
    let out_lines: Vec<String> = kept.iter().map(|&n| source[n - 1].clone()).collect();

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
    ok &= check_templates(config, source, &out_lines)?;
    ok &= check_word_shapes(source, &out_lines);
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
        for tokens in &batch {
            anonymizer.learn(tokens);
        }
    }
    anonymizer.seal();
    Ok(lines.iter().map(|line| anonymizer.rewrite(line)).collect())
}

/// What one fold of an input yields: the line numbers a distillation keeps
/// and the template of every group that formed.
struct Fold {
    kept: Vec<usize>,
    templates: Vec<String>,
}

fn fold(config: &Config, lines: &[String]) -> Result<Fold> {
    let mut folder = PatternFolder::new(config.clone());
    for (i, line) in lines.iter().enumerate() {
        folder.process_line_at(line, None, i + 1)?;
    }
    folder.finish()?;
    let (kept, templates) = folder.take_distilled();
    Ok(Fold { kept, templates })
}

/// The input line numbers the output carries, in order: what the folder
/// selected, plus the earliest line of every word shape those lines do not
/// already show. `--anonymize` without `--distill` keeps everything.
fn keep_set(lines: &[String], opts: &Options, selected: &[usize]) -> BTreeSet<usize> {
    if !opts.distill {
        return (1..=lines.len()).collect();
    }
    let mut kept: BTreeSet<usize> = selected.iter().copied().collect();

    // Word-shape coverage. The detectors cannot see a fold across a literal
    // word — that is the case where they found nothing to see — so the shape
    // is computed without them, and any shape the selection missed brings
    // its earliest line along.
    let covered: HashSet<String> = kept.iter().map(|&n| word_shape(&lines[n - 1])).collect();
    let mut earliest: BTreeMap<String, usize> = BTreeMap::new();
    for (i, line) in lines.iter().enumerate() {
        earliest.entry(word_shape(line)).or_insert(i + 1);
    }
    for (shape, line_no) in &earliest {
        if !covered.contains(shape) {
            kept.insert(*line_no);
        }
    }
    kept
}

/// Contract 1: folding the output yields the same templates as folding the
/// input. Both sides are read after anonymisation, so an invented value is
/// not mistaken for a lost shape.
fn check_templates(config: &Config, source: &[String], out_lines: &[String]) -> Result<bool> {
    let want: BTreeSet<String> = fold(config, source)?.templates.into_iter().collect();
    let have: BTreeSet<String> = fold(config, out_lines)?.templates.into_iter().collect();

    let lost: Vec<&String> = want.difference(&have).collect();
    let gained: Vec<&String> = have.difference(&want).collect();
    report("template missing from the distilled output", &lost);
    report("template only in the distilled output", &gained);
    Ok(lost.is_empty() && gained.is_empty())
}

/// Contract 1b: every distinct word shape of the input appears in the
/// output, recomputed on the final text.
fn check_word_shapes(source: &[String], out_lines: &[String]) -> bool {
    let have: HashSet<String> = out_lines.iter().map(|l| word_shape(l)).collect();
    let mut missing: BTreeSet<String> = BTreeSet::new();
    for line in source {
        let shape = word_shape(line);
        if !have.contains(&shape) {
            missing.insert(shape);
        }
    }
    let refs: Vec<&String> = missing.iter().collect();
    report("word shape missing from the distilled output", &refs);
    missing.is_empty()
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

    #[test]
    fn a_folded_group_contributes_members_and_a_singleton_stays() {
        let mut lines: Vec<String> = (0..10)
            .map(|i| format!("Connection from 10.0.0.{i} accepted"))
            .collect();
        lines.push("a lone unrepeated sentence".to_string());
        let folded = fold(&cfg(3), &lines).expect("fold");
        assert!(
            folded.kept.len() >= 4,
            "three members plus the singleton: {:?}",
            folded.kept
        );
        assert!(
            folded.kept.contains(&11),
            "the singleton is kept: {:?}",
            folded.kept
        );
    }

    #[test]
    fn a_large_group_keeps_a_log_scaled_sample_in_order() {
        // Every line identical, so the group has one normalized form and
        // neither the template-building step nor the distinct-form step
        // (capped at ROLLUP_DISTINCT_CAP) picks up any extra members: with
        // `--members` 3, the floor step contributes indices {0,1,2} before
        // the log-scaled sample is unioned in.
        for (n, expected) in [(12_000, 18), (150, 12), (3, 3)] {
            let lines: Vec<String> = (1..=n).map(|_| "worker finished job".to_string()).collect();
            let folded = fold(&cfg(3), &lines).expect("fold");
            let mut kept = folded.kept.clone();
            kept.sort_unstable();
            assert_eq!(kept.len(), expected, "n={n}: {kept:?}");
            assert_eq!(kept[0], 1, "n={n}: first line kept: {kept:?}");
            assert_eq!(*kept.last().unwrap(), n, "n={n}: last line kept: {kept:?}");
            assert!(
                kept.windows(2).all(|w| w[0] < w[1]),
                "n={n}: kept must be strictly ascending: {kept:?}"
            );
        }
    }

    #[test]
    fn word_shape_coverage_adds_a_line_the_members_missed() {
        // Nine identical events and one that differs in a literal word. The
        // odd line is last, so "the first three members" would drop it.
        let mut lines: Vec<String> = (0..9)
            .map(|i| format!("worker {i} finished cleanly"))
            .collect();
        lines.push("worker 9 finished dirty".to_string());
        let config = cfg(3);
        let folded = fold(&config, &lines).expect("fold");
        let opts = Options {
            distill: true,
            members: 3,
            anonymize: false,
            words_file: None,
            seed: None,
        };
        let kept = keep_set(&lines, &opts, &folded.kept);
        let shapes: HashSet<String> = kept.iter().map(|&n| word_shape(&lines[n - 1])).collect();
        assert!(
            shapes.contains("worker # finished dirty"),
            "the odd word shape must survive: {shapes:?}"
        );
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

    /// Nine events and a tenth that differs in one literal word.
    fn over_folded() -> Vec<String> {
        let mut lines: Vec<String> = (0..9)
            .map(|i| format!("worker {i} finished cleanly"))
            .collect();
        lines.push("worker 9 finished dirty".to_string());
        lines
    }

    #[test]
    fn the_template_check_fires_when_a_variant_is_dropped() {
        let lines = over_folded();
        let config = cfg(3);
        let folded = fold(&config, &lines).expect("fold");
        assert!(
            folded.templates.iter().any(|t| t.contains("<VARIES>")),
            "the fixture must over-fold for this test to mean anything: {:?}",
            folded.templates
        );

        // "The first three members" — the selection this feature exists to
        // replace — loses the tenth line, and the check must say so.
        let naive: Vec<String> = lines[..3].to_vec();
        assert!(
            !check_templates(&config, &lines, &naive).expect("check"),
            "a distillation missing the rare variant must not pass"
        );

        // What the selector actually keeps does pass.
        let kept = keep_set(&lines, &opts(), &folded.kept);
        let honest: Vec<String> = kept.iter().map(|&n| lines[n - 1].clone()).collect();
        assert!(
            check_templates(&config, &lines, &honest).expect("check"),
            "the selected members must reproduce every template"
        );
    }

    #[test]
    fn the_word_shape_check_fires_when_a_shape_is_dropped() {
        let lines = over_folded();
        let naive: Vec<String> = lines[..3].to_vec();
        assert!(
            !check_word_shapes(&lines, &naive),
            "a distillation missing a word shape must not pass"
        );

        let folded = fold(&cfg(3), &lines).expect("fold");
        let kept = keep_set(&lines, &opts(), &folded.kept);
        let honest: Vec<String> = kept.iter().map(|&n| lines[n - 1].clone()).collect();
        assert!(check_word_shapes(&lines, &honest));
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

    #[test]
    fn a_line_differing_only_in_numbers_is_one_shape() {
        let a = "Aug 29 08:40:15 host1 sshd[123]: Failed password for root from 10.0.0.5";
        let b = "Aug 30 09:41:16 host1 sshd[456]: Failed password for root from 10.0.0.9";
        let c = "Aug 29 08:40:15 host1 sshd[123]: Accepted password for root from 10.0.0.5";
        assert_eq!(word_shape(a), word_shape(b));
        assert_ne!(word_shape(a), word_shape(c));
        assert_eq!(
            word_shape(a),
            "Aug # #:#:# host# sshd # : Failed password for root from #.#.#.#"
        );
    }
}
