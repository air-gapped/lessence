use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::anonymize::{Anonymizer, SealedAnonymizer, at_token_boundary};
use crate::config::{Config, DEFAULT_MIN_COLLAPSE};
use crate::folder::{
    DISTILL_CHEAP_LINE_BYTES, DistillGroup, PatternFolder, ROLLUP_DISTINCT_CAP, VARIES_MARK,
};
use crate::ingest::{Event, IngestReport, Ingestor, InputReader};
use crate::normalize::Normalizer;
use crate::patterns::Token;

const MAX_FAILURES_PRINTED_PER_KIND: usize = 20;

const SUBSTRING_CHECK_MIN_LEN: usize = 6;

pub enum Selection {
    KeepEveryLine,
    Distill,
}

pub enum Seed {
    Fixed(u64),
    Clock,
}

pub struct Anonymization {
    pub words_file: Option<PathBuf>,
    pub seed: Seed,
}

pub struct Options {
    pub selection: Selection,
    pub anonymization: Option<Anonymization>,
}

impl Options {
    pub fn from_flags(
        distill: bool,
        anonymize: bool,
        words_file: Option<PathBuf>,
        seed: Option<u64>,
    ) -> Self {
        let words_ask_for_anonymization = words_file.is_some();
        Self {
            selection: if distill {
                Selection::Distill
            } else {
                Selection::KeepEveryLine
            },
            anonymization: (anonymize || words_ask_for_anonymization).then(|| Anonymization {
                words_file,
                seed: seed.map_or(Seed::Clock, Seed::Fixed),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractOutcome {
    Held,
    Broken,
    FailPatternMatched,
    ReaderClosedThePipe,
}

impl ContractOutcome {
    pub fn exit_code(self) -> i32 {
        match self {
            ContractOutcome::Held | ContractOutcome::ReaderClosedThePipe => 0,
            ContractOutcome::Broken | ContractOutcome::FailPatternMatched => 1,
        }
    }
}

pub fn distill_and_self_check(
    config: &Config,
    ingestor: &Ingestor,
    readers: Vec<InputReader>,
    opts: &Options,
) -> Result<ContractOutcome> {
    let mut buffered_input: Vec<String> = Vec::new();
    let report: IngestReport = ingestor.run(readers, |event| {
        if let Event::Line { text, .. } = event {
            buffered_input.push(text.to_string());
        }
        Ok(())
    })?;

    let normalizer = Normalizer::new(config.clone());
    let anonymized = match &opts.anonymization {
        Some(anonymization) => {
            let words = match &anonymization.words_file {
                Some(path) => read_vocabulary(path)?,
                None => Vec::new(),
            };
            let seed = match anonymization.seed {
                Seed::Fixed(seed) => seed,
                Seed::Clock => Anonymizer::clock_seed(),
            };
            let anonymizer = Anonymizer::new(seed, words);
            Some(anonymize_all(&buffered_input, anonymizer, &normalizer))
        }
        None => None,
    };
    let anonymized_source: &[String] = anonymized
        .as_ref()
        .map_or(&buffered_input, |(lines, _)| lines);

    let source_fold = fold(config, anonymized_source)?;
    let (kept, out_lines, output_fold) =
        select_until_no_merge(config, anonymized_source, opts, &source_fold)?;

    let mut ok = contract_coverage_preserved(&source_fold, &output_fold, &kept);
    let mut anonymity_held = true;
    if let Some((_, a)) = anonymized.as_ref() {
        let mut diag = io::stderr().lock();
        anonymity_held &=
            contract_no_replaced_value_survives(&a.replaced_originals(), &out_lines, &mut diag);
        anonymity_held &= contract_vocabulary_gone(a, &out_lines, &mut diag);
    }
    ok &= anonymity_held;

    let mut stdout = io::stdout().lock();
    for line in publishable(&out_lines, anonymity_held) {
        match writeln!(stdout, "{line}") {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                return Ok(ContractOutcome::ReaderClosedThePipe);
            }
            Err(e) => return Err(e.into()),
        }
    }
    stdout.flush()?;

    Ok(if !ok {
        ContractOutcome::Broken
    } else if report.fail_pattern_matched {
        ContractOutcome::FailPatternMatched
    } else {
        ContractOutcome::Held
    })
}

fn select_until_no_merge(
    config: &Config,
    source: &[String],
    opts: &Options,
    source_fold: &Fold,
) -> Result<(Cover, Vec<String>, Fold)> {
    let mut partner_choices = PartnerChoices::new();
    loop {
        let kept = keep_set(source, opts, source_fold, &partner_choices);
        let out_lines: Vec<String> = kept.lines.iter().map(|&n| source[n - 1].clone()).collect();
        let output_fold = fold(config, &out_lines)?;
        let blame: Vec<Vec<&'static str>> = over_folded_kept_templates(&kept, &output_fold)
            .iter()
            .filter_map(|t| source_fold.groups.iter().find(|g| &&g.template == t))
            .map(|g| g.token_types.clone())
            .filter(|k| partner_choices.get(k).copied().unwrap_or_default() != PartnerChoice::Alone)
            .collect();
        if blame.is_empty() {
            return Ok((kept, out_lines, output_fold));
        }
        for key in blame {
            let choice = partner_choices.entry(key).or_default();
            *choice = choice.retreat();
        }
    }
}

fn anonymize_all(
    lines: &[String],
    mut anonymizer: Anonymizer,
    normalizer: &Normalizer,
) -> (Vec<String>, SealedAnonymizer) {
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
            anonymizer.learn_line(tokens, line);
        }
    }
    let mut sealed = anonymizer.seal();
    let rewritten = lines.iter().map(|line| sealed.rewrite(line)).collect();
    (rewritten, sealed)
}

struct Fold {
    groups: Vec<DistillGroup>,
}

impl Fold {
    fn provable_properties(&self) -> ProvableProperties {
        let mut c = ProvableProperties::default();
        for g in &self.groups {
            c.structures.insert(Structure(g.token_types.clone()));
            c.token_types
                .extend(g.all_types.iter().copied().map(TokenType));
            c.some_group_reaches_min_collapse |= g.kept.len() >= DEFAULT_MIN_COLLAPSE;
            c.has_varies_slot |= g.template.contains(VARIES_MARK);
            c.some_rollup_capped |= g.distinct_forms > ROLLUP_DISTINCT_CAP;
            c.some_group_offers_capping_extra |= !g.capping_extra.is_empty();
        }
        c
    }

    fn templates(&self) -> BTreeSet<&str> {
        self.groups.iter().map(|g| g.template.as_str()).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Structure(Vec<&'static str>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TokenType(&'static str);

#[derive(Default)]
struct ProvableProperties {
    structures: BTreeSet<Structure>,
    token_types: BTreeSet<TokenType>,
    some_group_reaches_min_collapse: bool,
    has_varies_slot: bool,
    some_rollup_capped: bool,
    some_group_offers_capping_extra: bool,
}

impl ProvableProperties {
    fn requires_capped_rollup(&self) -> bool {
        self.some_rollup_capped && self.some_group_offers_capping_extra
    }
}

#[derive(Default)]
struct Cover {
    lines: BTreeSet<usize>,
    must_stay_distinct: BTreeSet<String>,
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

fn keep_set(
    lines: &[String],
    opts: &Options,
    source: &Fold,
    partner_choices: &PartnerChoices,
) -> Cover {
    match opts.selection {
        Selection::KeepEveryLine => keep_all(lines.len()),
        Selection::Distill => covering_subset(
            &source.groups,
            partner_choices,
            DISTILL_ANCHOR_PROOF_BUDGET_BYTES,
        ),
    }
}

fn keep_all(line_count: usize) -> Cover {
    Cover {
        lines: (1..=line_count).collect(),
        must_stay_distinct: BTreeSet::new(),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum PartnerChoice {
    #[default]
    Nearest,
    Farthest,
    Alone,
}

impl PartnerChoice {
    fn retreat(self) -> Self {
        match self {
            PartnerChoice::Nearest => PartnerChoice::Farthest,
            PartnerChoice::Farthest | PartnerChoice::Alone => PartnerChoice::Alone,
        }
    }
}

type PartnerChoices = BTreeMap<Vec<&'static str>, PartnerChoice>;

fn common_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

fn unordered_words(template: &str) -> BTreeSet<&str> {
    template.split_whitespace().collect()
}

fn jaccard_permille(a: &BTreeSet<&str>, b: &BTreeSet<&str>) -> usize {
    let union = a.union(b).count();
    if union == 0 {
        return 1000;
    }
    a.intersection(b).count() * 1000 / union
}

fn busiest_earliest(groups: &[DistillGroup], members: &[usize]) -> usize {
    *members
        .iter()
        .max_by_key(|&&i| (groups[i].count, std::cmp::Reverse(i)))
        .expect("a bucket is never empty")
}

fn literal_split_partner(
    groups: &[DistillGroup],
    members: &[usize],
    primary: usize,
    choice: PartnerChoice,
) -> Option<usize> {
    members
        .iter()
        .filter(|&&i| i != primary && groups[i].anchor == groups[primary].anchor)
        .max_by_key(|&&i| {
            let shared = common_prefix_len(&groups[i].template, &groups[primary].template);
            let rank = if choice == PartnerChoice::Nearest {
                shared
            } else {
                usize::MAX - shared
            };
            (rank, std::cmp::Reverse(i))
        })
        .copied()
}

fn farthest_by_prefix(groups: &[DistillGroup], members: &[usize], primary: usize) -> Option<usize> {
    members
        .iter()
        .filter(|&&i| i != primary)
        .min_by_key(|&&i| {
            (
                common_prefix_len(&groups[i].template, &groups[primary].template),
                i,
            )
        })
        .copied()
}

fn farthest_by_words(groups: &[DistillGroup], members: &[usize], primary: usize) -> Option<usize> {
    let primary_words = unordered_words(&groups[primary].template);
    members
        .iter()
        .filter(|&&i| i != primary)
        .min_by_key(|&&i| {
            (
                jaccard_permille(&unordered_words(&groups[i].template), &primary_words),
                i,
            )
        })
        .copied()
}

/// Bytes the further anchor values of long-line buckets may add to a
/// distillation, for the whole input. The first anchor value of every bucket
/// is outside it.
const DISTILL_ANCHOR_PROOF_BUDGET_BYTES: usize = 1 << 20;

fn anchor_values_busiest_then_first_seen(
    groups: &[DistillGroup],
    members: &[usize],
    primary: usize,
) -> Vec<usize> {
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
    let mut values: Vec<usize> = by_anchor.into_values().collect();
    values.sort_unstable();
    if let Some(busiest_at) = (0..values.len())
        .max_by_key(|&at| (groups[values[at]].count, std::cmp::Reverse(values[at])))
    {
        let busiest = values.remove(busiest_at);
        values.insert(0, busiest);
    }
    values
}

/// Different literal words are different events: every set of literal words
/// in a bucket keeps its busiest group, in first-seen order. Groups whose
/// templates differ only inside placeholders share one set.
fn one_group_per_literal_word_set(
    groups: &[DistillGroup],
    members: &[usize],
    primary: usize,
) -> Vec<usize> {
    let mut by_words: BTreeMap<Vec<&str>, usize> = BTreeMap::new();
    by_words.insert(literal_words(&groups[primary].template), primary);
    for &i in members {
        by_words
            .entry(literal_words(&groups[i].template))
            .and_modify(|best| {
                if (groups[i].count, std::cmp::Reverse(i))
                    > (groups[*best].count, std::cmp::Reverse(*best))
                {
                    *best = i;
                }
            })
            .or_insert(i);
    }
    let mut kept: Vec<usize> = by_words.into_values().filter(|&i| i != primary).collect();
    kept.sort_unstable();
    kept
}

fn lines_are_cheap_to_repeat(avg_line_bytes: usize) -> bool {
    avg_line_bytes <= DISTILL_CHEAP_LINE_BYTES
}

fn bytes_kept_for(group: &DistillGroup) -> usize {
    group.kept.len().saturating_mul(group.avg_bytes)
}

fn further_anchor_values_within_budget(
    groups: &[DistillGroup],
    queue_per_bucket: &[Vec<usize>],
    already_chosen: &BTreeSet<usize>,
    budget_bytes: usize,
) -> Vec<usize> {
    let mut taken: Vec<usize> = Vec::new();
    let mut spent: usize = 0;
    let rounds = queue_per_bucket.iter().map(Vec::len).max().unwrap_or(0);
    for round in 0..rounds {
        for &group in queue_per_bucket.iter().filter_map(|queue| queue.get(round)) {
            let cost = if already_chosen.contains(&group) {
                0
            } else {
                bytes_kept_for(&groups[group])
            };
            match spent
                .checked_add(cost)
                .filter(|&total| total <= budget_bytes)
            {
                Some(total) => {
                    spent = total;
                    taken.push(group);
                }
                None => return taken,
            }
        }
    }
    taken
}

fn covering_subset(
    groups: &[DistillGroup],
    partner_choices: &PartnerChoices,
    anchor_proof_budget_bytes: usize,
) -> Cover {
    let mut buckets: BTreeMap<&[&'static str], Vec<usize>> = BTreeMap::new();
    for (i, g) in groups.iter().enumerate() {
        buckets.entry(&g.token_types).or_default().push(i);
    }

    let mut chosen: BTreeSet<usize> = BTreeSet::new();
    let mut further_anchor_values: Vec<Vec<usize>> = Vec::new();
    let mut further_word_sets: Vec<Vec<usize>> = Vec::new();
    for (key, members) in &buckets {
        let primary = busiest_earliest(groups, members);
        chosen.insert(primary);

        let choice = partner_choices
            .get(key.to_vec().as_slice())
            .copied()
            .unwrap_or_default();
        if choice != PartnerChoice::Alone {
            chosen.extend(literal_split_partner(groups, members, primary, choice));
            chosen.extend(farthest_by_prefix(groups, members, primary));
            chosen.extend(farthest_by_words(groups, members, primary));
        }
        let anchor_values = anchor_values_busiest_then_first_seen(groups, members, primary);
        let word_sets = one_group_per_literal_word_set(groups, members, primary);
        if lines_are_cheap_to_repeat(groups[primary].avg_bytes) {
            chosen.extend(anchor_values);
            chosen.extend(word_sets);
        } else if let Some((&free, further)) = anchor_values.split_first() {
            chosen.insert(free);
            further_anchor_values.push(further.to_vec());
            further_word_sets.push(word_sets);
        } else {
            further_word_sets.push(word_sets);
        }
    }
    let within_budget = further_anchor_values_within_budget(
        groups,
        &further_anchor_values,
        &chosen,
        anchor_proof_budget_bytes,
    );
    let spent: usize = within_budget
        .iter()
        .filter(|g| !chosen.contains(g))
        .map(|&g| bytes_kept_for(&groups[g]))
        .sum();
    chosen.extend(within_budget);
    let word_sets_within_budget = further_anchor_values_within_budget(
        groups,
        &further_word_sets,
        &chosen,
        anchor_proof_budget_bytes.saturating_sub(spent),
    );
    chosen.extend(word_sets_within_budget);

    top_up_missing_properties(groups, &mut chosen);

    let mut out = Cover::default();
    for &i in &chosen {
        out.lines.extend(groups[i].kept.iter().copied());
        out.must_stay_distinct.insert(groups[i].template.clone());
    }
    take_capped_once(groups, &mut out);
    out
}

fn top_up_missing_properties(groups: &[DistillGroup], chosen: &mut BTreeSet<usize>) {
    let has_varies = |g: &DistillGroup| g.template.contains(VARIES_MARK);
    let reaches_min_collapse = |g: &DistillGroup| g.kept.len() >= DEFAULT_MIN_COLLAPSE;
    for property in [
        &has_varies as &dyn Fn(&DistillGroup) -> bool,
        &reaches_min_collapse,
    ] {
        if !chosen.iter().any(|&i| property(&groups[i]))
            && let Some(i) = fewest_lines_satisfying(groups, property)
        {
            chosen.insert(i);
        }
    }
}

fn take_capped_once(groups: &[DistillGroup], out: &mut Cover) {
    if let Some(i) = fewest_lines_satisfying(groups, |g| !g.capping_extra.is_empty()) {
        out.lines.extend(groups[i].kept.iter().copied());
        out.lines.extend(groups[i].capping_extra.iter().copied());
        out.must_stay_distinct.insert(groups[i].template.clone());
    }
}

fn fewest_lines_satisfying(
    groups: &[DistillGroup],
    want: impl Fn(&DistillGroup) -> bool,
) -> Option<usize> {
    groups
        .iter()
        .enumerate()
        .filter(|(_, g)| want(g))
        .min_by_key(|(i, g)| (g.kept.len() + g.capping_extra.len(), *i))
        .map(|(i, _)| i)
}

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

fn over_folded_kept_templates<'a>(cover: &'a Cover, output: &Fold) -> Vec<&'a String> {
    let have = output.templates();
    let literal_word_lists_in_output: BTreeSet<Vec<&str>> =
        have.iter().map(|t| literal_words(t)).collect();
    cover
        .must_stay_distinct
        .iter()
        .filter(|t| {
            let lost_its_own_line = !have.contains(t.as_str());
            let merged_across_a_literal_word =
                !literal_word_lists_in_output.contains(&literal_words(t));
            lost_its_own_line && merged_across_a_literal_word
        })
        .collect()
}

fn contract_coverage_preserved(source: &Fold, output: &Fold, cover: &Cover) -> bool {
    let want = source.provable_properties();
    let have = output.provable_properties();

    let missing = |what: &str, items: Vec<String>| -> bool {
        let refs: Vec<&String> = items.iter().collect();
        report(what, &refs);
        items.is_empty()
    };

    let mut ok = missing(
        "token-type structure missing from the distilled output",
        want.structures
            .difference(&have.structures)
            .map(|s| s.0.join(","))
            .collect(),
    );
    ok &= missing(
        "token type missing from the distilled output",
        want.token_types
            .difference(&have.token_types)
            .map(|t| t.0.to_string())
            .collect(),
    );
    ok &= missing(
        "two groups the input kept apart merged in the distilled output",
        over_folded_kept_templates(cover, output)
            .into_iter()
            .cloned()
            .collect(),
    );
    for (name, wanted, got) in [
        (
            "a folded group",
            want.some_group_reaches_min_collapse,
            have.some_group_reaches_min_collapse,
        ),
        (
            "a <VARIES> template",
            want.has_varies_slot,
            have.has_varies_slot,
        ),
        (
            "a capped rollup",
            want.requires_capped_rollup(),
            have.some_rollup_capped,
        ),
    ] {
        if wanted && !got {
            eprintln!("lessence: the distilled output no longer shows {name}");
            ok = false;
        }
    }
    ok
}

/// The lines written to stdout: all of them when the anonymisation checks
/// held, none when either found an original value in them.
fn publishable(out_lines: &[String], anonymity_held: bool) -> &[String] {
    if anonymity_held { out_lines } else { &[] }
}

fn contract_no_replaced_value_survives(
    values: &HashSet<String>,
    out_lines: &[String],
    diag: &mut dyn Write,
) -> bool {
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
    report_count(
        diag,
        "original value survived anonymisation",
        survivors.len(),
    );
    survivors.is_empty()
}

fn contract_vocabulary_gone(
    anonymizer: &SealedAnonymizer,
    out_lines: &[String],
    diag: &mut dyn Write,
) -> bool {
    let vocab = anonymizer.vocabulary();
    if vocab.is_empty() {
        return true;
    }
    let mut survivors: BTreeSet<String> = BTreeSet::new();
    let lowered: Vec<String> = out_lines.iter().map(|line| line.to_lowercase()).collect();
    for word in vocab {
        let needle = word.to_lowercase();
        let checked_as_substring = needle.chars().count() >= SUBSTRING_CHECK_MIN_LEN;
        let found = lowered.iter().any(|lower| {
            if checked_as_substring {
                lower.contains(&needle)
            } else {
                lower
                    .match_indices(needle.as_str())
                    .any(|(start, m)| at_token_boundary(lower, start, start + m.len()))
            }
        });
        if found {
            survivors.insert(word.clone());
        }
    }
    report_count(
        diag,
        "vocabulary word survived anonymisation",
        survivors.len(),
    );
    survivors.is_empty()
}

/// States how many values a check found, never the values themselves.
fn report_count(diag: &mut dyn Write, what: &str, count: usize) {
    if count > 0 {
        let _ = writeln!(diag, "lessence: {count} {what}; no output written");
    }
}

fn report(what: &str, items: &[&String]) {
    for item in items.iter().take(MAX_FAILURES_PRINTED_PER_KIND) {
        eprintln!("lessence: {what}: {item}");
    }
    if items.len() > MAX_FAILURES_PRINTED_PER_KIND {
        eprintln!(
            "lessence: {} more {what} not shown",
            items.len() - MAX_FAILURES_PRINTED_PER_KIND
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
            group_sink: crate::config::GroupSink::RecordDistillMembers {
                members_per_group: members,
            },
            stats: false,
            thread_count: Some(1),
            ..Config::default()
        }
    }

    fn opts() -> Options {
        Options {
            selection: Selection::Distill,
            anonymization: None,
        }
    }

    fn fold_cover_and_emit(lines: &[String], members: usize) -> (Fold, Cover, Vec<String>) {
        let config = cfg(members);
        let source = fold(&config, lines).expect("fold");
        let cover = keep_set(lines, &opts(), &source, &PartnerChoices::new());
        let out = cover.lines.iter().map(|&n| lines[n - 1].clone()).collect();
        (source, cover, out)
    }

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
        lines.push(format!("{stem} juliet kzz"));
        for _ in 0..4 {
            lines.push(format!("{stem} india kzz"));
        }
        assert_eq!(lines.len(), 70);

        let folded = fold(&cfg(2), &lines).expect("fold");
        assert_eq!(folded.groups.len(), 1, "one group");
        assert!(
            folded.groups[0].kept.contains(&66),
            "line 66 is the only evidence the india slot varies, and it comes after the distinct-form bound and after --members: {:?}",
            folded.groups[0].kept
        );
        assert!(
            folded.groups[0].template.matches(VARIES_MARK).count() >= 2,
            "both slots vary: {}",
            folded.groups[0].template
        );
    }

    #[test]
    fn a_huge_group_and_a_small_one_cost_the_same_because_proportion_is_not_carried() {
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
        assert_eq!(
            kept,
            vec![3, 3, 3],
            "12,000 and 12 identical members prove the same shapes: {kept:?}"
        );
    }

    #[test]
    fn a_folded_group_keeps_min_collapse_members() {
        let mut lines: Vec<String> = (0..10)
            .map(|i| format!("Connection from 10.0.0.{i} accepted"))
            .collect();
        lines.push("a lone unrepeated sentence".to_string());

        let (source, _, out) = fold_cover_and_emit(&lines, 3);
        assert!(
            source.provable_properties().some_group_reaches_min_collapse,
            "the input folds"
        );
        let after = fold(&cfg(3), &out).expect("fold");
        assert!(
            after.provable_properties().some_group_reaches_min_collapse,
            "below DEFAULT_MIN_COLLAPSE members no variation is computed, so the distillation must keep that many: {out:?}"
        );
        assert!(
            out.iter().any(|l| l == "a lone unrepeated sentence"),
            "the singleton is not folded away, it is the log: {out:?}"
        );
    }

    #[test]
    fn one_structure_with_different_literal_words_keeps_every_event() {
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
        let (source, cover, _) = fold_cover_and_emit(&lines, 3);
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
            cover.must_stay_distinct.len(),
            spellings.len(),
            "different literal words are different events: each keeps a group: {:?}",
            cover.must_stay_distinct
        );
    }

    #[test]
    fn a_token_type_seen_once_late_still_fires() {
        let mut lines: Vec<String> = (0..40)
            .map(|i| format!("worker finished job {i} cleanly"))
            .collect();
        lines.push("worker finished job 99 cleanly at 10.0.0.7".to_string());

        let (source, _, out) = fold_cover_and_emit(&lines, 3);
        assert!(
            source
                .provable_properties()
                .token_types
                .contains(&TokenType("IPV4")),
            "the fixture must fire IPV4, on its late member only, for this test to mean anything"
        );
        let after = fold(&cfg(3), &out).expect("fold");
        assert!(
            contract_coverage_preserved(
                &source,
                &after,
                &keep_set(&lines, &opts(), &source, &PartnerChoices::new())
            ),
            "coverage must hold"
        );
        assert!(
            after
                .provable_properties()
                .token_types
                .contains(&TokenType("IPV4"))
        );
    }

    fn nine_events_and_one_differing_in_a_literal_word() -> Vec<String> {
        let mut lines: Vec<String> = (0..9)
            .map(|i| format!("worker {i} finished cleanly"))
            .collect();
        lines.push("worker 9 finished dirty".to_string());
        lines
    }

    #[test]
    fn the_coverage_check_fires_when_a_property_is_dropped() {
        let lines = nine_events_and_one_differing_in_a_literal_word();
        let config = cfg(3);
        let folded = fold(&config, &lines).expect("fold");
        assert!(
            folded
                .groups
                .iter()
                .any(|g| g.template.contains(VARIES_MARK)),
            "the fixture must over-fold for this test to mean anything"
        );

        let naive: Vec<String> = lines[..1].to_vec();
        let cover = keep_set(&lines, &opts(), &folded, &PartnerChoices::new());
        assert!(
            !contract_coverage_preserved(&folded, &fold(&config, &naive).expect("fold"), &cover),
            "a single line proves no fold and no variation, so it must not pass"
        );

        let honest: Vec<String> = cover.lines.iter().map(|&n| lines[n - 1].clone()).collect();
        assert!(
            contract_coverage_preserved(&folded, &fold(&config, &honest).expect("fold"), &cover),
            "the cover's own lines must prove everything the input proved"
        );
    }

    #[test]
    fn a_merge_across_a_literal_word_is_an_over_fold_and_one_across_a_value_is_not() {
        let cover = Cover {
            lines: BTreeSet::new(),
            must_stay_distinct: ["<TIMESTAMP> fs (<VARIES> unmounting volume <UUID>".to_string()]
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
            over_folded_kept_templates(
                &cover,
                &surviving("<TIMESTAMP> fs (<VARIES> mounted volume <UUID>")
            )
            .len(),
            1,
            "unmounting swallowed by mounted is an over-fold, and every later gate would read the distilled corpus as correct"
        );
        assert!(
            over_folded_kept_templates(
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
            !contract_no_replaced_value_survives(
                &values,
                &["url=https://host7.example.com/x".to_string()],
                &mut io::sink()
            ),
            "a value inside a URL is still that value"
        );
        assert!(
            contract_no_replaced_value_survives(
                &values,
                &["host7.example.community".to_string()],
                &mut io::sink()
            ),
            "a longer token that merely starts the same is not a survivor"
        );
    }

    #[test]
    fn a_short_vocabulary_word_inside_a_literal_is_not_a_survivor() {
        let a = Anonymizer::new(1, vec!["g8".to_string()]).seal();
        assert!(
            contract_vocabulary_gone(
                &a,
                &["cfg80211 driver loaded".to_string(), "a8r8g8b8".to_string()],
                &mut io::sink()
            ),
            "a short vocabulary word glued inside a longer token is not a survivor"
        );
        assert!(
            !contract_vocabulary_gone(&a, &["seen on g8 today".to_string()], &mut io::sink()),
            "the same word as its own token is a survivor"
        );
    }

    const LONG_LINE_BYTES: usize = 1_000;
    const LINES_PER_ANCHOR_GROUP: usize = 2;
    const BYTES_PER_FURTHER_VALUE: usize = LONG_LINE_BYTES * LINES_PER_ANCHOR_GROUP;

    fn long_line_anchor_buckets() -> (Vec<DistillGroup>, PartnerChoices) {
        let shape: [(&'static str, u64, usize); 7] = [
            ("A", 0, 100),
            ("A", 1, 50),
            ("A", 2, 10),
            ("A", 3, 20),
            ("B", 0, 100),
            ("B", 5, 50),
            ("B", 6, 10),
        ];
        let groups: Vec<DistillGroup> = shape
            .iter()
            .enumerate()
            .map(|(i, &(structure, anchor, count))| DistillGroup {
                template: format!("g{i}"),
                token_types: vec![structure],
                all_types: vec![structure],
                anchor,
                avg_bytes: LONG_LINE_BYTES,
                kept: (0..LINES_PER_ANCHOR_GROUP)
                    .map(|line| 1 + i * LINES_PER_ANCHOR_GROUP + line)
                    .collect(),
                capping_extra: Vec::new(),
                count,
                distinct_forms: 1,
            })
            .collect();
        let alone: PartnerChoices = [
            (vec!["A"], PartnerChoice::Alone),
            (vec!["B"], PartnerChoice::Alone),
        ]
        .into_iter()
        .collect();
        (groups, alone)
    }

    fn kept_templates(cover: &Cover) -> Vec<&str> {
        cover
            .must_stay_distinct
            .iter()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn long_lines_whose_anchor_proofs_fit_the_budget_keep_every_anchor_value() {
        let (groups, alone) = long_line_anchor_buckets();
        let cover = covering_subset(&groups, &alone, DISTILL_ANCHOR_PROOF_BUDGET_BYTES);
        assert_eq!(
            kept_templates(&cover),
            vec!["g0", "g1", "g2", "g3", "g4", "g5", "g6"],
            "three further values of 2,000 bytes fit in 1 MiB, so none is dropped"
        );
    }

    #[test]
    fn long_lines_past_the_budget_keep_one_value_per_bucket_and_a_round_robin_share() {
        let (groups, alone) = long_line_anchor_buckets();
        let free_values = ["g0", "g1", "g4", "g5"];

        let at_budget = 2 * BYTES_PER_FURTHER_VALUE;
        let cover = covering_subset(&groups, &alone, at_budget);
        assert_eq!(
            kept_templates(&cover),
            vec!["g0", "g1", "g2", "g4", "g5", "g6"],
            "round one takes g2 from A (first seen, though g3 is busier) and g6 from B; g3 would pass the budget"
        );
        let further_bytes: usize = cover
            .must_stay_distinct
            .iter()
            .filter(|t| !free_values.contains(&t.as_str()))
            .map(|t| bytes_kept_for(&groups[t[1..].parse::<usize>().expect("gN")]))
            .sum();
        assert_eq!(further_bytes, at_budget);
        assert!(further_bytes + BYTES_PER_FURTHER_VALUE > at_budget);

        let one_byte_short = at_budget - 1;
        assert_eq!(
            kept_templates(&covering_subset(&groups, &alone, one_byte_short)),
            vec!["g0", "g1", "g2", "g4", "g5"],
            "one byte under two values keeps only the first further value"
        );
        assert_eq!(
            kept_templates(&covering_subset(
                &groups,
                &alone,
                3 * BYTES_PER_FURTHER_VALUE
            )),
            vec!["g0", "g1", "g2", "g3", "g4", "g5", "g6"],
            "exactly three values' bytes keeps all three"
        );
        assert_eq!(
            kept_templates(&covering_subset(&groups, &alone, 0)),
            free_values.to_vec(),
            "with no budget each bucket keeps its primary and its one free anchor value"
        );
    }

    #[test]
    fn the_anchor_selection_is_the_same_on_a_second_run() {
        let (groups, alone) = long_line_anchor_buckets();
        let budget = 2 * BYTES_PER_FURTHER_VALUE;
        let first = covering_subset(&groups, &alone, budget);
        let second = covering_subset(&groups, &alone, budget);
        assert_eq!(first.lines, second.lines);
        assert_eq!(first.must_stay_distinct, second.must_stay_distinct);
    }

    #[test]
    fn a_long_vocabulary_word_glued_to_letters_is_a_survivor() {
        let a = Anonymizer::new(1, vec!["zorquid".to_string()]).seal();
        assert!(
            !contract_vocabulary_gone(&a, &["node9zorquidfoo online".to_string()], &mut io::sink()),
            "a 6+ character vocabulary word is checked as a substring anywhere"
        );
    }

    #[test]
    fn a_survivor_report_states_the_count_and_not_the_value() {
        let mut values = HashSet::new();
        values.insert("host7.example.com".to_string());
        let mut diag: Vec<u8> = Vec::new();
        assert!(!contract_no_replaced_value_survives(
            &values,
            &["url=https://host7.example.com/x".to_string()],
            &mut diag
        ));
        let a = Anonymizer::new(1, vec!["zorquid".to_string()]).seal();
        assert!(!contract_vocabulary_gone(
            &a,
            &["node zorquid online".to_string()],
            &mut diag
        ));
        let text = String::from_utf8(diag).expect("utf8");
        assert!(text.contains("lessence: 1 original value"), "{text}");
        assert!(text.contains("lessence: 1 vocabulary word"), "{text}");
        assert!(
            !text.contains("host7") && !text.contains("zorquid"),
            "{text}"
        );
    }

    #[test]
    fn output_lines_are_written_only_when_the_anonymisation_checks_hold() {
        let lines = vec!["one".to_string(), "two".to_string()];
        assert_eq!(publishable(&lines, true), lines.as_slice());
        assert!(publishable(&lines, false).is_empty());
    }
}
