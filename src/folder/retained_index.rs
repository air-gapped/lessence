//! Candidate lookup for retained founders. This only rejects impossible
//! matches; the normalizer and plain-word guard still decide membership.

use std::collections::BTreeMap;

use ahash::{AHashMap as HashMap, AHashSet as HashSet};

use crate::patterns::LogLine;

#[derive(Default)]
pub(super) struct RetainedIndex {
    anchors: HashMap<u64, AnchorIndex>,
}

#[derive(Default)]
struct AnchorIndex {
    lengths: BTreeMap<usize, Postings>,
    fallback: Vec<u64>,
}

#[derive(Default)]
struct Postings {
    groups: Vec<u64>,
    tokens: HashMap<u64, Vec<u64>>,
}

impl RetainedIndex {
    pub(super) fn insert(&mut self, founder: &LogLine) {
        let anchor = self.anchors.entry(founder.anchor).or_default();
        let hashes = founder.sim().sorted_hashes();
        if hashes.is_empty() {
            anchor.fallback.push(founder.hash);
            return;
        }
        let postings = anchor.lengths.entry(hashes.len()).or_default();
        postings.groups.push(founder.hash);
        let mut previous = None;
        for &hash in hashes {
            if previous != Some(hash) {
                postings.tokens.entry(hash).or_default().push(founder.hash);
                previous = Some(hash);
            }
        }
    }

    pub(super) fn candidates(&self, line: &LogLine, threshold: u8) -> Vec<u64> {
        if threshold > 100 {
            return Vec::new();
        }
        let Some(anchor) = self.anchors.get(&line.anchor) else {
            return Vec::new();
        };
        let hashes = line.sim().sorted_hashes();
        // Below 70 the normalizer can accept by byte-length ratio alone;
        // empty token caches use its byte fallback. Neither has a token
        // overlap lower bound, so only the anchor can narrow the search.
        if threshold < 70 || hashes.is_empty() {
            return anchor
                .lengths
                .values()
                .flat_map(|p| p.groups.iter())
                .chain(&anchor.fallback)
                .copied()
                .collect();
        }
        let n = hashes.len();
        let t = usize::from(threshold);
        let low = (t * n).div_ceil(200 - t);
        let high = (200 - t) * n / t;
        let mut candidates: HashSet<u64> = anchor.fallback.iter().copied().collect();
        for (&m, postings) in anchor.lengths.range(low..=high) {
            let needed = (t * (n + m)).div_ceil(200);
            // A successful multiset/LCS match needs at least `needed`
            // shared token occurrences. It must therefore share a token
            // in ANY n-needed+1 positions of the input. Choose the rarest
            // postings first, so common timestamp/level tokens do not
            // force a scan of every retained group. Duplicate positions
            // count toward this proof; duplicate candidate IDs do not.
            let mut rarest: Vec<_> = hashes
                .iter()
                .map(|&h| (postings.tokens.get(&h).map_or(0, Vec::len), h))
                .collect();
            rarest.sort_unstable();
            for (_, hash) in rarest.into_iter().take(n - needed + 1) {
                if let Some(groups) = postings.tokens.get(&hash) {
                    candidates.extend(groups);
                }
            }
        }
        candidates.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, normalize::Normalizer};

    /// The length window must admit an exact one-token match at threshold
    /// 100 (lessence-e8v 68:22): low is ceil(t*n / (200-t)) = 1 and high is
    /// 1, so the range is 1..=1. A low of 2 would either panic (range start
    /// above end) or skip the only bucket and lose the founder.
    #[test]
    fn candidate_filter_keeps_a_one_token_exact_match_at_threshold_100() {
        let normalizer = Normalizer::new(Config {
            threshold: 100,
            ..Config::default()
        });
        let norm = |s: &str| normalizer.normalize_line(s.to_string()).unwrap();
        let founder = norm("alpha");
        let line = norm("alpha");
        assert_eq!(line.sim().sorted_hashes().len(), 1);
        assert!(normalizer.are_similar(&line, &founder));
        let mut index = RetainedIndex::default();
        index.insert(&founder);
        assert!(index.candidates(&line, 100).contains(&founder.hash));
    }

    #[test]
    fn candidate_filter_never_loses_a_match_with_repeated_tokens_or_length_changes() {
        let texts = [
            "alpha beta gamma delta epsilon zeta",
            "alpha beta gamma theta epsilon zeta",
            "alpha alpha alpha beta gamma",
            "alpha alpha beta gamma",
            "alpha alpha alpha alpha beta gamma",
            "a very different sentence entirely",
            "",
            "    ",
        ];
        for threshold in [0, 50, 69, 70, 83, 100] {
            let normalizer = Normalizer::new(Config {
                threshold,
                ..Config::default()
            });
            let lines: Vec<_> = texts
                .iter()
                .map(|s| normalizer.normalize_line(s.to_string()).unwrap())
                .collect();
            let mut index = RetainedIndex::default();
            for line in &lines {
                index.insert(line);
            }
            for line in &lines {
                let candidates = index.candidates(line, threshold);
                for founder in &lines {
                    if normalizer.are_similar(line, founder) {
                        assert!(
                            candidates.contains(&founder.hash),
                            "threshold={threshold}, {:?} vs {:?}",
                            line.normalized,
                            founder.normalized
                        );
                    }
                }
            }
        }
    }

    /// The proof scans `n - needed + 1` of the rarest postings; a founder
    /// whose shared tokens are all common ones must still be found
    /// (lessence-e8v 84:56). At threshold 70 with ten tokens a side,
    /// needed is 7, so four positions are scanned: the three tokens no
    /// founder has, then one common token that reaches every founder.
    #[test]
    fn candidate_filter_reaches_a_founder_through_its_commonest_tokens() {
        let line = "alpha beta gamma delta epsilon zeta eta theta iota kappa";
        let founder = "alpha beta gamma delta epsilon zeta eta xray yankee zulu";
        let decoys = [
            "alpha beta gamma delta epsilon zeta eta one two three",
            "alpha beta gamma delta epsilon zeta eta four five six",
            "alpha beta gamma delta epsilon zeta eta seven eight nine",
        ];
        let normalizer = Normalizer::new(Config {
            threshold: 70,
            ..Config::default()
        });
        let norm = |s: &str| normalizer.normalize_line(s.to_string()).unwrap();
        let line = norm(line);
        let founder = norm(founder);
        assert!(normalizer.are_similar(&line, &founder));
        let mut index = RetainedIndex::default();
        index.insert(&founder);
        for decoy in decoys {
            index.insert(&norm(decoy));
        }
        assert!(index.candidates(&line, 70).contains(&founder.hash));
    }

    #[test]
    fn candidate_filter_keeps_overflow_and_byte_fallback_matches() {
        let texts = [
            "same lead words here ".to_string() + &"alpha ".repeat(60),
            "same lead words here ".to_string() + &"alpha ".repeat(61),
            "same lead words here ".to_string() + &"alpha ".repeat(80),
            "same lead words here ".to_string() + &"alpha ".repeat(4_097),
            "same lead words here ".to_string() + &"alpha ".repeat(4_098),
            "    ".into(),
            "     ".into(),
        ];
        for threshold in [50, 70, 83, 100] {
            let normalizer = Normalizer::new(Config {
                threshold,
                ..Config::default()
            });
            let lines: Vec<_> = texts
                .iter()
                .enumerate()
                .map(|(i, text)| LogLine::new(text.clone(), text.clone(), vec![], i as u64))
                .collect();
            let mut index = RetainedIndex::default();
            for line in &lines {
                index.insert(line);
            }
            for line in &lines {
                let candidates = index.candidates(line, threshold);
                for founder in &lines {
                    if normalizer.are_similar(line, founder) {
                        assert!(candidates.contains(&founder.hash));
                    }
                }
            }
        }
    }

    #[test]
    fn anchors_and_rare_tokens_narrow_the_candidates() {
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("worker process alpha started successfully".into())
            .unwrap();
        let b = normalizer
            .normalize_line("entirely unrelated message with different tokens".into())
            .unwrap();
        let c = a.clone().anchored(a.anchor.wrapping_add(1));
        let mut index = RetainedIndex::default();
        index.insert(&a);
        index.insert(&b);
        index.insert(&c);
        assert_eq!(index.candidates(&a, 83), vec![a.hash]);
    }
}
