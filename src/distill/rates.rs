//! Diagnostics for the timing information lost by member selection.
//! Rates count every occurrence, including members sharing one timestamp.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use crate::briefing::epoch_seconds;
use crate::patterns::Token;

pub(crate) type Rates = BTreeMap<String, Occurrences>;

#[derive(Debug, Default)]
pub(crate) struct Occurrences {
    count: usize,
    timed: usize,
    min: Option<i64>,
    max: Option<i64>,
    first: Option<(usize, i64)>,
    last: Option<(usize, i64)>,
}

impl Occurrences {
    pub(crate) fn record(&mut self, line_no: usize, tokens: &[Token]) {
        self.count += 1;
        let epoch = tokens.iter().find_map(|t| match t {
            Token::Timestamp(ts) => Some(epoch_seconds(ts)),
            _ => None,
        });
        let Some(Some(epoch)) = epoch else { return };
        self.timed += 1;
        self.min = Some(self.min.map_or(epoch, |old| old.min(epoch)));
        self.max = Some(self.max.map_or(epoch, |old| old.max(epoch)));
        if self.first.is_none_or(|(n, _)| line_no < n) {
            self.first = Some((line_no, epoch));
        }
        if self.last.is_none_or(|(n, _)| line_no > n) {
            self.last = Some((line_no, epoch));
        }
    }

    fn interval(&self) -> Result<f64, &'static str> {
        if self.timed != self.count || self.timed == 0 {
            return Err("missing or unsupported wall-clock timestamps");
        }
        if self.count < 2 {
            return Err("fewer than two occurrences");
        }
        if self.first.unwrap().1 > self.last.unwrap().1 {
            return Err("clock reversal or ambiguous year boundary");
        }
        let span = i128::from(self.max.unwrap()) - i128::from(self.min.unwrap());
        if span == 0 {
            return Err("zero span at one-second resolution");
        }
        Ok(span as f64 / (self.count - 1) as f64)
    }
}

/// Print every template's interval distortion and every strict rate-order
/// inversion. Missing clocks, missing templates and zero spans are named,
/// never silently treated as zero rates. The report is advisory only.
pub(super) fn report(source: &Rates, output: &Rates, writer: &mut impl Write) -> io::Result<()> {
    let names: BTreeSet<&String> = source.keys().chain(output.keys()).collect();
    let rows: Vec<_> = names
        .into_iter()
        .map(|name| {
            let interval = |rates: &Rates| {
                rates
                    .get(name)
                    .ok_or("template absent")
                    .and_then(Occurrences::interval)
            };
            (name, interval(source), interval(output))
        })
        .collect();
    let mut factors: Vec<f64> = rows
        .iter()
        .filter_map(|(_, a, b)| Some(b.as_ref().ok()? / a.as_ref().ok()?))
        .collect();
    factors.sort_by(f64::total_cmp);
    let median = if factors.is_empty() {
        None
    } else {
        Some(f64::midpoint(
            factors[(factors.len() - 1) / 2],
            factors[factors.len() / 2],
        ))
    };
    writeln!(
        writer,
        "lessence: distill rates: advisory; mean interval = span/(occurrences-1), whole-second clocks; bursts count every occurrence"
    )?;
    writeln!(
        writer,
        "lessence: distill rates: {} comparable templates, {} unavailable; median interval distortion={}",
        factors.len(),
        rows.len() - factors.len(),
        median.map_or_else(|| "unavailable".to_string(), |n| format!("{n:.6}x"))
    )?;
    for (i, (name, a, b)) in rows.iter().enumerate() {
        match (a, b) {
            (Ok(a), Ok(b)) => writeln!(
                writer,
                "lessence: distill rate #{}: source_interval={a:.6}s distilled_interval={b:.6}s distortion={:.6}x relative_to_median={:.6}x template={name}",
                i + 1,
                b / a,
                (b / a) / median.unwrap()
            )?,
            _ => writeln!(
                writer,
                "lessence: distill rate #{}: unavailable; source={}; distilled={}; template={name}",
                i + 1,
                a.map_or_else(ToString::to_string, |n| format!("{n:.6}s")),
                b.map_or_else(ToString::to_string, |n| format!("{n:.6}s"))
            )?,
        }
    }
    let mut inversions = 0;
    for (i, (_, a, b)) in rows.iter().enumerate() {
        let (Ok(a), Ok(b)) = (a, b) else { continue };
        for (j, (_, c, d)) in rows.iter().enumerate().skip(i + 1) {
            let (Ok(c), Ok(d)) = (c, d) else { continue };
            if (a < c && b > d) || (a > c && b < d) {
                let (faster, slower) = if a < c {
                    (i + 1, j + 1)
                } else {
                    (j + 1, i + 1)
                };
                writeln!(
                    writer,
                    "lessence: distill rate inversion: #{faster} was faster than #{slower}; distilled ordering is reversed"
                )?;
                inversions += 1;
            }
        }
    }
    writeln!(
        writer,
        "lessence: distill rates: {inversions} ordering inversions"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn occurrences(times: &[i64]) -> Occurrences {
        let mut result = Occurrences::default();
        for (i, t) in times.iter().enumerate() {
            result.record(i + 1, &[Token::Timestamp((1_700_000_000 + t).to_string())]);
        }
        result
    }

    #[test]
    fn burst_members_count_even_when_their_timestamps_repeat() {
        let burst = occurrences(&[0, 0, 0, 9, 9, 9]);
        assert_eq!(burst.interval(), Ok(1.8));
    }

    #[test]
    fn reports_all_inversions_and_normalizes_against_even_sized_median() {
        let source = BTreeMap::from([
            ("alpha".into(), occurrences(&[0, 1, 2, 3, 4])),
            ("beta".into(), occurrences(&[0, 2, 4])),
        ]);
        let output = BTreeMap::from([
            ("alpha".into(), occurrences(&[0, 4])),
            ("beta".into(), occurrences(&[0, 2, 4])),
        ]);
        let mut bytes = Vec::new();
        report(&source, &output, &mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("median interval distortion=2.500000x"),
            "{text}"
        );
        assert!(
            text.contains("relative_to_median=1.600000x template=alpha"),
            "{text}"
        );
        assert!(
            text.contains("relative_to_median=0.400000x template=beta"),
            "{text}"
        );
        assert!(text.contains("#1 was faster than #2"), "{text}");
        assert!(text.contains("1 ordering inversions"), "{text}");
    }

    #[test]
    fn unchanged_rates_and_ties_are_not_inversions() {
        let source = BTreeMap::from([
            ("alpha".into(), occurrences(&[0, 2, 4])),
            ("beta".into(), occurrences(&[0, 2, 4])),
        ]);
        let mut bytes = Vec::new();
        report(&source, &source, &mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("median interval distortion=1.000000x"));
        assert!(text.contains("0 ordering inversions"));
    }

    #[test]
    fn unavailable_rates_are_named_and_excluded_from_the_median() {
        let mut missing = occurrences(&[0, 10]);
        missing.record(3, &[]);
        let source = BTreeMap::from([
            ("missing".into(), missing),
            ("singleton".into(), occurrences(&[0])),
            ("burst".into(), occurrences(&[0, 0])),
            ("reversed".into(), occurrences(&[10, 0])),
            ("lost".into(), occurrences(&[0, 10])),
        ]);
        let output = BTreeMap::from([
            ("missing".into(), occurrences(&[0, 10])),
            ("singleton".into(), occurrences(&[0])),
            ("burst".into(), occurrences(&[0, 0])),
            ("reversed".into(), occurrences(&[10, 0])),
        ]);
        let mut bytes = Vec::new();
        report(&source, &output, &mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("0 comparable templates, 5 unavailable"),
            "{text}"
        );
        for reason in [
            "missing or unsupported",
            "fewer than two",
            "zero span",
            "clock reversal",
            "template absent",
        ] {
            assert!(text.contains(reason), "{text}");
        }
        assert!(!text.contains("NaN"));
    }

    #[test]
    fn merging_evicted_groups_uses_input_order_and_full_span() {
        let mut merged = occurrences(&[20, 30]);
        // A separate group can flush before the earlier members of the
        // same final template. Accumulation must not depend on flush order.
        merged.first.as_mut().unwrap().0 += 2;
        merged.last.as_mut().unwrap().0 += 2;
        for (i, t) in [0, 10].iter().enumerate() {
            merged.record(i + 1, &[Token::Timestamp((1_700_000_000 + t).to_string())]);
        }
        assert_eq!(merged.interval(), Ok(10.0));
    }
}
