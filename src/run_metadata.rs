use crate::ingest::IngestReport;
use serde::Serialize;

#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
pub(crate) struct Count {
    value: Option<usize>,
    kind: &'static str,
}
impl Default for Count {
    fn default() -> Self {
        Self::exact(0)
    }
}
impl Count {
    pub(crate) const fn exact(value: usize) -> Self {
        Self {
            value: Some(value),
            kind: "exact",
        }
    }
    pub(crate) const fn lower_bound(value: usize) -> Self {
        Self {
            value: Some(value),
            kind: "lower_bound",
        }
    }
    pub(crate) const fn unknown() -> Self {
        Self {
            value: None,
            kind: "unknown",
        }
    }
}

#[derive(Serialize, Default)]
pub(crate) struct InputCompleteness {
    pub(crate) complete: bool,
    processed_lines: usize,
    skipped_overlong_lines: Count,
    unprocessed_after_max_lines: Count,
    failed_sources: Count,
}

#[derive(Default, Clone, Copy)]
enum IngestDigest {
    #[default]
    NoReport,
    OneReport(Option<[u8; 32]>),
    SeveralReportsHaveNoRawByteDigest,
}
impl IngestDigest {
    fn after_another_report(self, report: &IngestReport) -> Self {
        match self {
            Self::NoReport => Self::OneReport(report.input_hash),
            Self::OneReport(_) | Self::SeveralReportsHaveNoRawByteDigest => {
                Self::SeveralReportsHaveNoRawByteDigest
            }
        }
    }
    fn hash(self) -> Option<[u8; 32]> {
        match self {
            Self::OneReport(hash) => hash,
            Self::NoReport | Self::SeveralReportsHaveNoRawByteDigest => None,
        }
    }
}

#[derive(Clone, Copy)]
enum Omission {
    OverlongLinesSkipped,
    MaxLinesReached,
    FailedSources,
}
impl Omission {
    const IN_SUMMARY_ORDER: [Self; 3] = [
        Self::OverlongLinesSkipped,
        Self::MaxLinesReached,
        Self::FailedSources,
    ];
    const fn code(self) -> &'static str {
        match self {
            Self::OverlongLinesSkipped => "input.overlong_lines_skipped",
            Self::MaxLinesReached => "input.max_lines_reached",
            Self::FailedSources => "input.failed_sources",
        }
    }
    const fn message(self) -> &'static str {
        match self {
            Self::OverlongLinesSkipped => "Input lines exceeding --max-line-length were skipped.",
            Self::MaxLinesReached => "The line limit stopped input processing before EOF.",
            Self::FailedSources => "One or more requested input sources could not be opened.",
        }
    }
    const fn repair(self) -> &'static str {
        match self {
            Self::OverlongLinesSkipped => {
                "Rerun the same sources with a larger --max-line-length to analyze those lines."
            }
            Self::MaxLinesReached => {
                "Rerun the same sources without --max-lines to analyze the remaining input."
            }
            Self::FailedSources => {
                "Correct the input paths or access reported on stderr and rerun all requested sources."
            }
        }
    }
    const fn count(self, completeness: &InputCompleteness) -> Count {
        match self {
            Self::OverlongLinesSkipped => completeness.skipped_overlong_lines,
            Self::MaxLinesReached => completeness.unprocessed_after_max_lines,
            Self::FailedSources => completeness.failed_sources,
        }
    }
}

#[derive(Default)]
pub(crate) struct InputFacts {
    skipped: usize,
    limited: bool,
    failed: usize,
    digest: IngestDigest,
}
impl InputFacts {
    pub(crate) fn absorb(&mut self, report: &IngestReport, failed: usize) {
        self.skipped += report.overlong_lines_skipped;
        self.limited |= report.max_lines_reached;
        self.failed += failed;
        self.digest = self.digest.after_another_report(report);
    }
    const fn has(&self, omission: Omission) -> bool {
        match omission {
            Omission::OverlongLinesSkipped => self.skipped != 0,
            Omission::MaxLinesReached => self.limited,
            Omission::FailedSources => self.failed != 0,
        }
    }
    fn omissions(&self) -> impl Iterator<Item = Omission> + '_ {
        Omission::IN_SUMMARY_ORDER
            .into_iter()
            .filter(|&omission| self.has(omission))
    }
    pub(crate) fn degraded_codes(&self) -> Vec<&'static str> {
        self.omissions().map(Omission::code).collect()
    }

    pub(crate) fn completeness(&self, processed_lines: usize) -> InputCompleteness {
        InputCompleteness {
            complete: self.skipped == 0 && !self.limited && self.failed == 0,
            processed_lines,
            skipped_overlong_lines: Count::exact(self.skipped),
            unprocessed_after_max_lines: if self.limited {
                Count::unknown()
            } else {
                Count::exact(0)
            },
            failed_sources: Count::exact(self.failed),
        }
    }
}

#[derive(Serialize)]
struct Version {
    semver: &'static str,
    build: &'static str,
    target: &'static str,
}
#[derive(Serialize)]
struct InputHash {
    algorithm: &'static str,
    scope: &'static str,
    value: Option<String>,
    unavailable_reason: Option<UnavailableReason>,
}
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum UnavailableReason {
    Sanitized,
    FailedSources,
    MaxLines,
    NotRecorded,
}
impl UnavailableReason {
    fn highest_precedence(input: &InputFacts, sanitized: bool) -> Option<Self> {
        [
            (sanitized, Self::Sanitized),
            (input.failed != 0, Self::FailedSources),
            (input.limited, Self::MaxLines),
            (input.digest.hash().is_none(), Self::NotRecorded),
        ]
        .into_iter()
        .find_map(|(applies, reason)| applies.then_some(reason))
    }
}
#[derive(Serialize)]
struct Degraded {
    code: &'static str,
    count: Count,
    message: &'static str,
    repair: &'static str,
}

#[derive(Serialize)]
pub(crate) struct RunMetadata {
    schema_version: u32,
    version: Version,
    input_hash: InputHash,
    degraded: Vec<Degraded>,
}
impl RunMetadata {
    pub(crate) fn new(input: &InputFacts, sanitized: bool) -> Self {
        let completeness = input.completeness(0);
        let degraded = input
            .omissions()
            .map(|omission| Degraded {
                code: omission.code(),
                count: omission.count(&completeness),
                message: omission.message(),
                repair: omission.repair(),
            })
            .collect();
        let reason = UnavailableReason::highest_precedence(input, sanitized);
        Self {
            schema_version: 1,
            version: Version {
                semver: env!("CARGO_PKG_VERSION"),
                build: env!("LESSENCE_BUILD_ID"),
                target: env!("LESSENCE_TARGET"),
            },
            input_hash: InputHash {
                algorithm: "sha256",
                scope: "ordered-source-bytes-v1",
                value: if reason.is_none() {
                    input.digest.hash().map(|h| hex(&h))
                } else {
                    None
                },
                unavailable_reason: reason,
            },
            degraded,
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_ingestion_or_multiple_reports_cannot_claim_a_complete_raw_digest() {
        let mut input = InputFacts::default();
        assert_eq!(
            RunMetadata::new(&input, false)
                .input_hash
                .unavailable_reason,
            Some(UnavailableReason::NotRecorded),
            "no ingestion has no digest to claim"
        );
        let report = IngestReport {
            input_hash: Some([0x42; 32]),
            ..Default::default()
        };
        input.absorb(&report, 0);
        assert!(RunMetadata::new(&input, false).input_hash.value.is_some());
        input.absorb(&report, 0);
        let metadata = RunMetadata::new(&input, false);
        assert_eq!(
            metadata.input_hash.unavailable_reason,
            Some(UnavailableReason::NotRecorded),
            "a second report has no raw-byte digest of the whole run"
        );
        assert!(metadata.input_hash.value.is_none());
        assert!(metadata.degraded.is_empty());
    }

    #[test]
    fn omissions_have_one_shared_truth_and_stable_order() {
        for skipped in [0, 2] {
            for limited in [false, true] {
                for failed in [0, 3] {
                    let mut input = InputFacts::default();
                    input.absorb(
                        &IngestReport {
                            overlong_lines_skipped: skipped,
                            max_lines_reached: limited,
                            ..Default::default()
                        },
                        failed,
                    );
                    let metadata = RunMetadata::new(&input, false);
                    assert_eq!(metadata.degraded.is_empty(), input.completeness(7).complete);
                    let expected: Vec<_> = [
                        (skipped > 0, "input.overlong_lines_skipped"),
                        (limited, "input.max_lines_reached"),
                        (failed > 0, "input.failed_sources"),
                    ]
                    .into_iter()
                    .filter_map(|(yes, code)| yes.then_some(code))
                    .collect();
                    assert_eq!(
                        metadata.degraded.iter().map(|x| x.code).collect::<Vec<_>>(),
                        expected
                    );
                    assert_eq!(input.completeness(7).failed_sources, Count::exact(failed));
                }
            }
        }
    }
}
