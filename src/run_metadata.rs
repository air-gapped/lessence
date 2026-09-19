//! Additive run metadata for JSON summaries and preflight documents.
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

/// One owner for both completeness and actionable input-omission notes.
#[derive(Default)]
pub(crate) struct InputFacts {
    skipped: usize,
    limited: bool,
    failed: usize,
    hash: Option<[u8; 32]>,
    recorded: bool,
}
impl InputFacts {
    pub(crate) fn absorb(&mut self, report: &IngestReport, failed: usize) {
        self.skipped += report.overlong_lines_skipped;
        self.limited |= report.max_lines_reached;
        self.failed += failed;
        // A digest describes one whole ingest run. Combining reports cannot
        // combine their aggregate digests into that run's raw-byte identity;
        // absent a higher-priority omission, a second report is not_recorded.
        self.hash = if self.recorded {
            None
        } else {
            report.input_hash
        };
        self.recorded = true;
    }
    /// The degraded codes this run proved, in the same order and spelling
    /// the summary record's `degraded` array uses. The report locator names
    /// them so stdout and the file agree on what the input was.
    pub(crate) fn degraded_codes(&self) -> Vec<&'static str> {
        [
            (self.skipped != 0, "input.overlong_lines_skipped"),
            (self.limited, "input.max_lines_reached"),
            (self.failed != 0, "input.failed_sources"),
        ]
        .into_iter()
        .filter_map(|(yes, code)| yes.then_some(code))
        .collect()
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
    unavailable_reason: Option<&'static str>,
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
        let mut degraded = Vec::new();
        if input.skipped != 0 {
            degraded.push(Degraded {
                code: "input.overlong_lines_skipped",
                count: completeness.skipped_overlong_lines,
                message: "Input lines exceeding --max-line-length were skipped.",
                repair: "Rerun the same sources with a larger --max-line-length to analyze those lines.",
            });
        }
        if input.limited {
            degraded.push(Degraded {
                code: "input.max_lines_reached",
                count: completeness.unprocessed_after_max_lines,
                message: "The line limit stopped input processing before EOF.",
                repair: "Rerun the same sources without --max-lines to analyze the remaining input.",
            });
        }
        if input.failed != 0 {
            degraded.push(Degraded {
                code: "input.failed_sources",
                count: completeness.failed_sources,
                message: "One or more requested input sources could not be opened.",
                repair: "Correct the input paths or access reported on stderr and rerun all requested sources.",
            });
        }
        let reason = if sanitized {
            Some("sanitized")
        } else if input.failed != 0 {
            Some("failed_sources")
        } else if input.limited {
            Some("max_lines")
        } else if input.hash.is_none() {
            Some("not_recorded")
        } else {
            None
        };
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
                    input
                        .hash
                        .map(|h| format!("{:x}", sha2::digest::Output::<sha2::Sha256>::from(h)))
                } else {
                    None
                },
                unavailable_reason: reason,
            },
            degraded,
        }
    }
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
            Some("not_recorded")
        );
        let report = IngestReport {
            input_hash: Some([0x42; 32]),
            ..Default::default()
        };
        input.absorb(&report, 0);
        assert!(RunMetadata::new(&input, false).input_hash.value.is_some());
        input.absorb(&report, 0);
        let metadata = RunMetadata::new(&input, false);
        assert_eq!(metadata.input_hash.unavailable_reason, Some("not_recorded"));
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
