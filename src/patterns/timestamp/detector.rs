//! Unified timestamp detection.
//!
//! One table of regexes, each with an overlap-resolution score. Every line is
//! scanned by every pattern; where two matches overlap, the lower score wins.
//!
//! # The score
//!
//! Lower is stronger. The bands come from how much evidence a match carries
//! and how badly a false positive hurts:
//!
//! | band | family | why |
//! |------|--------|-----|
//! | -100..-40 | structured (ISO 8601, RFC 2822/822) | full date + time + zone; unmistakable |
//! | 0..60 | application (Kubernetes, Docker, Apache, Log4j, cloud) | full date + time, vendor-shaped |
//! | 140..160 | regional (US, European, Windows) | `01/02/2024` is a date, but which field is the month is a guess |
//! | 240 | database (MySQL, Oracle) | short forms, easily matched by accident |
//! | 350..360 | legacy (syslog, ANSI C, bare time, durations) | no year, or no date at all |
//! | 1480..1490 | unix epochs | a bare 10-13 digit integer is far more often an id, a size, or a port |
//!
//! Ties are broken by position in this table, which is why the table is
//! written pre-sorted: what you read is the resolution order. Two patterns
//! sharing a score can still disagree about how much text to swallow —
//! `us-date` takes the trailing `AM` of `01/02/2024 10:00:00 AM` and
//! `european-date` does not — so the order is load-bearing, not cosmetic.
//!
//! To add a format: put one `p(...)` line in the band it belongs to. Nothing
//! else needs touching.

use super::{DetectionResult, TimestampMatch, Token};
use regex::{Regex, RegexSet, RegexSetBuilder};
use std::sync::LazyLock;

/// One timestamp regex and the score that decides who wins an overlap.
pub struct TimestampPattern {
    /// Stable identifier, used by the format-coverage contract tests.
    pub name: &'static str,
    pub regex: Regex,
    /// Lower wins. See the module docs for the bands.
    pub score: i32,
}

fn p(name: &'static str, pattern: &str, score: i32) -> TimestampPattern {
    TimestampPattern {
        name,
        regex: Regex::new(pattern).expect("timestamp pattern must compile"),
        score,
    }
}

/// All timestamp patterns, pre-sorted by score (strongest first).
static PATTERNS: LazyLock<Vec<TimestampPattern>> = LazyLock::new(|| {
    vec![
        // ---- structured ----
        p(
            "iso8601-enhanced",
            r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}?)\b",
            -100,
        ),
        // A datetime with the weekday in front and the zone abbreviation
        // behind, as systemd-timesyncd writes it: `Thu 2025-10-30 16:53:44
        // CET`. Both are part of the timestamp; left outside it they made a
        // seven-line group read `Thu <TIMESTAMP> CET` for Fri/Sat/CEST members.
        p(
            "weekday-datetime-zone",
            r"\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) )?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})? (?:UTC|GMT|[ECMP][SD]T|CES?T|EES?T|WES?T|BST|IST|JST|KST|AE[SD]T|A[CW][SD]T|NZ[SD]T|MSK|HKT|SGT|PHT|WIB|WITA|WIT|HST|AK[SD]T|A[SD]T|N[SD]T)\b",
            -95,
        ),
        // A 12-hour clock's meridiem is part of the timestamp. Scored
        // with the regional forms, `iso8601-full` took the date and time
        // and left ` AM` outside: five lines of one event read
        // `<TIMESTAMP> <VARIES>` for AM against PM.
        p(
            "us-date-12h",
            r"\b\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}:\d{2}(?:\.\d{1,9})?\s*(?:AM|PM|am|pm)\b",
            -91,
        ),
        // The gateway's network-init script joins date and time with a
        // dash: `2025-06-26-00:45:05.454`. Unrecognised, the year folded as
        // a number and the time as a timestamp, and every calendar date was
        // its own group.
        p(
            "dash-joined-datetime",
            r"\b\d{4}-\d{2}-\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            -90,
        ),
        p(
            "week-date",
            r"\b\d{4}-W\d{2}-\d(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}?)?)?\b",
            -90,
        ),
        p(
            "ordinal-date",
            r"\b\d{4}-\d{3}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}?)?)?\b",
            -90,
        ),
        p(
            "iso8601-full",
            r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:\s*(?:UTC|GMT|[+-]\d{2}:?\d{2}?))?\b",
            -90,
        ),
        p(
            "rfc2822",
            r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b",
            -80,
        ),
        p(
            "rfc822",
            r"\w{3},\s+\d{2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT",
            -40,
        ),
        // ---- application ----
        p("kubernetes-log", r"[IWEF]\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+", 0),
        // The kernel ring buffer's uptime stamp, brackets and padding
        // included: `[    0.028586]` and `[4324019.474441]` are one shape,
        // where `[ <DECIMAL>]` against `[<DECIMAL>]` split a group in two
        // the moment the counter grew a digit.
        p("kernel-uptime", r"\[ *\d{1,7}\.\d{6}\]", 0),
        p(
            "docker-log",
            r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z\b",
            0,
        ),
        p(
            "java-simple-date",
            r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{1,9}\b",
            30,
        ),
        p(
            "apache-common",
            r"\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]",
            30,
        ),
        p(
            "log4j",
            r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}\s+\[",
            30,
        ),
        p(
            "nginx-access",
            r"\b\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\b",
            60,
        ),
        p(
            "splunk",
            r"\b\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}\.\d{1,6}\b",
            60,
        ),
        // Cloud logs differ only in fractional-second width: 3 / 6 / 7 digits.
        p("aws", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", 60),
        p("gcp", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", 60),
        p("azure", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z", 60),
        // ---- regional ----
        // Order matters against `european-date` below: both match
        // `01/02/2024 10:00:00 AM` from the same offset, but only this one
        // swallows the meridiem.
        p(
            "us-date",
            r"\b\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:\s*(?:AM|PM))?\b",
            140,
        ),
        p(
            "european-date",
            r"\b[0-3]\d/[01]\d/\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            140,
        ),
        p(
            "us-date-dash",
            r"\b\d{1,2}-\d{1,2}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            160,
        ),
        p(
            "european-date-dot",
            r"\b[0-3]\d\.[01]\d\.\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            160,
        ),
        p(
            "windows-event",
            r"\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)",
            160,
        ),
        p("windows-iis", r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", 160),
        // glog / rancher / norman: 2025/09/14 07:25:28
        p(
            "slash-date",
            r"\b\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            160,
        ),
        // ---- database ----
        p("mysql-timestamp", r"\b\d{6}\s+\d{2}:\d{2}:\d{2}\b", 240),
        p(
            "oracle",
            r"\b\d{2}-[A-Z]{3}-\d{2}\s+\d{2}\.\d{2}\.\d{2}(?:\.\d+)?\s*(?:AM|PM)?",
            240,
        ),
        // ---- legacy ----
        // asctime — `Sat Aug 29 08:40:15 2026`, Apache's `[Sat Aug 29
        // 08:40:15.123456 2026]`, git's `Aug 29 08:40:15 2026` — must
        // outrank syslog-bsd, which matches its middle: left to the bsd form
        // the weekday and the year stayed literal and every event on the
        // access points split three ways by day.
        p(
            "ansic",
            r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\s+\d{4}",
            340,
        ),
        p(
            "git-commit",
            r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\s+\d{4}",
            340,
        ),
        // `20260801142207`: year, a month 01–12, then day and clock.
        p("compact", r"\b20\d{2}(?:0[1-9]|1[0-2])\d{8}\b", 350),
        p(
            "syslog-bsd",
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            350,
        ),
        p("ibm-format", r"\b\d{2}\.\d{3}\s+\d{2}:\d{2}:\d{2}\b", 350),
        p(
            "syslog-with-year",
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            360,
        ),
        p(
            "time-only",
            r"\b\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}?)?\b",
            360,
        ),
        // ---- unix epochs ----
        p("unix-prefixed", r"@1[0-9]{9,10}(?:\.\d{1,9})?\b", 1480),
        p("unix-bracketed", r"\[1[0-9]{9,10}(?:\.\d{1,9})?\]", 1480),
        p("unix-timestamp", r"\b1[0-9]{9,10}(?:\.\d{1,9})?\b", 1490),
        // Like the seconds form, an epoch in ms or ns starts with 1 for every
        // date between 2001 and 2033; a 19-digit block id or database system
        // identifier that starts with anything else is a number.
        p("unix-timestamp-ms", r"\b1[0-9]{12}\b", 1490),
        p("unix-timestamp-us", r"\b1[0-9]{15}\b", 1490),
        p("unix-timestamp-ns", r"\b1[0-9]{18}\b", 1490),
    ]
});

// Rule out unrelated formats in one scan on ASCII text. On that input,
// ASCII and Unicode character classes and word boundaries agree. Actual
// matches still come from the original regexes; non-ASCII input takes the
// unchanged individual-regex path below.
static ASCII_CANDIDATES: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSetBuilder::new(patterns().iter().map(|pattern| pattern.regex.as_str()))
        .unicode(false)
        .build()
        .expect("ASCII timestamp candidate patterns must compile")
});

/// The full pattern table, strongest first.
pub fn patterns() -> &'static [TimestampPattern] {
    &PATTERNS
}

/// Central timestamp pattern detection system
pub struct UnifiedTimestampDetector;

impl UnifiedTimestampDetector {
    /// Primary detection interface - replaces TimestampDetector::detect_and_replace
    ///
    /// Constitutional requirements:
    /// - Support all 30+ timestamp formats without shortcuts
    /// - Thread-safe for parallel processing
    /// - Preserve 100% of unique information
    /// - Replace only longest/most specific match when overlaps occur
    /// - Unix timestamps lowest priority to prevent false positives
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let result = Self::detect_with_metadata(text);

        // Convert to legacy format for compatibility
        let tokens = result
            .matches
            .iter()
            .map(|m| Token::Timestamp(m.original.clone()))
            .collect();

        (result.normalized_text, tokens)
    }

    /// Advanced detection interface for detailed analysis
    ///
    /// Provides full detection metadata for debugging and validation
    pub fn detect_with_metadata(text: &str) -> DetectionResult {
        // Quick pre-filter to avoid expensive regex operations
        if !Self::has_timestamp_indicators(text) {
            return DetectionResult {
                normalized_text: text.to_string(),
                matches: Vec::new(),
            };
        }

        let mut all_matches = Vec::new();

        let candidates = text.is_ascii().then(|| ASCII_CANDIDATES.matches(text));
        // The set only rules out impossible patterns. Keep the original
        // regexes, match enumeration, scores and ordering for actual matches.
        for (index, pattern) in patterns().iter().enumerate() {
            if candidates.as_ref().is_some_and(|set| !set.matched(index)) {
                continue;
            }
            for regex_match in pattern.regex.find_iter(text) {
                if !Self::is_plausible(text, regex_match.start(), regex_match.end(), pattern.name) {
                    continue;
                }
                all_matches.push(TimestampMatch {
                    original: regex_match.as_str().to_string(),
                    start_pos: regex_match.start(),
                    end_pos: regex_match.end(),
                    score: pattern.score,
                });
            }
        }

        // Sort by position for overlap resolution
        all_matches.sort_by_key(|m| m.start_pos);

        // Resolve overlaps - select longest/most specific match
        let resolved_matches = Self::resolve_overlaps(all_matches);

        // Apply replacements
        let normalized_text = Self::apply_replacements(text, &resolved_matches);

        DetectionResult {
            normalized_text,
            matches: resolved_matches,
        }
    }

    /// A `hh:mm:ss` sitting inside a longer colon-hex chain
    /// (`01:67:32:d9:b3:...`, an ssh fingerprint) is two bytes of a digest,
    /// not a clock. A bare epoch glued to `-` or `_` (`blk_-6952...`,
    /// `blk_1234...`) is a negative number or an identifier, not a time.
    /// The clock's own digits are not range-checked: a malformed timestamp
    /// still folds as one, by long-standing contract.
    /// A bare epoch in seconds — ten digits, no fraction, plain or in
    /// brackets — is a timestamp only as the line's first token: anywhere
    /// else (`id=1700000000`, `size 1727676930 bytes`) it is a number.
    fn is_plausible(text: &str, start: usize, end: usize, pattern_name: &str) -> bool {
        let b = text.as_bytes();
        let m = &b[start..end];
        // A numeric epoch must cover the whole number. A decimal's
        // fractional digits can have exactly the length of a ms/us/ns
        // epoch; likewise an epoch-shaped integer prefix is not a
        // timestamp when its decimal fraction was not matched.
        if m.iter().all(u8::is_ascii_digit)
            && ((start > 0 && matches!(b[start - 1], b'-' | b'_'))
                || (pattern_name.starts_with("unix-timestamp")
                    && ((start > 0 && b[start - 1] == b'.')
                        || (end + 1 < b.len() && b[end] == b'.' && b[end + 1].is_ascii_digit()))))
        {
            return false;
        }
        let inner = match (m.first(), m.last()) {
            (Some(b'['), Some(b']')) => &m[1..m.len() - 1],
            _ => m,
        };
        if inner.len() <= 11 && inner.iter().all(u8::is_ascii_digit) && start > 0 {
            return false;
        }
        // `trace[1539274761]`, `Trace[1310679091]:` — a bracket glued to a
        // word is an index, whatever the number inside would parse as,
        // whether the candidate carries the bracket or sits inside it.
        if m.first() == Some(&b'[') && start > 0 && b[start - 1].is_ascii_alphanumeric() {
            return false;
        }
        if m.first().is_some_and(u8::is_ascii_digit)
            && start >= 2
            && b[start - 1] == b'['
            && b[start - 2].is_ascii_alphanumeric()
        {
            return false;
        }
        let hex_pair_before = start >= 3
            && b[start - 1] == b':'
            && b[start - 2].is_ascii_hexdigit()
            && b[start - 3].is_ascii_hexdigit();
        let hex_pair_after = end + 3 < b.len()
            && b[end] == b':'
            && b[end + 1].is_ascii_hexdigit()
            && b[end + 2].is_ascii_hexdigit()
            && b[end + 3] == b':';
        !(hex_pair_before || hex_pair_after)
    }

    /// A run of exactly ten digits starting with 1, standing alone and
    /// followed by a fractional part: `1481076984.827`. A bare ten-digit
    /// integer stays out — it is far more often a size or an id (see the
    /// module docs) — unless it opens the line, plain or bracketed
    /// (`1754057127 …`, `[1754057127] …`), where it is the line's stamp.
    fn has_epoch_run(text: &str) -> bool {
        let b = text.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'1' && (i == 0 || !b[i - 1].is_ascii_digit()) {
                let mut j = i;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if j - i == 10 && j + 1 < b.len() && b[j] == b'.' && b[j + 1].is_ascii_digit() {
                    return true;
                }
                let opens_line = i == 0 || (i == 1 && b[0] == b'[');
                if j - i == 10 && opens_line && (j == b.len() || !b[j].is_ascii_alphanumeric()) {
                    return true;
                }
                // ms, µs and ns epochs carry their precision as digits.
                if matches!(j - i, 13 | 16 | 19) && (j == b.len() || !b[j].is_ascii_alphanumeric())
                {
                    return true;
                }
                i = j;
            } else {
                i += 1;
            }
        }
        false
    }

    /// Does the line *open* on a kernel-uptime stamp? Only a date-bearing
    /// stamp is followed by a syslog host field; a dmesg line's first word
    /// is a driver (`usb`, `mem`, `hub`), never a host. A kernel stamp
    /// further along the line (`Aug 29 08:40:15 gw-core kernel: [ 1.2] …`)
    /// is not this: there the host field is real.
    pub(crate) fn opens_with_kernel_uptime(text: &str) -> bool {
        match text.find(']') {
            Some(end) if text.starts_with('[') => Self::has_kernel_uptime(&text[..=end]),
            _ => false,
        }
    }

    /// `[    0.028586]` / `[4324019.474441]`: a bracket, padding, digits, a
    /// dot and six more digits, then the closing bracket — carries no colon
    /// and no year, so the general indicators miss it.
    fn has_kernel_uptime(text: &str) -> bool {
        let b = text.as_bytes();
        let mut i = 0;
        while let Some(off) = b[i..].iter().position(|&c| c == b'[') {
            let mut j = i + off + 1;
            while j < b.len() && b[j] == b' ' {
                j += 1;
            }
            let d0 = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > d0
                && j + 7 < b.len()
                && b[j] == b'.'
                && b[j + 1..j + 7].iter().all(u8::is_ascii_digit)
                && b[j + 7] == b']'
            {
                return true;
            }
            i = i + off + 1;
        }
        false
    }

    /// `I0829 `, `W0101 `, `E1231 `: a klog level letter, four digits and a
    /// space, at the line start or after `] ` (a kubectl prefix).
    fn has_klog_header(text: &str) -> bool {
        let b = text.as_bytes();
        let mut i = 0;
        while i + 5 < b.len() {
            if matches!(b[i], b'I' | b'W' | b'E' | b'F')
                && b[i + 1..i + 5].iter().all(u8::is_ascii_digit)
                && b[i + 5] == b' '
                && (i == 0 || b[i - 1] == b' ')
            {
                return true;
            }
            i += 1;
        }
        false
    }

    /// `20260801142207`: fourteen digits standing alone, `20` then a
    /// month 01–12 — the `compact` shape, which carries no colon.
    fn has_compact_stamp(text: &str) -> bool {
        let b = text.as_bytes();
        text.match_indices("20").any(|(i, _)| {
            i + 14 <= b.len()
                && (i == 0 || !b[i - 1].is_ascii_alphanumeric())
                && b[i + 2..i + 14].iter().all(u8::is_ascii_digit)
                && (i + 14 == b.len() || !b[i + 14].is_ascii_alphanumeric())
                && matches!(
                    (b[i + 4], b[i + 5]),
                    (b'0', b'1'..=b'9') | (b'1', b'0'..=b'2')
                )
        })
    }

    /// `26.213 14:22:07`: two digits, a dot, three digits, whitespace and a
    /// clock — the `ibm-format` shape, which carries none of the general
    /// indicators.
    fn has_ibm_stamp(text: &str) -> bool {
        let b = text.as_bytes();
        text.match_indices('.').any(|(dot, _)| {
            let Some(i) = dot.checked_sub(2) else {
                return false;
            };
            if i + 10 > b.len()
                || (i > 0 && b[i - 1].is_ascii_alphanumeric())
                || !b[i].is_ascii_digit()
                || !b[i + 1].is_ascii_digit()
                || !b[i + 3..i + 6].iter().all(u8::is_ascii_digit)
                || !b[i + 6].is_ascii_whitespace()
            {
                return false;
            }
            let mut j = i + 7;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            j + 3 <= b.len()
                && b[j].is_ascii_digit()
                && b[j + 1].is_ascii_digit()
                && b[j + 2] == b':'
        })
    }

    /// Fast pre-filter for timestamp indicators
    fn has_timestamp_indicators(text: &str) -> bool {
        // `@1758304800` carries no colon at all, and neither does a bare
        // epoch: `audit(1481076984.827:17)` was `<TIMESTAMP>` on lines
        // that happened to contain a `T` and `<DECIMAL>` on the rest.
        text.contains("@1")
            || Self::has_epoch_run(text)
            || Self::has_kernel_uptime(text)
            || text.contains(':')
                && (text.contains("20") || // Years 20xx
            text.contains("19") || // Years 19xx
            text.contains('-') ||  // Date separators
            text.contains('T') ||  // ISO 8601 separator
            text.contains('[') ||  // Log brackets
            // A klog header, any month: `I0829 01:12:10.311614`. Listing
            // only I09..I12 left every August line's timestamp to luck — a
            // capital T elsewhere on the line.
            Self::has_klog_header(text) ||
            // Month names
            text.contains("Jan") || text.contains("Feb") || text.contains("Mar") ||
            text.contains("Apr") || text.contains("May") || text.contains("Jun") ||
            text.contains("Jul") || text.contains("Aug") || text.contains("Sep") ||
            text.contains("Oct") || text.contains("Nov") || text.contains("Dec") ||
            Self::has_ibm_stamp(text))
            || Self::has_compact_stamp(text)
    }

    /// Resolve overlapping matches using longest-match-first rule
    fn resolve_overlaps(mut matches: Vec<TimestampMatch>) -> Vec<TimestampMatch> {
        if matches.is_empty() {
            return matches;
        }

        // Strongest patterns first. The sort is stable and the input arrived
        // position-sorted, so equal scores fall back to position and then to
        // table order — see the module docs on why that order is load-bearing.
        matches.sort_by_key(|m| m.score);

        let mut resolved = Vec::new();
        // Accepted, mutually-disjoint intervals keyed by start position.
        // A BTreeMap lets each candidate's overlap test probe only its two
        // neighbouring intervals in O(log k) instead of scanning every
        // accepted interval, keeping resolution O(M log M) rather than O(M^2)
        // on adversarial inputs (e.g. a 1 MB line of disjoint timestamps).
        let mut used_positions: std::collections::BTreeMap<usize, usize> =
            std::collections::BTreeMap::new();

        for candidate in matches {
            let (start, end) = (candidate.start_pos, candidate.end_pos);

            // Accepted intervals are disjoint, so at most two neighbours can
            // touch this candidate: the one starting at or before `start`
            // (overlaps iff its end > start) and the one starting at or after
            // `start` (overlaps iff its start < end). This preserves the
            // original `start < used.end && end > used.start` semantics while
            // making the test O(log k) per candidate.
            let predecessor_overlaps = used_positions
                .range(..=start)
                .next_back()
                .is_some_and(|(_, &used_end)| used_end > start);
            let successor_overlaps = used_positions
                .range(start..)
                .next()
                .is_some_and(|(&used_start, _)| used_start < end);
            let overlaps = predecessor_overlaps || successor_overlaps;

            if !overlaps {
                used_positions.insert(start, end);
                resolved.push(candidate);
            }
        }

        // Sort resolved matches by position for consistent output
        resolved.sort_by_key(|m| m.start_pos);
        resolved
    }

    /// Apply timestamp replacements to text
    fn apply_replacements(text: &str, matches: &[TimestampMatch]) -> String {
        if matches.is_empty() {
            return text.to_string();
        }

        let mut result = text.to_string();

        // Apply replacements in reverse order to maintain positions
        let mut sorted_matches = matches.to_vec();
        sorted_matches.sort_by_key(|m| std::cmp::Reverse(m.start_pos));

        for timestamp_match in sorted_matches {
            let range = timestamp_match.start_pos..timestamp_match.end_pos;
            if range.end <= result.len() {
                result.replace_range(range, "<TIMESTAMP>");
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn kernel_uptime_only_opens_a_line_when_it_is_the_first_field() {
        assert!(UnifiedTimestampDetector::opens_with_kernel_uptime(
            "[   12.345678] flomp 1-1.2: attached"
        ));
        // Forwarded by syslog: the host field before `kernel:` is real, so
        // this line does carry a host and must not be gated out.
        assert!(!UnifiedTimestampDetector::opens_with_kernel_uptime(
            "Aug 29 08:40:15 gw-core kernel: [   12.345678] flomp 1-1.2: attached"
        ));
        assert!(!UnifiedTimestampDetector::opens_with_kernel_uptime(
            "[pod/blorb/frobnicator] starting"
        ));
    }
    use super::*;

    // ---- the table itself ----

    #[test]
    fn table_is_sorted_by_score() {
        // The table is read top-to-bottom as the resolution order, and
        // `resolve_overlaps` relies on a stable sort to fall back to it on
        // ties. An out-of-order line would silently change which pattern wins.
        let scores: Vec<i32> = patterns().iter().map(|p| p.score).collect();
        let mut sorted = scores.clone();
        sorted.sort_unstable();
        assert_eq!(
            scores, sorted,
            "PATTERNS must be written pre-sorted by score"
        );
    }

    #[test]
    fn table_names_are_unique() {
        let mut names: Vec<&str> = patterns().iter().map(|p| p.name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "pattern names must be unique");
    }

    #[test]
    fn unix_epochs_rank_below_everything_else() {
        // Constitutional requirement: a bare integer must never outrank a
        // real date, because most 10-13 digit integers in logs are not times.
        let worst_non_unix = patterns()
            .iter()
            .filter(|p| !p.name.starts_with("unix-"))
            .map(|p| p.score)
            .max()
            .unwrap();
        let best_unix = patterns()
            .iter()
            .filter(|p| p.name.starts_with("unix-"))
            .map(|p| p.score)
            .min()
            .unwrap();
        assert!(
            best_unix > worst_non_unix,
            "unix epoch patterns must score above (lose to) every other pattern"
        );
    }

    #[test]
    fn tie_between_us_and_european_date_is_deterministic() {
        // Both patterns match `01/02/2024 10:00:00 AM` from offset 0 with the
        // same score, but `us-date` also takes the ` AM`. Before the table was
        // pre-sorted the winner was drawn from HashMap iteration order, so the
        // same input normalised two different ways across runs.
        let (out, _) = UnifiedTimestampDetector::detect_and_replace("01/02/2024 10:00:00 AM alpha");
        assert_eq!(out, "<TIMESTAMP> alpha");
    }

    #[test]
    fn detection_is_stable_across_calls() {
        let input = "01/02/2024 10:00:00 AM alpha";
        let first = UnifiedTimestampDetector::detect_and_replace(input).0;
        for _ in 0..50 {
            assert_eq!(UnifiedTimestampDetector::detect_and_replace(input).0, first);
        }
    }

    #[test]
    fn one_line_can_contain_dates_with_different_separator_shapes() {
        let input = "I0901 12:30:00.123456 replay 2025-01-02T03:04:05Z then 03/04/2025 06:07:08 and 05.06.2025 09:10:11";
        let result = UnifiedTimestampDetector::detect_with_metadata(input);
        assert_eq!(
            result.normalized_text,
            "<TIMESTAMP> replay <TIMESTAMP> then <TIMESTAMP> and <TIMESTAMP>"
        );
        assert_eq!(result.matches.len(), 4);
    }

    #[test]
    fn ascii_and_unicode_digit_dates_keep_the_same_recognition() {
        let input = "2025-01-02T03:04:05Z then ٢٠٢٥-٠١-٠٢T٠٣:٠٤:٠٥Z";
        let result = UnifiedTimestampDetector::detect_with_metadata(input);
        assert_eq!(result.normalized_text, "<TIMESTAMP> then <TIMESTAMP>");
        assert_eq!(result.matches.len(), 2);
        assert_eq!(result.matches[1].original, "٢٠٢٥-٠١-٠٢T٠٣:٠٤:٠٥Z");
    }

    proptest::proptest! {
        #[test]
        fn ascii_candidate_scan_keeps_every_matching_format(
            prefix in "[ -~]{0,80}",
            suffix in "[ -~]{0,80}",
            year in 2000u16..2100,
            month in 1u8..13,
            day in 1u8..29,
        ) {
            let text = format!(
                "{prefix} I0901 12:30:00.123456 {year}-{month:02}-{day:02}T03:04:05Z {month}/{day}/{year} 06:07:08 {suffix}"
            );
            let candidates = ASCII_CANDIDATES.matches(&text);
            for (index, pattern) in patterns().iter().enumerate() {
                proptest::prop_assert_eq!(
                    candidates.matched(index),
                    pattern.regex.is_match(&text),
                    "candidate scan disagreed for {} on {:?}", pattern.name, text
                );
            }
        }
    }

    #[test]
    fn table_covers_thirty_plus_formats() {
        assert!(
            patterns().len() >= 30,
            "constitutional requirement: 30+ timestamp formats, got {}",
            patterns().len()
        );
    }

    /// systemd-timesyncd's `Thu 2025-10-30 16:53:44 CET` is one timestamp,
    /// weekday and zone included; a level word after a datetime is not a
    /// zone; network-init's dash-joined `2025-06-26-00:45:05.454` is one
    /// timestamp too.
    #[test]
    fn weekday_zone_and_dash_joined_datetimes_are_one_timestamp() {
        let (r, _) = UnifiedTimestampDetector::detect_and_replace(
            "restoring from recorded timestamp: Thu 2025-10-30 16:53:44 CET",
        );
        assert_eq!(r, "restoring from recorded timestamp: <TIMESTAMP>");
        let (r, _) = UnifiedTimestampDetector::detect_and_replace(
            "restoring from recorded timestamp: Sat 2026-05-09 23:28:08 CEST",
        );
        assert_eq!(r, "restoring from recorded timestamp: <TIMESTAMP>");
        let (r, _) =
            UnifiedTimestampDetector::detect_and_replace("2025-10-30 16:53:44 EXIT code 1 WARN x");
        assert_eq!(r, "<TIMESTAMP> EXIT code 1 WARN x");
        let (r, _) = UnifiedTimestampDetector::detect_and_replace(
            "<6> 2025-06-26-00:45:05.454: network-init start",
        );
        assert_eq!(r, "<6> <TIMESTAMP>: network-init start");
    }

    #[test]
    fn has_timestamp_indicators_year_and_colon() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "2024-01-01 10:00:00"
        ));
    }

    #[test]
    fn has_timestamp_indicators_iso8601() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "foo:barT"
        ));
    }

    #[test]
    fn has_timestamp_indicators_month_name() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Jan 1 10:00:00"
        ));
    }

    #[test]
    fn has_timestamp_indicators_k8s_level() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "I1025 10:00:00.000"
        ));
    }

    #[test]
    fn has_timestamp_indicators_no_colon_rejects() {
        assert!(!UnifiedTimestampDetector::has_timestamp_indicators(
            "2024-01-01 no colon"
        ));
    }

    #[test]
    fn has_timestamp_indicators_colon_but_no_date() {
        // Has colon but no year, date separator, month name, or k8s indicator
        assert!(!UnifiedTimestampDetector::has_timestamp_indicators(
            "foo:bar"
        ));
    }

    #[test]
    fn has_timestamp_indicators_empty() {
        assert!(!UnifiedTimestampDetector::has_timestamp_indicators(""));
    }

    #[test]
    fn has_timestamp_indicators_bracket() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "[10:00:00]"
        ));
    }

    // Additional per-condition tests for remaining || branches

    #[test]
    fn ts_ind_year_19() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "1999-01:00"
        ));
    }

    #[test]
    fn ts_ind_dash_only() {
        // Has : and - but no year/T/month/k8s
        assert!(UnifiedTimestampDetector::has_timestamp_indicators("a-b:c"));
    }

    #[test]
    fn ts_ind_feb() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Feb 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_mar() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Mar 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_apr() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Apr 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_may() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "May 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_jun() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Jun 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_jul() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Jul 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_aug() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Aug 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_sep() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Sep 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_oct() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Oct 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_nov() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Nov 1 10:00"
        ));
    }

    #[test]
    fn ts_ind_dec() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "Dec 1 10:00"
        ));
    }

    // K8s level prefixes: W, E, F and other month combinations

    #[test]
    fn ts_ind_w09() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "W0929 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_e09() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "E0929 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_f09() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "F0929 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_i09() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "I0929 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_i11() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "I1129 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_w11() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "W1129 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_e11() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "E1129 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_f11() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "F1129 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_i12() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "I1229 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_w12() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "W1229 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_e12() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "E1229 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_f12() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "F1229 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_w10() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "W1029 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_e10() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "E1029 10:00:00"
        ));
    }

    #[test]
    fn ts_ind_f10() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "F1029 10:00:00"
        ));
    }

    // ---- resolve_overlaps: boundary tests ----

    /// `score` is the overlap-resolution score: lower wins.
    fn make_match(start: usize, end: usize, score: i32) -> TimestampMatch {
        TimestampMatch {
            original: String::new(),
            start_pos: start,
            end_pos: end,
            score,
        }
    }

    #[test]
    fn resolve_overlaps_empty() {
        let result = UnifiedTimestampDetector::resolve_overlaps(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn resolve_overlaps_no_overlap() {
        let matches = vec![make_match(0, 10, -90), make_match(15, 25, -80)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn resolve_overlaps_overlap_higher_wins() {
        // Two matches overlap: 0..20 and 10..30
        // Stronger score (-90) should win
        let matches = vec![make_match(0, 20, -90), make_match(10, 30, -50)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start_pos, 0);
        assert_eq!(result[0].end_pos, 20);
    }

    #[test]
    fn resolve_overlaps_adjacent_both_survive() {
        // Touching but not overlapping: 0..10 and 10..20
        let matches = vec![make_match(0, 10, -90), make_match(10, 20, -80)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn resolve_overlaps_end_equals_start_both_survive() {
        // Kills mutant: `candidate_range.end > used_range.start` → `>= `
        // Stronger match at 5..15 selected first.
        // Then candidate 0..5: start(0) < used_end(15) = true,
        // end(5) > used_start(5) → 5 > 5 = false → no overlap → survives.
        // With >=: 5 >= 5 = true → overlap → wrongly excluded.
        let matches = vec![make_match(5, 15, -90), make_match(0, 5, -50)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 2, "adjacent end==start should not overlap");
    }

    // ---- Mutant-killing: has_timestamp_indicators ----

    #[test]
    fn ts_ind_requires_colon() {
        // Kills mutant: `text.contains(':') &&` condition
        // Input with date indicators but NO colon should return false
        assert!(!UnifiedTimestampDetector::has_timestamp_indicators(
            "2024-01-01 no colon here"
        ));
    }

    #[test]
    fn ts_ind_colon_with_year_20() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "2024:00"
        ));
    }

    // ---- Mutant-killing: resolve_overlaps ----

    #[test]
    fn resolve_overlaps_single_match() {
        // Single match should always survive
        let matches = vec![make_match(5, 15, -90)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start_pos, 5);
    }

    #[test]
    fn resolve_overlaps_three_overlapping() {
        // Three overlapping matches: 0..20, 5..25, 10..30
        // Strongest (-90) wins, others excluded
        let matches = vec![
            make_match(0, 20, -90),
            make_match(5, 25, -50),
            make_match(10, 30, -30),
        ];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 1, "only strongest should survive");
        assert_eq!(result[0].start_pos, 0);
    }

    #[test]
    fn resolve_overlaps_many_disjoint_bounded() {
        // Regression for F-006: a crafted line yields thousands of disjoint
        // timestamp candidates. The old linear used_positions scan made this
        // O(M^2) (CPU-DoS); the BTreeMap neighbour probe keeps it O(M log M).
        // We assert correctness on a large disjoint input — every disjoint
        // match must survive — which also exercises the sub-quadratic path
        // for thousands of candidates.
        const N: usize = 20_000;
        // Disjoint intervals 0..1, 2..3, 4..5, ... (a one-unit gap between each)
        // so none overlap; all must be retained.
        let matches: Vec<_> = (0..N).map(|i| make_match(i * 2, i * 2 + 1, -90)).collect();
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), N, "every disjoint match must survive");
        // Output is position-sorted and preserves each interval.
        for (i, m) in result.iter().enumerate() {
            assert_eq!(m.start_pos, i * 2);
            assert_eq!(m.end_pos, i * 2 + 1);
        }
    }

    #[test]
    fn resolve_overlaps_many_overlapping_one_wins() {
        // Adversarial counterpart: thousands of mutually-overlapping
        // candidates. The strongest score wins and blocks all others; the
        // neighbour probe still runs in O(log k).
        const N: usize = 20_000;
        // All share position 0..N+1; scores -10 down to -(10 + N - 1).
        let mut matches: Vec<_> = (0..N)
            .map(|i| make_match(0, N + 1, -10 - i as i32))
            .collect();
        matches.reverse(); // strongest no longer first in input order
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 1, "all overlap; only strongest survives");
        assert_eq!(result[0].score, -10 - (N as i32 - 1));
    }

    #[test]
    fn resolve_overlaps_rejects_candidate_overlapping_successor() {
        // Strong match at [10,20); weaker candidate [5,15) starts BEFORE it.
        // The successor check (used_start < end) must reject it — only the
        // predecessor check was previously pinned.
        let matches = vec![make_match(10, 20, -10), make_match(5, 15, -1)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(
            result.len(),
            1,
            "overlapping weaker candidate must be dropped"
        );
        assert_eq!(result[0].start_pos, 10);
        assert_eq!(result[0].score, -10);
    }

    /// `hh:mm:ss` inside a colon-hex chain is two bytes of a digest; a real
    /// clock, and a malformed one, still fold.
    #[test]
    fn a_clock_inside_a_hex_chain_is_not_one() {
        let (r, _) = UnifiedTimestampDetector::detect_and_replace(
            "RSA 01:67:32:d9:b3:20:5d:2d:5f:b4:35:c5:a5:8b:0a:5e",
        );
        assert!(!r.contains("<TIMESTAMP>"), "{r}");
        let (r, _) = UnifiedTimestampDetector::detect_and_replace(
            "RSA ab:12:34:56:cd:ef:01:23:45:67:89:ab:cd:ef:01:23",
        );
        assert!(!r.contains("<TIMESTAMP>"), "{r}");
        let (r, _) = UnifiedTimestampDetector::detect_and_replace("[at] 12:34:56 done");
        assert_eq!(r, "[at] <TIMESTAMP> done");
        let (r, _) = UnifiedTimestampDetector::detect_and_replace("[20/Jan/2025:10:21:18 +0000] x");
        assert_eq!(r, "<TIMESTAMP> x");
        let (r, _) = UnifiedTimestampDetector::detect_and_replace("[at] 25:99:99 done");
        assert_eq!(r, "[at] <TIMESTAMP> done", "malformed still folds");
    }

    #[test]
    fn slash_date_is_a_timestamp() {
        let (r, _) = UnifiedTimestampDetector::detect_and_replace("2025/09/14 07:25:28 [INFO] x");
        assert_eq!(r, "<TIMESTAMP> [INFO] x");
    }

    /// An epoch in ms or ns starts with 1, like the seconds form already
    /// required; and `@epoch` needs no colon to be looked at.
    #[test]
    fn an_epoch_starts_with_one() {
        let (r, _) =
            UnifiedTimestampDetector::detect_and_replace("block blk_-6952295868487656571: x");
        assert!(!r.contains("<TIMESTAMP>"), "{r}");
        let (r, _) =
            UnifiedTimestampDetector::detect_and_replace("block blk_1234567890123456789: x");
        assert!(
            !r.contains("<TIMESTAMP>"),
            "a block id is glued to an underscore: {r}"
        );
        let (r, _) = UnifiedTimestampDetector::detect_and_replace("[ns] 1758304800311000000: x");
        assert_eq!(r, "[ns] <TIMESTAMP>: x");
        let (r, _) = UnifiedTimestampDetector::detect_and_replace("@1758304800.311 metric");
        assert_eq!(r, "<TIMESTAMP> metric");
    }

    /// A bare epoch is seen without a colon or a date hint on the line.
    #[test]
    fn a_bare_epoch_needs_no_hint() {
        let (r, _) =
            UnifiedTimestampDetector::detect_and_replace("msg=audit(1481076984.827:17) cwd=/");
        assert_eq!(r, "msg=audit(<TIMESTAMP>:17) cwd=/");
        let (r, _) = UnifiedTimestampDetector::detect_and_replace("File size 1727676930 bytes");
        assert_eq!(
            r, "File size 1727676930 bytes",
            "a bare ten-digit integer is a size"
        );
    }
}

#[cfg(test)]
mod shapes_2026_08_29 {
    use super::UnifiedTimestampDetector;

    #[test]
    fn asctime_is_one_timestamp_weekday_and_year_included() {
        let (r, _) = UnifiedTimestampDetector::detect_and_replace(
            "Sat Aug 29 08:40:15 2026 daemon.info hostapd[10691]: x",
        );
        assert_eq!(r, "<TIMESTAMP> daemon.info hostapd[10691]: x");
        let (r, _) = UnifiedTimestampDetector::detect_and_replace(
            "[Sat Aug 29 08:40:15.123456 2026] [error] mod_jk",
        );
        assert_eq!(r, "[<TIMESTAMP>] [error] mod_jk");
        let (r, _) =
            UnifiedTimestampDetector::detect_and_replace("Date:   Aug 29 08:40:15 2026 +0200");
        assert_eq!(r, "Date:   <TIMESTAMP> +0200");
    }

    #[test]
    fn the_kernel_uptime_stamp_is_one_shape_at_any_width() {
        for line in [
            "[    0.028586] x",
            "[  3054.599909] x",
            "[4324019.474441] x",
        ] {
            let (r, t) = UnifiedTimestampDetector::detect_and_replace(line);
            assert_eq!(r, "<TIMESTAMP> x", "{line}");
            assert_eq!(t.len(), 1);
        }
        let (r, _) = UnifiedTimestampDetector::detect_and_replace("[abc] 1.5 x");
        assert_eq!(r, "[abc] 1.5 x");
    }

    #[test]
    fn a_bracket_glued_to_a_word_is_an_index() {
        for line in [
            "trace[1539274761] transaction",
            "Trace[1310679091]: end",
            "trace[1539274761.5] x",
        ] {
            let (r, t) = UnifiedTimestampDetector::detect_and_replace(line);
            assert_eq!(r, line, "{line}");
            assert!(t.is_empty());
        }
        let (r, _) = UnifiedTimestampDetector::detect_and_replace("[1539274761] ok: x");
        assert_eq!(r, "<TIMESTAMP> ok: x");
    }

    #[test]
    fn a_klog_header_is_a_timestamp_in_any_month() {
        for line in [
            "I0829 01:12:10.311614       1 x.go:1] no capital t here",
            "W0101 00:00:00.000001       1 x.go:1] y",
            "[pod/a/b] E1231 23:59:59.999999       1 x.go:1] z",
        ] {
            let (r, t) = UnifiedTimestampDetector::detect_and_replace(line);
            assert!(r.contains("<TIMESTAMP>"), "{line} -> {r}");
            assert_eq!(t.len(), 1, "{line}");
        }
        assert!(!UnifiedTimestampDetector::has_klog_header("FILE0829 x"));
    }

    #[test]
    fn a_meridiem_is_part_of_its_timestamp() {
        for line in [
            "2026-08-01 08:22:07 AM backup verification passed",
            "2026-08-09 11:47:33 PM backup verification passed",
            "2026-08-15 2:05:19.250 am backup verification passed",
        ] {
            let (r, t) = UnifiedTimestampDetector::detect_and_replace(line);
            assert_eq!(r, "<TIMESTAMP> backup verification passed", "{line}");
            assert_eq!(t.len(), 1, "{line}");
        }
        let (r, _) =
            UnifiedTimestampDetector::detect_and_replace("2026-08-01 14:22:07 AMQP link up");
        assert_eq!(
            r, "<TIMESTAMP> AMQP link up",
            "a word starting AM is a word"
        );
    }

    #[test]
    fn a_compact_stamp_and_an_ibm_stamp_need_no_other_hint() {
        for line in [
            "20260801142207 checkpoint written to disk",
            "20260815000000 checkpoint written to disk",
            "26.213 14:22:07 CICS transaction ABCD completed",
            "26.241\t00:00:00 CICS transaction ABCD completed",
        ] {
            let (r, t) = UnifiedTimestampDetector::detect_and_replace(line);
            assert!(r.starts_with("<TIMESTAMP> "), "{line} -> {r}");
            assert_eq!(t.len(), 1, "{line}");
        }
        for line in [
            "20261301000000 is no date, month 13",
            "seq 20260801142207x glued",
            "26.2134 14:22:07 four digits",
        ] {
            let (r, _) = UnifiedTimestampDetector::detect_and_replace(line);
            assert!(!r.starts_with("<TIMESTAMP>"), "{line} -> {r}");
        }
    }

    #[test]
    fn a_bare_epoch_is_a_timestamp_only_as_the_first_token() {
        for line in [
            "1754057127 heartbeat received from node-05",
            "[1754057127] audit event logged for user svc-ci",
            "[1756463415] audit event logged for user svc-ci",
        ] {
            let (r, t) = UnifiedTimestampDetector::detect_and_replace(line);
            assert!(r.starts_with("<TIMESTAMP> "), "{line} -> {r}");
            assert_eq!(t.len(), 1, "{line}");
        }
        for line in [
            "event id=1754057127 processed successfully by worker-3",
            "processing record id=1700000000 for batch queue-3",
            "2026-08-01 14:22:07 size 1727676930 bytes written",
            "at [1539274761] ok: x",
            "1754057127x glued",
        ] {
            let (r, _) = UnifiedTimestampDetector::detect_and_replace(line);
            assert_eq!(
                r.matches("<TIMESTAMP>").count(),
                usize::from(line.starts_with("2026")),
                "{line} -> {r}"
            );
        }
        let (r, _) =
            UnifiedTimestampDetector::detect_and_replace("msg=audit(1481076984.827:17) cwd=/");
        assert_eq!(
            r, "msg=audit(<TIMESTAMP>:17) cwd=/",
            "a fraction still marks an epoch anywhere"
        );
    }

    #[test]
    fn an_iso_duration_is_not_a_timestamp() {
        let (r, t) =
            UnifiedTimestampDetector::detect_and_replace("PT30M15S scheduled backup running");
        assert_eq!(r, "PT30M15S scheduled backup running");
        assert!(t.is_empty());
        assert!(super::patterns().iter().all(|p| p.name != "duration"));
    }

    #[test]
    fn epoch_sized_decimal_parts_are_not_timestamps() {
        for value in [
            "2.1437169999999",
            "2.1437169999999997",
            "2.1437169999999997123",
            ".1437169999999997",
            "-2.1437169999999997",
            "1437169999999.5",
            "1437169999999997.5",
            "1437169999999997123.5",
        ] {
            // A genuine timestamp elsewhere must not change classification.
            for prefix in ["", "2026-09-16T04:00:00Z "] {
                let line = format!("{prefix}latency={value}");
                let (shown, tokens) = UnifiedTimestampDetector::detect_and_replace(&line);
                assert!(
                    shown.ends_with(&format!("latency={value}")),
                    "{line} -> {shown}"
                );
                assert_eq!(tokens.len(), usize::from(!prefix.is_empty()), "{line}");
            }
        }
        for line in [
            "1789550000 request completed",
            "[1789550000] request completed",
            "stamp=@1789550000.123456789",
            "stamp=1789550000.123456789",
            "stamp=1789550000123",
            "stamp=1789550000123456",
            "stamp=1789550000123456789",
            // Compact calendar dates are a distinct, date-bearing format.
            "version=0.20260916120000-build",
        ] {
            let (shown, tokens) = UnifiedTimestampDetector::detect_and_replace(line);
            assert!(shown.contains("<TIMESTAMP>"), "{line} -> {shown}");
            assert_eq!(tokens.len(), 1, "{line}");
        }
    }

    #[test]
    fn an_epoch_in_microseconds_is_a_timestamp() {
        let (r, _) =
            UnifiedTimestampDetector::detect_and_replace(r#"{"time_micros": 1787969018585092}"#);
        assert_eq!(r, r#"{"time_micros": <TIMESTAMP>}"#);
    }
}
