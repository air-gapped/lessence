use super::{DetectionResult, TimestampMatch, Token};
use regex::{Regex, RegexSet, RegexSetBuilder, SetMatches};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::sync::LazyLock;

pub(crate) const TIMESTAMP_PLACEHOLDER: &str = "<TIMESTAMP>";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Band {
    StructuredFullDateTimeZone,
    ApplicationVendorShaped,
    RegionalAmbiguousDayMonth,
    DatabaseShortForm,
    LegacyNoYearOrNoDate,
    UnixEpochUsuallyANumber,
}

impl Band {
    pub const fn scores(self) -> RangeInclusive<i32> {
        match self {
            Self::StructuredFullDateTimeZone => -100..=-40,
            Self::ApplicationVendorShaped => 0..=60,
            Self::RegionalAmbiguousDayMonth => 140..=160,
            Self::DatabaseShortForm => 240..=240,
            Self::LegacyNoYearOrNoDate => 340..=360,
            Self::UnixEpochUsuallyANumber => 1480..=1490,
        }
    }
}

pub struct TimestampPattern {
    pub name: &'static str,
    pub regex: Regex,
    pub band: Band,
    pub score: i32,
}

fn p(name: &'static str, pattern: &str, band: Band, score: i32) -> TimestampPattern {
    debug_assert!(
        band.scores().contains(&score),
        "{name} scores {score}, outside its band {band:?} {:?}",
        band.scores()
    );
    TimestampPattern {
        name,
        regex: Regex::new(pattern).expect("timestamp pattern must compile"),
        band,
        score,
    }
}

const WEEKDAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
static WEEKDAY: LazyLock<String> = LazyLock::new(|| format!("(?:{})", WEEKDAY_NAMES.join("|")));
static MONTH: LazyLock<String> = LazyLock::new(|| format!("(?:{})", MONTH_NAMES.join("|")));
const MONTH_01_TO_12: &str = "(?:0[1-9]|1[0-2])";
const ZONE_OFFSET_HH_HHMM_OR_HH_COLON_MM: &str = r"[+-]\d{2}(?::?\d{2})?";
const ZONE_ABBREVIATION: &str = r"(?:UTC|GMT|[ECMP][SD]T|CES?T|EES?T|WES?T|BST|IST|JST|KST|AE[SD]T|A[CW][SD]T|NZ[SD]T|MSK|HKT|SGT|PHT|WIB|WITA|WIT|HST|AK[SD]T|A[SD]T|N[SD]T)";
const KERNEL_UPTIME_FRACTION_DIGITS: usize = 6;
const EPOCH_LEAD_DIGIT_2001_TO_2033: char = '1';
const EPOCH_AT_PREFIX: &str = "@1";
const EPOCH_SECONDS_DIGITS: usize = 10;
const EPOCH_SECONDS_MAX_DIGITS: usize = EPOCH_SECONDS_DIGITS + 1;
const EPOCH_SUBSECOND_DIGITS: [usize; 3] = [13, 16, 19];

fn cloud_iso_with_fraction_width(width: usize) -> String {
    format!(r"\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}\.\d{{{width}}}Z")
}

static PATTERNS: LazyLock<Vec<TimestampPattern>> = LazyLock::new(|| {
    use Band::{
        ApplicationVendorShaped, DatabaseShortForm, LegacyNoYearOrNoDate,
        RegionalAmbiguousDayMonth, StructuredFullDateTimeZone, UnixEpochUsuallyANumber,
    };
    let weekday = WEEKDAY.as_str();
    let month = MONTH.as_str();
    let zone = ZONE_OFFSET_HH_HHMM_OR_HH_COLON_MM;
    vec![
        p(
            "iso8601-enhanced",
            &[
                r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|",
                zone,
                r")\b",
            ]
            .concat(),
            StructuredFullDateTimeZone,
            -100,
        ),
        p(
            "weekday-datetime-zone",
            &[
                r"\b(?:",
                weekday,
                r" )?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})? ",
                ZONE_ABBREVIATION,
                r"\b",
            ]
            .concat(),
            StructuredFullDateTimeZone,
            -95,
        ),
        p(
            "us-date-12h",
            r"\b\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}:\d{2}(?:\.\d{1,9})?\s*(?:AM|PM|am|pm)\b",
            StructuredFullDateTimeZone,
            -91,
        ),
        p(
            "dash-joined-datetime",
            r"\b\d{4}-\d{2}-\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            StructuredFullDateTimeZone,
            -90,
        ),
        p(
            "week-date",
            &[
                r"\b\d{4}-W\d{2}-\d(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|",
                zone,
                r")?)?\b",
            ]
            .concat(),
            StructuredFullDateTimeZone,
            -90,
        ),
        p(
            "ordinal-date",
            &[
                r"\b\d{4}-\d{3}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|",
                zone,
                r")?)?\b",
            ]
            .concat(),
            StructuredFullDateTimeZone,
            -90,
        ),
        p(
            "iso8601-full",
            &[
                r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:\s*(?:UTC|GMT|",
                zone,
                r"))?\b",
            ]
            .concat(),
            StructuredFullDateTimeZone,
            -90,
        ),
        p(
            "rfc2822",
            &[
                r"\b",
                weekday,
                r",\s+\d{1,2}\s+",
                month,
                r"\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b",
            ]
            .concat(),
            StructuredFullDateTimeZone,
            -80,
        ),
        p(
            "rfc822",
            &[
                r"\b",
                weekday,
                r",\s+\d{2}\s+",
                month,
                r"\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT\b",
            ]
            .concat(),
            StructuredFullDateTimeZone,
            -40,
        ),
        p(
            "kubernetes-log",
            r"\b[IWEF]\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+",
            ApplicationVendorShaped,
            0,
        ),
        p(
            "kernel-uptime",
            &format!(r"\[ *\d{{1,7}}\.\d{{{KERNEL_UPTIME_FRACTION_DIGITS}}}\]"),
            ApplicationVendorShaped,
            0,
        ),
        p(
            "apache-common",
            r"\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]",
            ApplicationVendorShaped,
            30,
        ),
        p(
            "nginx-access",
            r"\b\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\b",
            ApplicationVendorShaped,
            60,
        ),
        p(
            "splunk",
            r"\b\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}\.\d{1,6}\b",
            ApplicationVendorShaped,
            60,
        ),
        p(
            "aws",
            &cloud_iso_with_fraction_width(3),
            ApplicationVendorShaped,
            60,
        ),
        p(
            "gcp",
            &cloud_iso_with_fraction_width(6),
            ApplicationVendorShaped,
            60,
        ),
        p(
            "azure",
            &cloud_iso_with_fraction_width(7),
            ApplicationVendorShaped,
            60,
        ),
        p(
            "us-date",
            r"\b\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:\s*(?:AM|PM))?\b",
            RegionalAmbiguousDayMonth,
            140,
        ),
        p(
            "european-date",
            r"\b[0-3]\d/[01]\d/\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            RegionalAmbiguousDayMonth,
            140,
        ),
        p(
            "us-date-dash",
            r"\b\d{1,2}-\d{1,2}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            RegionalAmbiguousDayMonth,
            160,
        ),
        p(
            "european-date-dot",
            r"\b[0-3]\d\.[01]\d\.\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            RegionalAmbiguousDayMonth,
            160,
        ),
        p(
            "windows-event",
            r"\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)",
            RegionalAmbiguousDayMonth,
            160,
        ),
        p(
            "windows-iis",
            r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}",
            RegionalAmbiguousDayMonth,
            160,
        ),
        p(
            "slash-date",
            r"\b\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            RegionalAmbiguousDayMonth,
            160,
        ),
        p(
            "mysql-timestamp",
            r"\b\d{6}\s+\d{2}:\d{2}:\d{2}\b",
            DatabaseShortForm,
            240,
        ),
        p(
            "oracle",
            r"\b\d{2}-[A-Z]{3}-\d{2}\s+\d{2}\.\d{2}\.\d{2}(?:\.\d+)?\s*(?:AM|PM)?",
            DatabaseShortForm,
            240,
        ),
        p(
            "ansic",
            &[
                r"\b",
                weekday,
                r"\s+",
                month,
                r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\s+\d{4}\b",
            ]
            .concat(),
            LegacyNoYearOrNoDate,
            340,
        ),
        p(
            "git-commit",
            &[
                r"\b",
                month,
                r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\s+\d{4}\b",
            ]
            .concat(),
            LegacyNoYearOrNoDate,
            340,
        ),
        p(
            "compact",
            &[r"\b20\d{2}", MONTH_01_TO_12, r"\d{8}\b"].concat(),
            LegacyNoYearOrNoDate,
            350,
        ),
        p(
            "syslog-bsd",
            &[
                r"\b",
                month,
                r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            ]
            .concat(),
            LegacyNoYearOrNoDate,
            350,
        ),
        p(
            "ibm-format",
            r"\b\d{2}\.\d{3}\s+\d{2}:\d{2}:\d{2}\b",
            LegacyNoYearOrNoDate,
            350,
        ),
        p(
            "syslog-with-year",
            &[
                r"\b",
                month,
                r"\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\b",
            ]
            .concat(),
            LegacyNoYearOrNoDate,
            360,
        ),
        p(
            "time-only",
            &[r"\b\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|", zone, r")?\b"].concat(),
            LegacyNoYearOrNoDate,
            360,
        ),
        p(
            "unix-prefixed",
            &format!(r"@{EPOCH_LEAD_DIGIT_2001_TO_2033}[0-9]{{9,10}}(?:\.\d{{1,9}})?\b"),
            UnixEpochUsuallyANumber,
            1480,
        ),
        p(
            "unix-bracketed",
            &format!(r"\[{EPOCH_LEAD_DIGIT_2001_TO_2033}[0-9]{{9,10}}(?:\.\d{{1,9}})?\]"),
            UnixEpochUsuallyANumber,
            1480,
        ),
        p(
            "unix-timestamp",
            &format!(r"\b{EPOCH_LEAD_DIGIT_2001_TO_2033}[0-9]{{9,10}}(?:\.\d{{1,9}})?\b"),
            UnixEpochUsuallyANumber,
            1490,
        ),
        p(
            "unix-timestamp-ms",
            &format!(r"\b{EPOCH_LEAD_DIGIT_2001_TO_2033}[0-9]{{12}}\b"),
            UnixEpochUsuallyANumber,
            1490,
        ),
        p(
            "unix-timestamp-us",
            &format!(r"\b{EPOCH_LEAD_DIGIT_2001_TO_2033}[0-9]{{15}}\b"),
            UnixEpochUsuallyANumber,
            1490,
        ),
        p(
            "unix-timestamp-ns",
            &format!(r"\b{EPOCH_LEAD_DIGIT_2001_TO_2033}[0-9]{{18}}\b"),
            UnixEpochUsuallyANumber,
            1490,
        ),
    ]
});

static ASCII_ONLY_PREFILTER: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSetBuilder::new(patterns().iter().map(|pattern| pattern.regex.as_str()))
        .unicode(false)
        .build()
        .expect("ASCII timestamp candidate patterns must compile")
});

fn formats_that_may_match_ascii(text: &str) -> Option<SetMatches> {
    text.is_ascii().then(|| ASCII_ONLY_PREFILTER.matches(text))
}

pub fn patterns() -> &'static [TimestampPattern] {
    &PATTERNS
}

#[derive(Default)]
struct DisjointIntervals {
    end_by_start: BTreeMap<usize, usize>,
}

impl DisjointIntervals {
    fn insert_if_disjoint(&mut self, start: usize, end: usize) -> bool {
        let predecessor_overlaps = self
            .end_by_start
            .range(..=start)
            .next_back()
            .is_some_and(|(_, &used_end)| used_end > start);
        let successor_overlaps = self
            .end_by_start
            .range(start..)
            .next()
            .is_some_and(|(&used_start, _)| used_start < end);
        if predecessor_overlaps || successor_overlaps {
            return false;
        }
        self.end_by_start.insert(start, end);
        true
    }
}

fn all_digits(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_digit)
}

pub struct UnifiedTimestampDetector;

impl UnifiedTimestampDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let result = Self::detect_with_metadata(text);

        let tokens = result
            .matches
            .iter()
            .map(|m| Token::Timestamp(m.original.clone()))
            .collect();

        (result.normalized_text, tokens)
    }

    pub fn detect_with_metadata(text: &str) -> DetectionResult {
        if !Self::has_timestamp_indicators(text) {
            return DetectionResult {
                normalized_text: text.to_string(),
                matches: Vec::new(),
            };
        }

        let mut all_matches = Vec::new();

        let may_match = formats_that_may_match_ascii(text);
        for (index, pattern) in patterns().iter().enumerate() {
            if may_match.as_ref().is_some_and(|set| !set.matched(index)) {
                continue;
            }
            for regex_match in pattern.regex.find_iter(text) {
                if !Self::is_plausible(text, regex_match.start(), regex_match.end(), pattern.band) {
                    continue;
                }
                all_matches.push(TimestampMatch {
                    original: regex_match.as_str().to_string(),
                    start_pos: regex_match.start(),
                    end_pos: regex_match.end(),
                    score: pattern.score,
                    pattern_index: index,
                });
            }
        }

        let resolved_matches = Self::resolve_overlaps(all_matches);

        let normalized_text = Self::apply_replacements(text, &resolved_matches);

        DetectionResult {
            normalized_text,
            matches: resolved_matches,
        }
    }

    fn is_plausible(text: &str, start: usize, end: usize, band: Band) -> bool {
        let b = text.as_bytes();
        !(Self::number_glued_to_an_identifier(b, start, end)
            || (band == Band::UnixEpochUsuallyANumber && Self::epoch_cuts_a_decimal(b, start, end))
            || Self::short_bare_number_not_opening_the_line(b, start, end)
            || Self::bracket_glued_to_a_word(b, start, end)
            || Self::inside_a_colon_hex_chain(b, start, end))
    }

    fn number_glued_to_an_identifier(b: &[u8], start: usize, end: usize) -> bool {
        all_digits(&b[start..end]) && start > 0 && matches!(b[start - 1], b'-' | b'_')
    }

    fn epoch_cuts_a_decimal(b: &[u8], start: usize, end: usize) -> bool {
        all_digits(&b[start..end])
            && ((start > 0 && b[start - 1] == b'.')
                || (end + 1 < b.len() && b[end] == b'.' && b[end + 1].is_ascii_digit()))
    }

    fn short_bare_number_not_opening_the_line(b: &[u8], start: usize, end: usize) -> bool {
        let m = &b[start..end];
        let inside_brackets = match (m.first(), m.last()) {
            (Some(b'['), Some(b']')) => &m[1..m.len() - 1],
            _ => m,
        };
        inside_brackets.len() <= EPOCH_SECONDS_MAX_DIGITS
            && all_digits(inside_brackets)
            && start > 0
    }

    fn bracket_glued_to_a_word(b: &[u8], start: usize, end: usize) -> bool {
        let m = &b[start..end];
        let carries_the_bracket =
            m.first() == Some(&b'[') && start > 0 && b[start - 1].is_ascii_alphanumeric();
        let sits_inside_the_bracket = m.first().is_some_and(u8::is_ascii_digit)
            && start >= 2
            && b[start - 1] == b'['
            && b[start - 2].is_ascii_alphanumeric();
        carries_the_bracket || sits_inside_the_bracket
    }

    fn inside_a_colon_hex_chain(b: &[u8], start: usize, end: usize) -> bool {
        let hex_pair_before = start >= 3
            && b[start - 1] == b':'
            && b[start - 2].is_ascii_hexdigit()
            && b[start - 3].is_ascii_hexdigit();
        let hex_pair_after = end + 3 < b.len()
            && b[end] == b':'
            && b[end + 1].is_ascii_hexdigit()
            && b[end + 2].is_ascii_hexdigit()
            && b[end + 3] == b':';
        hex_pair_before || hex_pair_after
    }

    fn has_epoch_run(text: &str) -> bool {
        let b = text.as_bytes();
        let ends_standing_alone = |j: usize| j == b.len() || !b[j].is_ascii_alphanumeric();
        let mut i = 0;
        while i < b.len() {
            if b[i] == EPOCH_LEAD_DIGIT_2001_TO_2033 as u8 && (i == 0 || !b[i - 1].is_ascii_digit())
            {
                let mut j = i;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                let digits = j - i;
                let seconds_with_fraction = digits == EPOCH_SECONDS_DIGITS
                    && j + 1 < b.len()
                    && b[j] == b'.'
                    && b[j + 1].is_ascii_digit();
                let opens_line = i == 0 || (i == 1 && b[0] == b'[');
                let bare_seconds_opening_the_line =
                    digits == EPOCH_SECONDS_DIGITS && opens_line && ends_standing_alone(j);
                let subsecond_precision =
                    EPOCH_SUBSECOND_DIGITS.contains(&digits) && ends_standing_alone(j);
                if seconds_with_fraction || bare_seconds_opening_the_line || subsecond_precision {
                    return true;
                }
                i = j;
            } else {
                i += 1;
            }
        }
        false
    }

    pub(crate) fn opens_with_kernel_uptime(text: &str) -> bool {
        match text.find(']') {
            Some(end) if text.starts_with('[') => Self::has_kernel_uptime(&text[..=end]),
            _ => false,
        }
    }

    fn has_kernel_uptime(text: &str) -> bool {
        const FRACTION: usize = KERNEL_UPTIME_FRACTION_DIGITS;
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
                && j + FRACTION + 1 < b.len()
                && b[j] == b'.'
                && all_digits(&b[j + 1..=j + FRACTION])
                && b[j + FRACTION + 1] == b']'
            {
                return true;
            }
            i = i + off + 1;
        }
        false
    }

    fn has_klog_header(text: &str) -> bool {
        let b = text.as_bytes();
        let mut i = 0;
        while i + 5 < b.len() {
            if matches!(b[i], b'I' | b'W' | b'E' | b'F')
                && all_digits(&b[i + 1..i + 5])
                && b[i + 5] == b' '
                && (i == 0 || b[i - 1] == b' ')
            {
                return true;
            }
            i += 1;
        }
        false
    }

    fn has_compact_stamp(text: &str) -> bool {
        let b = text.as_bytes();
        text.match_indices("20").any(|(i, _)| {
            i + 14 <= b.len()
                && (i == 0 || !b[i - 1].is_ascii_alphanumeric())
                && all_digits(&b[i + 2..i + 14])
                && (i + 14 == b.len() || !b[i + 14].is_ascii_alphanumeric())
                && matches!(
                    (b[i + 4], b[i + 5]),
                    (b'0', b'1'..=b'9') | (b'1', b'0'..=b'2')
                )
        })
    }

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
                || !all_digits(&b[i + 3..i + 6])
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

    fn has_timestamp_indicators(text: &str) -> bool {
        text.contains(EPOCH_AT_PREFIX)
            || Self::has_epoch_run(text)
            || Self::has_kernel_uptime(text)
            || text.contains(':') && Self::has_date_hint_beside_a_colon(text)
            || Self::has_compact_stamp(text)
    }

    fn has_date_hint_beside_a_colon(text: &str) -> bool {
        const CENTURY_PREFIXES: [&str; 2] = ["20", "19"];
        const DATE_OR_LOG_SEPARATORS: [char; 3] = ['-', 'T', '['];
        CENTURY_PREFIXES
            .iter()
            .any(|century| text.contains(century))
            || DATE_OR_LOG_SEPARATORS.iter().any(|&sep| text.contains(sep))
            || Self::has_klog_header(text)
            || MONTH_NAMES.iter().any(|month| text.contains(month))
            || Self::has_ibm_stamp(text)
    }

    fn resolve_overlaps(mut matches: Vec<TimestampMatch>) -> Vec<TimestampMatch> {
        if matches.is_empty() {
            return matches;
        }

        matches.sort_by_key(TimestampMatch::precedence);

        let mut resolved = Vec::new();
        let mut taken = DisjointIntervals::default();

        for candidate in matches {
            if taken.insert_if_disjoint(candidate.start_pos, candidate.end_pos) {
                resolved.push(candidate);
            }
        }

        resolved.sort_by_key(|m| m.start_pos);
        resolved
    }

    fn apply_replacements(text: &str, matches: &[TimestampMatch]) -> String {
        if matches.is_empty() {
            return text.to_string();
        }

        let mut result = text.to_string();

        let mut sorted_matches = matches.to_vec();
        sorted_matches.sort_by_key(|m| std::cmp::Reverse(m.start_pos));

        for timestamp_match in sorted_matches {
            let range = timestamp_match.start_pos..timestamp_match.end_pos;
            debug_assert!(
                range.end <= result.len(),
                "disjoint matches replaced right to left never reach past the text"
            );
            result.replace_range(range, TIMESTAMP_PLACEHOLDER);
        }

        result
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn kernel_uptime_only_opens_a_line_when_it_is_the_first_field() {
        assert!(
            UnifiedTimestampDetector::opens_with_kernel_uptime(
                "[   12.345678] flomp 1-1.2: attached"
            ),
            "a dmesg line's first word is a driver, never a host"
        );
        assert!(
            !UnifiedTimestampDetector::opens_with_kernel_uptime(
                "Aug 29 08:40:15 gw-core kernel: [   12.345678] flomp 1-1.2: attached"
            ),
            "forwarded by syslog: the host field before kernel: is real and must not be gated out"
        );
        assert!(!UnifiedTimestampDetector::opens_with_kernel_uptime(
            "[pod/blorb/frobnicator] starting"
        ));
    }
    use super::*;

    #[test]
    fn table_is_sorted_by_score() {
        let scores: Vec<i32> = patterns().iter().map(|p| p.score).collect();
        let mut sorted = scores.clone();
        sorted.sort_unstable();
        assert_eq!(
            scores, sorted,
            "PATTERNS must be written pre-sorted by score: resolve_overlaps falls back to table order on ties"
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
    fn every_score_lies_in_its_band_and_the_bands_follow_the_table() {
        for pattern in patterns() {
            assert!(
                pattern.band.scores().contains(&pattern.score),
                "{} scores {} outside {:?}",
                pattern.name,
                pattern.score,
                pattern.band
            );
        }
        let bands: Vec<Band> = patterns().iter().map(|p| p.band).collect();
        assert!(
            bands.is_sorted(),
            "a format is written in the band it belongs to"
        );
    }

    #[test]
    fn every_bare_digit_unix_pattern_is_in_the_epoch_band() {
        for pattern in patterns() {
            assert_eq!(
                pattern.name.starts_with("unix-"),
                pattern.band == Band::UnixEpochUsuallyANumber,
                "{}",
                pattern.name
            );
        }
    }

    fn precedence_of(name: &str) -> (i32, usize) {
        let (index, pattern) = patterns()
            .iter()
            .enumerate()
            .find(|(_, p)| p.name == name)
            .unwrap_or_else(|| panic!("no pattern {name}"));
        (pattern.score, index)
    }

    #[test]
    fn each_format_that_must_win_an_overlap_outranks_the_one_it_beats() {
        for (stronger, weaker, line, why) in [
            (
                "weekday-datetime-zone",
                "iso8601-full",
                "Thu 2025-10-30 16:53:44 CET x",
                "the weekday and the zone abbreviation are inside the stamp",
            ),
            (
                "us-date-12h",
                "iso8601-full",
                "2026-08-01 08:22:07 AM x",
                "the meridiem is inside the stamp",
            ),
            (
                "ansic",
                "syslog-bsd",
                "Sat Aug 29 08:40:15 2026 x",
                "asctime's weekday and year are inside the stamp",
            ),
            (
                "git-commit",
                "syslog-bsd",
                "Aug 29 08:40:15 2026 x",
                "the year is inside the stamp",
            ),
            (
                "us-date",
                "european-date",
                "01/02/2024 10:00:00 AM x",
                "only us-date swallows the AM",
            ),
        ] {
            assert!(
                precedence_of(stronger) < precedence_of(weaker),
                "{stronger} must outrank {weaker}: {why}"
            );
            assert_eq!(
                UnifiedTimestampDetector::detect_and_replace(line).0,
                "<TIMESTAMP> x",
                "{stronger} over {weaker}: {why}"
            );
        }
    }

    #[test]
    fn us_date_and_european_date_tie_on_score_so_table_order_decides() {
        let (us_score, us_index) = precedence_of("us-date");
        let (eu_score, eu_index) = precedence_of("european-date");
        assert_eq!(us_score, eu_score);
        assert!(
            us_index < eu_index,
            "both match 01/02/2024 10:00:00 AM from offset 0; only us-date takes the AM"
        );
    }

    #[test]
    fn unix_epochs_rank_below_everything_else() {
        let worst_non_unix = patterns()
            .iter()
            .filter(|p| p.band != Band::UnixEpochUsuallyANumber)
            .map(|p| p.score)
            .max()
            .unwrap();
        let best_unix = patterns()
            .iter()
            .filter(|p| p.band == Band::UnixEpochUsuallyANumber)
            .map(|p| p.score)
            .min()
            .unwrap();
        assert!(
            best_unix > worst_non_unix,
            "unix epoch patterns must score above (lose to) every other pattern: most 10-13 digit integers in logs are not times"
        );
    }

    #[test]
    fn tie_between_us_and_european_date_is_deterministic() {
        let (out, _) = UnifiedTimestampDetector::detect_and_replace("01/02/2024 10:00:00 AM alpha");
        assert_eq!(
            out, "<TIMESTAMP> alpha",
            "us-date and european-date both match at offset 0 at the same score; only us-date takes the AM"
        );
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
            let candidates = ASCII_ONLY_PREFILTER.matches(&text);
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
            "the table keeps at least 30 timestamp formats, got {}",
            patterns().len()
        );
    }

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
    fn a_colon_and_a_capital_t_are_an_iso_hint() {
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
    fn a_klog_header_is_a_hint() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "I1025 10:00:00.000"
        ));
    }

    #[test]
    fn date_hints_without_a_colon_are_not_a_hint() {
        for line in ["2024-01-01 no colon", "2024-01-01 no colon here"] {
            assert!(
                !UnifiedTimestampDetector::has_timestamp_indicators(line),
                "{line}"
            );
        }
    }

    #[test]
    fn every_month_abbreviation_with_a_colon_is_a_hint() {
        for month in [
            "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ] {
            let line = format!("{month} 1 10:00");
            assert!(
                UnifiedTimestampDetector::has_timestamp_indicators(&line),
                "{line}"
            );
        }
    }

    #[test]
    fn a_klog_header_of_any_level_and_month_is_a_hint() {
        for header in [
            "W0929", "E0929", "F0929", "I0929", "I1129", "W1129", "E1129", "F1129", "I1229",
            "W1229", "E1229", "F1229", "W1029", "E1029", "F1029",
        ] {
            let line = format!("{header} 10:00:00");
            assert!(
                UnifiedTimestampDetector::has_timestamp_indicators(&line),
                "{line}"
            );
        }
    }

    #[test]
    fn a_colon_without_any_date_hint_is_not_a_hint() {
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

    #[test]
    fn a_colon_and_a_19xx_year_are_a_hint() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "1999-01:00"
        ));
    }

    #[test]
    fn a_colon_and_a_dash_alone_are_a_hint() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators("a-b:c"));
    }

    fn make_match(start: usize, end: usize, score: i32) -> TimestampMatch {
        TimestampMatch {
            original: String::new(),
            start_pos: start,
            end_pos: end,
            score,
            pattern_index: 0,
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
    fn resolve_overlaps_lower_score_wins_an_overlap() {
        let matches = vec![make_match(0, 20, -90), make_match(10, 30, -50)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start_pos, 0);
        assert_eq!(result[0].end_pos, 20);
    }

    #[test]
    fn touching_intervals_do_not_overlap() {
        let matches = vec![make_match(0, 10, -90), make_match(10, 20, -80)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn a_weaker_match_ending_where_a_stronger_starts_survives() {
        let matches = vec![make_match(5, 15, -90), make_match(0, 5, -50)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 2, "end == start is not an overlap");
    }

    #[test]
    fn ts_ind_colon_with_year_20() {
        assert!(UnifiedTimestampDetector::has_timestamp_indicators(
            "2024:00"
        ));
    }

    #[test]
    fn resolve_overlaps_single_match() {
        let matches = vec![make_match(5, 15, -90)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start_pos, 5);
    }

    #[test]
    fn resolve_overlaps_three_overlapping() {
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
    fn twenty_thousand_disjoint_matches_all_survive_in_order() {
        const N: usize = 20_000;
        let matches: Vec<_> = (0..N).map(|i| make_match(i * 2, i * 2 + 1, -90)).collect();
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(
            result.len(),
            N,
            "every disjoint match must survive, resolved sub-quadratically"
        );
        for (i, m) in result.iter().enumerate() {
            assert_eq!(m.start_pos, i * 2);
            assert_eq!(m.end_pos, i * 2 + 1);
        }
    }

    #[test]
    fn the_strongest_of_twenty_thousand_overlapping_matches_wins_whatever_its_input_position() {
        const N: usize = 20_000;
        let mut matches: Vec<_> = (0..N)
            .map(|i| make_match(0, N + 1, -10 - i as i32))
            .collect();
        matches.reverse();
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(
            result.len(),
            1,
            "all overlap; only the strongest survives, though the input puts it first"
        );
        assert_eq!(result[0].score, -10 - (N as i32 - 1));
    }

    #[test]
    fn a_weaker_match_starting_before_a_stronger_one_is_dropped() {
        let matches = vec![make_match(10, 20, -10), make_match(5, 15, -1)];
        let result = UnifiedTimestampDetector::resolve_overlaps(matches);
        assert_eq!(
            result.len(),
            1,
            "a weaker candidate overlapping the start of a stronger one must be dropped"
        );
        assert_eq!(result[0].start_pos, 10);
        assert_eq!(result[0].score, -10);
    }

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

    #[test]
    fn an_epoch_starts_with_one_and_is_never_glued_to_an_underscore_or_dash() {
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
    fn iso_formats_cover_docker_java_and_log4j_stamps() {
        for (line, want) in [
            ("2024-01-01T10:00:00.123456789Z ready", "<TIMESTAMP> ready"),
            (
                "2024-01-01 10:00:00,123 INFO ready",
                "<TIMESTAMP> INFO ready",
            ),
            ("2024-01-01 10:00:00,123456 ready", "<TIMESTAMP> ready"),
            (
                "2024-01-01 10:00:00,123 [main] INFO ready",
                "<TIMESTAMP> [main] INFO ready",
            ),
        ] {
            let (r, t) = UnifiedTimestampDetector::detect_and_replace(line);
            assert_eq!(r, want, "{line}");
            assert_eq!(t.len(), 1, "{line}");
        }
    }

    #[test]
    fn an_hour_only_zone_offset_is_inside_the_stamp() {
        for line in [
            "2024-01-01T10:00:00+05 job ok",
            "2024-01-01T10:00:00+0530 job ok",
            "2024-01-01T10:00:00-05:30 job ok",
            "2024-01-01 10:00:00 +05 job ok",
        ] {
            let (r, t) = UnifiedTimestampDetector::detect_and_replace(line);
            assert_eq!(r, "<TIMESTAMP> job ok", "{line}");
            assert_eq!(t.len(), 1, "{line}");
        }
    }

    #[test]
    fn a_stamp_never_takes_the_tail_of_a_word() {
        for (line, want) in [
            ("cache hit Aug 3 10:00:00 2026", "cache hit <TIMESTAMP>"),
            ("Sat Aug 29 08:40:15 2026 ok", "<TIMESTAMP> ok"),
            ("Mon, 03 Aug 2026 10:00:00 GMT ok", "<TIMESTAMP> ok"),
        ] {
            assert_eq!(UnifiedTimestampDetector::detect_and_replace(line).0, want);
        }
        for (line, kept) in [
            ("backup failed 12 10:00:00 2026", "backup failed 12 "),
            ("fooMon, 03 Aug 2026 10:00:00 GMT x", "fooMon, 03 Aug 2026 "),
            (
                "I0829 01:00:00.100000 read FILE0829 01:12:10.311614",
                "FILE0829 ",
            ),
        ] {
            let (r, _) = UnifiedTimestampDetector::detect_and_replace(line);
            assert!(r.contains(kept), "{line} -> {r}");
        }
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

#[cfg(test)]
mod prefilter_boundaries {
    use super::*;

    type D = UnifiedTimestampDetector;

    #[test]
    fn the_ibm_stamp_shape_at_every_boundary() {
        assert!(D::has_ibm_stamp("26.213 14:22:07 msg"));
        assert!(D::has_ibm_stamp("26.213    14:22:07"));
        assert!(D::has_ibm_stamp("26.213 14:"));
        assert!(D::has_ibm_stamp("x 26.213 14:22"));
        for no in [
            "x26.213 14:22:07",
            "6.213 14:22:07",
            "26.21 14:22:07",
            "26.2134 14:22:07",
            "26.213x14:22:07",
            "26.213 1:22",
            "26.213 14",
            "26.213 14 22",
            "26.213",
            "a.213 14:22",
            "2a.213 14:22",
            "26.213 ",
            "26.213  ",
            "26.213 1",
            "26.213 1x:",
            "26.213      ",
            "26.213     1",
        ] {
            assert!(!D::has_ibm_stamp(no), "{no}");
        }
    }

    #[test]
    fn the_compact_stamp_shape_at_every_boundary() {
        assert!(D::has_compact_stamp("20260801142207"));
        assert!(D::has_compact_stamp("20260801142207 rest"));
        assert!(D::has_compact_stamp("at 20261231000000"));
        assert!(D::has_compact_stamp("xxxxx 20261231000000 z"));
        assert!(!D::has_compact_stamp("xxxxxxxxxxxxx 202601abcdefgh"));
        for no in [
            "x20260801142207",
            "20260801142207x",
            "2026080114220",
            "20261301142207",
            "20260001142207",
            "20a60801142207",
        ] {
            assert!(!D::has_compact_stamp(no), "{no}");
        }
    }

    #[test]
    fn the_kernel_uptime_shape_at_every_boundary() {
        assert!(D::has_kernel_uptime("[    0.028586] usb 1-1"));
        assert!(D::has_kernel_uptime("[4324019.474441]"));
        assert!(D::has_kernel_uptime("x [0.000001] y"));
        for no in [
            "[0.02858]",
            "[0.0285866]",
            "[.028586]",
            "[0.028586",
            "[0,028586]",
            "[0.02858a]",
            "0.028586]",
            "[ab.028586]",
            "[",
            "[   ",
            "[12",
            "[ 12",
        ] {
            assert!(!D::has_kernel_uptime(no), "{no}");
        }
    }

    #[test]
    fn the_klog_header_shape_at_every_boundary() {
        assert!(D::has_klog_header("I0829 01:12:10.311614"));
        assert!(D::has_klog_header("[pod/x/y] W0101 rest"));
        assert!(D::has_klog_header("F1231 x"));
        for no in [
            "xI0829 rest",
            "I082 rest",
            "I08290 rest",
            "I0829",
            "I0829x",
            "i0829 rest",
            "I08a9 rest",
        ] {
            assert!(!D::has_klog_header(no), "{no}");
        }
    }

    #[test]
    fn the_epoch_run_shape_at_every_boundary() {
        for yes in [
            "1481076984.827",
            "x 1481076984.8",
            "x1481076984.5",
            "1481076984 x",
            "1481076984",
            "1481076984.",
            "[1481076984] x",
            "x 1481076984123 y",
            "1481076984123456",
            "1481076984123456789",
        ] {
            assert!(D::has_epoch_run(yes), "{yes}");
        }
        for no in [
            "x 1481076984 y",
            "id=1481076984",
            "1481076984x",
            "14810769841",
            "148107698",
            "2481076984.5",
            "x 1481076984123x",
            "x 1481076984.x",
            "21481076984.5",
            "(1481076984) x",
        ] {
            assert!(!D::has_epoch_run(no), "{no}");
        }
    }

    #[test]
    fn plausibility_rejections_at_every_boundary() {
        const EPOCH: Band = Band::UnixEpochUsuallyANumber;
        const ISO: Band = Band::StructuredFullDateTimeZone;
        let p = |text: &str, start: usize, end: usize, band: Band| {
            D::is_plausible(text, start, end, band)
        };
        assert!(p("1700000000 x", 0, 10, EPOCH));
        assert!(p("2024-01-01T00:00:00 x", 0, 19, ISO));
        assert!(p("1700000000.", 0, 10, EPOCH));
        assert!(p("1700000000:ab", 0, 10, EPOCH));
        assert!(p("[1700000000] x", 0, 12, EPOCH));
        assert!(p("1700000000.x", 0, 10, EPOCH));
        assert!(p("x [1700000000123] y", 2, 17, EPOCH));
        assert!(p("1700000000:zz:", 0, 10, EPOCH));
        assert!(p("1700000000:zb:", 0, 10, EPOCH));
        assert!(p("1700000000:az:", 0, 10, EPOCH));
        assert!(p("x [1700000000123] y", 3, 16, EPOCH));
        assert!(p("xxxx [1700000000123] y", 6, 19, EPOCH));
        assert!(p("az:1700000000123", 3, 16, EPOCH));
        assert!(p("za:1700000000123", 3, 16, EPOCH));
        for (text, start, end, band) in [
            ("id-1700000000", 3, 13, EPOCH),
            ("id_1700000000", 3, 13, EPOCH),
            ("x.1700000000", 2, 12, EPOCH),
            ("x 1700000000.5", 2, 12, EPOCH),
            ("x 1700000000 y", 2, 12, EPOCH),
            ("x [1700000000]", 2, 14, EPOCH),
            ("trace[1539274761]", 5, 17, EPOCH),
            ("Trace[1310679091]:", 6, 16, EPOCH),
            ("ab:1700000000", 3, 13, EPOCH),
            ("1700000000:ab:", 0, 10, EPOCH),
            ("id-1700000000123", 3, 16, EPOCH),
            ("id_1700000000123", 3, 16, EPOCH),
            ("Trace[1310679091123]:", 6, 19, EPOCH),
            ("x[1700000000123]", 1, 16, EPOCH),
            ("z[1700000000123]", 2, 15, EPOCH),
            ("ab:1700000000123", 3, 16, EPOCH),
            ("zzzzab:1700000000123", 7, 20, EPOCH),
        ] {
            assert!(
                !p(text, start, end, band),
                "{text}: rows are long candidates no later rule rejects, so each rule stands alone"
            );
        }
    }
}
