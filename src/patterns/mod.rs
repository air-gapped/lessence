pub mod bracket_context;
pub mod duration;
pub mod email;
pub mod hash;
pub mod http_status;
pub mod json;
pub mod key_value;
pub mod kubernetes;
pub mod log_module;
pub mod names;
pub mod network;
pub mod path;
pub mod process;
pub mod quoted;
pub mod structured;
pub mod timestamp;
pub mod uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Timestamp(String),
    IPv4(String),
    IPv6(String),
    Mac(String),
    Fqdn(String),
    Host(String),
    Port(u16),
    Hash(HashType, String),
    Uuid(String),
    Pid(u32),
    ThreadID(String),
    Path(String),
    EmbeddedJson(String),
    Duration(String),
    CpuQuantity(String),
    Size(String),
    Number(String),
    HttpStatus(u16),
    QuotedString(String),
    Name(String),
    KubernetesNamespace(String),
    VolumeName(String),
    PluginType(String),
    PodName(String),
    HttpStatusClass(String),
    BracketContext(Vec<String>),
    KeyValuePair { key: String, value_type: String },
    LogWithModule { level: String, module: String },
    StructuredMessage { component: String, level: String },

    Email(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
    SHA512,
    Generic { len: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum StatsBucket {
    Timestamps,
    Ips,
    Macs,
    Ports,
    Fqdns,
    Hashes,
    Uuids,
    Pids,
    Durations,
    CpuQuantities,
    HttpStatus,
    Sizes,
    Numbers,
    Paths,
    Json,
    QuotedStrings,
    Names,
    Brackets,
    KeyValues,
    LogModules,
    Structured,
    Kubernetes,
    Emails,
}

pub(crate) struct KindFacts {
    pub machine_name: &'static str,
    pub display_label: &'static str,
    pub stats_bucket: StatsBucket,
    pub sample_worthy: bool,
    pub variation_compares_values: bool,
}

impl Token {
    pub(crate) fn facts(&self) -> KindFacts {
        const fn facts(
            machine_name: &'static str,
            display_label: &'static str,
            stats_bucket: StatsBucket,
            sample_worthy: bool,
        ) -> KindFacts {
            KindFacts {
                machine_name,
                display_label,
                stats_bucket,
                sample_worthy,
                variation_compares_values: true,
            }
        }
        match self {
            Token::Timestamp(_) => facts("TIMESTAMP", "timestamp", StatsBucket::Timestamps, false),
            Token::IPv4(_) => facts("IPV4", "IP", StatsBucket::Ips, true),
            Token::IPv6(_) => facts("IPV6", "IP", StatsBucket::Ips, true),
            Token::Mac(_) => facts("MAC", "mac", StatsBucket::Macs, true),
            Token::Fqdn(_) => facts("FQDN", "FQDN", StatsBucket::Fqdns, true),
            Token::Host(_) => facts("HOST", "host", StatsBucket::Fqdns, true),
            Token::Port(_) => facts("PORT", "port", StatsBucket::Ports, false),
            Token::Hash(_, _) => facts("HASH", "hash", StatsBucket::Hashes, true),
            Token::Uuid(_) => facts("UUID", "UUID", StatsBucket::Uuids, true),
            Token::Pid(_) => facts("PID", "PID", StatsBucket::Pids, false),
            Token::ThreadID(_) => facts("THREAD_ID", "thread", StatsBucket::Pids, false),
            Token::Path(_) => facts("PATH", "path", StatsBucket::Paths, true),
            Token::EmbeddedJson(_) => facts("JSON", "json", StatsBucket::Json, true),
            Token::Duration(_) => facts("DURATION", "duration", StatsBucket::Durations, false),
            Token::CpuQuantity(_) => facts(
                "CPU_QUANTITY",
                "cpu_quantity",
                StatsBucket::CpuQuantities,
                true,
            ),
            Token::Size(_) => facts("SIZE", "size", StatsBucket::Sizes, false),
            Token::Number(_) => facts("NUMBER", "number", StatsBucket::Numbers, false),
            Token::HttpStatus(_) => {
                facts("HTTP_STATUS", "http_status", StatsBucket::HttpStatus, true)
            }
            Token::QuotedString(_) => facts(
                "QUOTED_STRING",
                "quoted_string",
                StatsBucket::QuotedStrings,
                true,
            ),
            Token::Name(_) => facts("NAME", "name", StatsBucket::Names, true),
            Token::KubernetesNamespace(_) => {
                facts("K8S_NAMESPACE", "namespace", StatsBucket::Kubernetes, true)
            }
            Token::VolumeName(_) => facts("K8S_VOLUME", "volume", StatsBucket::Kubernetes, true),
            Token::PluginType(_) => facts("K8S_PLUGIN", "plugin", StatsBucket::Kubernetes, true),
            Token::PodName(_) => facts("K8S_POD", "pod", StatsBucket::Kubernetes, true),
            Token::HttpStatusClass(_) => facts(
                "HTTP_STATUS_CLASS",
                "http_status_class",
                StatsBucket::HttpStatus,
                true,
            ),
            Token::BracketContext(_) => facts(
                "BRACKET_CONTEXT",
                "bracket_context",
                StatsBucket::Brackets,
                true,
            ),
            Token::KeyValuePair { .. } => {
                facts("KEY_VALUE", "key_value_pair", StatsBucket::KeyValues, false)
            }
            Token::LogWithModule { .. } => KindFacts {
                machine_name: "LOG_WITH_MODULE",
                display_label: "log_with_module",
                stats_bucket: StatsBucket::LogModules,
                sample_worthy: false,
                variation_compares_values: false,
            },
            Token::StructuredMessage { .. } => KindFacts {
                machine_name: "STRUCTURED_MESSAGE",
                display_label: "structured_message",
                stats_bucket: StatsBucket::Structured,
                sample_worthy: false,
                variation_compares_values: false,
            },
            Token::Email(_) => facts("EMAIL", "email", StatsBucket::Emails, true),
        }
    }

    pub(crate) fn value_string(&self) -> String {
        match self {
            Token::Timestamp(s)
            | Token::IPv4(s)
            | Token::IPv6(s)
            | Token::Mac(s)
            | Token::Fqdn(s)
            | Token::Host(s)
            | Token::Uuid(s)
            | Token::Path(s)
            | Token::EmbeddedJson(s)
            | Token::Duration(s)
            | Token::CpuQuantity(s)
            | Token::Size(s)
            | Token::Number(s)
            | Token::QuotedString(s)
            | Token::Name(s)
            | Token::KubernetesNamespace(s)
            | Token::VolumeName(s)
            | Token::PluginType(s)
            | Token::PodName(s)
            | Token::ThreadID(s)
            | Token::HttpStatusClass(s)
            | Token::Email(s) => s.clone(),
            Token::Hash(_, s) => s.clone(),
            Token::BracketContext(parts) => parts.join(","),
            Token::Port(p) => p.to_string(),
            Token::HttpStatus(s) => s.to_string(),
            Token::Pid(p) => p.to_string(),
            Token::KeyValuePair { key, value_type } => format!("{key}={value_type}"),
            Token::LogWithModule { level, module } => format!("{level}:{module}"),
            Token::StructuredMessage { component, level } => format!("{component}:{level}"),
        }
    }
}

pub(crate) const MAX_SIMILARITY_TOKENS: usize = 64;

pub(crate) const MULTISET_LEAD: usize = 4;

pub(crate) const MAX_HASHED_TOKENS: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub(crate) struct SimTok {
    pub hash: u64,
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone)]
pub(crate) enum SimTokens {
    Lcs {
        toks: Vec<SimTok>,
        sorted_hashes: Vec<u64>,
    },
    Multiset {
        lead: [u64; MULTISET_LEAD],
        sorted_hashes: Vec<u64>,
    },
    ByteOverlap,
}

impl SimTokens {
    pub(crate) fn sorted_hashes(&self) -> &[u64] {
        match self {
            SimTokens::Lcs { sorted_hashes, .. } | SimTokens::Multiset { sorted_hashes, .. } => {
                sorted_hashes
            }
            SimTokens::ByteOverlap => &[],
        }
    }

    pub(crate) fn lead(&self) -> Option<&[u64; MULTISET_LEAD]> {
        match self {
            SimTokens::Multiset { lead, .. } => Some(lead),
            SimTokens::Lcs { .. } | SimTokens::ByteOverlap => None,
        }
    }
}

const JSON_FIELD_SEPARATORS: &[u8] = b",{}";

#[inline]
pub(crate) fn is_word_sep(b: u8) -> bool {
    b.is_ascii_whitespace() || JSON_FIELD_SEPARATORS.contains(&b)
}

fn toggles_quote(b: &[u8], i: usize) -> bool {
    b[i] == b'"' && (i == 0 || b[i - 1] != b'\\')
}

pub(crate) fn word_spans(s: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let b = s.as_bytes();
    let mut i = 0;
    let mut quoted = false;
    std::iter::from_fn(move || {
        let sep =
            |i: usize, quoted: bool| b[i].is_ascii_whitespace() || (!quoted && is_word_sep(b[i]));
        while i < b.len() && sep(i, quoted) {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        let start = i;
        while i < b.len() && !sep(i, quoted) {
            if toggles_quote(b, i) {
                quoted = !quoted;
            }
            i += 1;
        }
        Some((start, i - start))
    })
}

const SMALL_INT_MAX_DIGITS: usize = 2;
const SMALL_INT_TAIL_CLOSERS: &[u8] = b"])";
const SMALL_INT_SIM_SENTINEL: &str = "<d>";

#[inline]
pub(crate) fn is_small_int(tok: &str) -> bool {
    (1..=SMALL_INT_MAX_DIGITS).contains(&tok.len()) && tok.bytes().all(|b| b.is_ascii_digit())
}

pub(crate) fn small_int_tail(tok: &str) -> Option<(&str, &str)> {
    let b = tok.as_bytes();
    let mut end = b.len();
    if end > 0 && SMALL_INT_TAIL_CLOSERS.contains(&b[end - 1]) {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && b[start - 1].is_ascii_digit() {
        start -= 1;
    }
    let digits = end - start;
    if digits == 0 || digits > SMALL_INT_MAX_DIGITS || start == 0 {
        return None;
    }
    Some((&tok[..start], &tok[end..]))
}

#[inline]
fn hash_sim_token(tok: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = ahash::AHasher::default();
    if is_small_int(tok) {
        SMALL_INT_SIM_SENTINEL.hash(&mut hasher);
    } else if let Some((before, after)) = small_int_tail(tok) {
        before.hash(&mut hasher);
        SMALL_INT_SIM_SENTINEL.hash(&mut hasher);
        after.hash(&mut hasher);
    } else {
        tok.hash(&mut hasher);
    }
    hasher.finish()
}

pub(crate) fn words(s: &str) -> impl Iterator<Item = &str> + '_ {
    word_spans(s).map(move |(at, len)| &s[at..at + len])
}

impl SimTokens {
    fn from_normalized(s: &str) -> Self {
        if s.len() > u32::MAX as usize {
            return SimTokens::ByteOverlap;
        }
        let mut toks = Vec::with_capacity(16);
        for (start, len) in word_spans(s) {
            if toks.len() == MAX_SIMILARITY_TOKENS {
                return Self::overflow_from(s);
            }
            let tok = &s[start..start + len];
            toks.push(SimTok {
                hash: hash_sim_token(tok),
                start: start as u32,
                end: (start + len) as u32,
            });
        }
        let mut sorted_hashes: Vec<u64> = toks.iter().map(|t| t.hash).collect();
        sorted_hashes.sort_unstable();
        SimTokens::Lcs {
            toks,
            sorted_hashes,
        }
    }

    fn overflow_from(s: &str) -> Self {
        let mut sorted_hashes: Vec<u64> = Vec::with_capacity(MAX_SIMILARITY_TOKENS * 2);
        let mut lead = [0u64; MULTISET_LEAD];
        for tok in words(s) {
            if sorted_hashes.len() == MAX_HASHED_TOKENS {
                return SimTokens::ByteOverlap;
            }
            let h = hash_sim_token(tok);
            if sorted_hashes.len() < MULTISET_LEAD {
                lead[sorted_hashes.len()] = h;
            }
            sorted_hashes.push(h);
        }
        sorted_hashes.sort_unstable();
        SimTokens::Multiset {
            lead,
            sorted_hashes,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub original: String,
    pub normalized: String,
    pub tokens: Vec<Token>,
    pub hash: u64,
    pub(crate) anchor: u64,
    sim_cache: std::sync::OnceLock<SimTokens>,
}

impl LogLine {
    pub fn new(original: String, normalized: String, tokens: Vec<Token>, hash: u64) -> Self {
        LogLine {
            original,
            normalized,
            tokens,
            hash,
            anchor: 0,
            sim_cache: std::sync::OnceLock::new(),
        }
    }

    pub(crate) fn anchored(mut self, anchor: u64) -> Self {
        self.anchor = anchor;
        self
    }

    pub(crate) fn sim(&self) -> &SimTokens {
        self.sim_cache
            .get_or_init(|| SimTokens::from_normalized(&self.normalized))
    }
}

pub(crate) const SOURCE_EXTENSIONS: &[&str] = &[
    "go", "rs", "py", "js", "ts", "tsx", "jsx", "java", "c", "cc", "cpp", "h", "hpp", "rb", "php",
    "kt", "swift", "cs", "ex", "exs", "erl", "hrl", "scala", "clj", "lua", "pl", "sh", "m", "mm",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnchorSentinel {
    KlogCallSiteVisibleToPid,
    OpaqueToDetectors,
}

impl AnchorSentinel {
    pub(crate) const fn start(self) -> &'static str {
        match self {
            Self::KlogCallSiteVisibleToPid => "\0K",
            Self::OpaqueToDetectors => "\0A",
        }
    }

    pub(crate) fn text(self, index: usize) -> String {
        format!("{}{index}\0", self.start())
    }
}

pub(crate) fn is_source_file_name(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, ext)| SOURCE_EXTENSIONS.contains(&ext))
}

pub(crate) static EVENT_OBJECT_META: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(r"&Event\{ObjectMeta:\{[^}]*\}")
            .expect("Failed to compile event object regex")
    });

pub(crate) fn fold_matches(
    text: &mut String,
    tokens: &mut Vec<Token>,
    regex: &regex::Regex,
    recognise: impl Fn(&regex::Captures) -> Option<(Token, String)>,
) {
    struct Fold<'t, F> {
        tokens: &'t mut Vec<Token>,
        recognise: F,
    }
    impl<F: Fn(&regex::Captures) -> Option<(Token, String)>> regex::Replacer for Fold<'_, F> {
        fn replace_append(&mut self, caps: &regex::Captures<'_>, dst: &mut String) {
            match (self.recognise)(caps) {
                Some((token, replacement)) => {
                    self.tokens.push(token);
                    dst.push_str(&replacement);
                }
                None => dst.push_str(&caps[0]),
            }
        }
    }
    let folded = regex.replace_all(text, Fold { tokens, recognise });
    if let std::borrow::Cow::Owned(s) = folded {
        *text = s;
    }
}

pub(crate) const SYSTEMD_UNIT_TYPES: &[&str] = &[
    "service",
    "socket",
    "device",
    "mount",
    "automount",
    "swap",
    "target",
    "path",
    "timer",
    "slice",
    "scope",
];

pub(crate) fn is_systemd_unit_type(word: &str) -> bool {
    SYSTEMD_UNIT_TYPES.contains(&word)
}

pub(crate) fn is_designator(word: &str) -> bool {
    let letters = word.bytes().take_while(u8::is_ascii_alphabetic).count();
    letters >= 2 && word.bytes().skip(letters).all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod shared_word_shapes {
    use super::*;

    #[test]
    fn a_designator_is_two_or_more_letters_then_only_digits() {
        for word in ["ed25519", "sha256", "ipv6", "AES128", "ED25519"] {
            assert!(is_designator(word), "{word}");
        }
        for word in ["a1", "1abc", "ab1c", "F9009C60", "c420064480", ""] {
            assert!(!is_designator(word), "{word}");
        }
    }

    #[test]
    fn the_unit_types_are_every_systemd_unit_type() {
        let mut types = SYSTEMD_UNIT_TYPES.to_vec();
        types.sort_unstable();
        assert_eq!(
            types,
            [
                "automount",
                "device",
                "mount",
                "path",
                "scope",
                "service",
                "slice",
                "socket",
                "swap",
                "target",
                "timer"
            ]
        );
        assert!(is_systemd_unit_type("automount"));
        assert!(!is_systemd_unit_type("com"));
    }
}

#[cfg(test)]
mod similarity_token_boundaries {
    use super::*;

    #[test]
    fn a_small_int_is_one_or_two_digits() {
        assert!(is_small_int("7"));
        assert!(is_small_int("42"));
        for no in ["", "123", "1a", "a", "-1"] {
            assert!(!is_small_int(no), "{no}");
        }
    }

    #[test]
    fn a_small_int_tail_splits_the_surroundings_at_every_boundary() {
        assert_eq!(small_int_tail("slot[2]"), Some(("slot[", "]")));
        assert_eq!(small_int_tail("on(12)"), Some(("on(", ")")));
        assert_eq!(small_int_tail("eth0"), Some(("eth", "")));
        assert_eq!(small_int_tail("wifi0ap1"), Some(("wifi0ap", "")));
        assert_eq!(small_int_tail("a12]"), Some(("a", "]")));
        for none in ["", "]", "12", "1]", "abc", "x123", "x1234", "slot[]", "a1b"] {
            assert_eq!(small_int_tail(none), None, "{none}");
        }
    }

    #[test]
    fn quoted_values_keep_their_commas_and_escaped_quotes_do_not_close_them() {
        let plain: Vec<&str> = words("a b  c").collect();
        assert_eq!(plain, vec!["a", "b", "c"]);
        let record: Vec<&str> = words(r#"{"a":1,"b":"x,y"}"#).collect();
        assert_eq!(record, vec![r#""a":1"#, r#""b":"x,y""#]);
        let escaped: Vec<&str> = words(r#"k="a,\"b\",c" w"#).collect();
        assert_eq!(escaped, vec![r#"k="a,\"b\",c""#, "w"]);
        let odd: Vec<&str> = words(r#"k="a,\"b,c" w"#).collect();
        assert_eq!(
            odd,
            vec![r#"k="a,\"b,c""#, "w"],
            "an odd escaped quote is still one string; the comma stays inside"
        );
    }

    #[test]
    fn a_long_line_overflows_to_a_multiset_and_only_the_cap_is_unbounded() {
        let over: String = (0..(MAX_SIMILARITY_TOKENS + 5))
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        match SimTokens::from_normalized(&over) {
            SimTokens::Multiset { sorted_hashes, .. } => {
                assert_eq!(sorted_hashes.len(), MAX_SIMILARITY_TOKENS + 5);
                assert!(sorted_hashes.windows(2).all(|w| w[0] <= w[1]));
            }
            other => panic!(
                "expected Overflow, got {}",
                match other {
                    SimTokens::Lcs { .. } => "Tokens",
                    SimTokens::ByteOverlap => "Unbounded",
                    SimTokens::Multiset { .. } => unreachable!(),
                }
            ),
        }
        let capped: String = (0..=MAX_HASHED_TOKENS)
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(matches!(
            SimTokens::from_normalized(&capped),
            SimTokens::ByteOverlap
        ));
    }
}
