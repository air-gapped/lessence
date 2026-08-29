pub mod duration;
pub mod email;
pub mod hash;
pub mod json;
pub mod kubernetes;
pub mod names;
pub mod network;
pub mod path;
pub mod process;
pub mod quoted;
pub mod timestamp;
pub mod uuid;
// New patterns from 001-read-the-current
pub mod bracket_context;
pub mod http_status;
pub mod key_value;
pub mod log_module;
pub mod structured;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Timestamp(String),
    IPv4(String),
    IPv6(String),
    /// A hardware address, six hex pairs: one atom, whatever its bytes look like.
    Mac(String),
    Fqdn(String),
    Port(u16),
    Hash(HashType, String),
    Uuid(String),
    Pid(u32),
    ThreadID(String),
    Path(String),
    Json(String),
    Duration(String),
    Size(String),
    Number(String),
    HttpStatus(u16),
    QuotedString(String),
    Name(String),
    KubernetesNamespace(String),
    VolumeName(String),
    PluginType(String),
    PodName(String),
    // New patterns from 001-read-the-current
    HttpStatusClass(String),
    BracketContext(Vec<String>),
    KeyValuePair {
        key: String,
        value_type: String,
    },
    LogWithModule {
        level: String,
        module: String,
    },
    StructuredMessage {
        component: String,
        level: String,
    },

    // Email pattern
    Email(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
    SHA512,
    Generic(usize), // Length for generic hex strings
}

/// Which `FoldingStats` counter a token kind counts into. Several kinds
/// share a bucket (IPv4+IPv6, Pid+ThreadID, HttpStatus+HttpStatusClass,
/// the four kubernetes kinds); the mapping is a per-kind fact here, and
/// `FoldingStats::bump` in the folder is its one consumer.
#[derive(Debug, Clone, Copy, PartialEq)]
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
    HttpStatus,
    Sizes,
    Percentages,
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

/// Per-token-kind facts. One taxonomy owns them all; the consumers in the
/// folder and renderer are projections of this table:
///
/// 1. `machine_name` — discriminant name for JSON output
///    (`GroupRecord.token_types`, the `variation` map keys). Stable across
///    runs because it is `&'static str`.
/// 2. `display_label` — the text compact marker's "varying: X" label.
/// 3. `stats_bucket` — which `FoldingStats` counter the kind counts into.
/// 4. `sample_worthy` — rollup sampling policy: identity types (UUID, IP,
///    Path, Email, Hash, kubernetes objects, HTTP status, quoted strings,
///    names, bracket context, JSON) surface sample values an agent can use
///    to identify the entities involved; measurement types (Timestamp,
///    Port, Pid, ThreadID, Duration, Size, Number, KeyValuePair,
///    LogWithModule, StructuredMessage) are count-only — distinct counts
///    are useful, specific values are noise.
/// 5. `variation_compares_values` — whether the compact-marker variation
///    check compares token values: LogWithModule and StructuredMessage
///    vary by presence, not by value, so their values are excluded from
///    that comparison (but still feed the rollup distinct counts).
pub(crate) struct KindFacts {
    pub machine_name: &'static str,
    pub display_label: &'static str,
    pub stats_bucket: StatsBucket,
    pub sample_worthy: bool,
    pub variation_compares_values: bool,
}

impl Token {
    /// THE single exhaustive match over token variants. Adding a variant
    /// forces a new `KindFacts` row here (every field required), so no
    /// projection can silently miss the new kind.
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
            Token::Port(_) => facts("PORT", "port", StatsBucket::Ports, false),
            Token::Hash(_, _) => facts("HASH", "hash", StatsBucket::Hashes, true),
            Token::Uuid(_) => facts("UUID", "UUID", StatsBucket::Uuids, true),
            Token::Pid(_) => facts("PID", "PID", StatsBucket::Pids, false),
            Token::ThreadID(_) => facts("THREAD_ID", "thread", StatsBucket::Pids, false),
            Token::Path(_) => facts("PATH", "path", StatsBucket::Paths, true),
            Token::Json(_) => facts("JSON", "json", StatsBucket::Json, true),
            Token::Duration(_) => facts("DURATION", "duration", StatsBucket::Durations, false),
            Token::Size(_) => facts("SIZE", "size", StatsBucket::Sizes, false),
            Token::Number(_) => facts("NUMBER", "number", StatsBucket::Percentages, false),
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

    /// Value stringification — the one payload-touching projection, kept
    /// beside `facts()` so a new variant updates both under one roof. Used
    /// for rollup samples (sample-worthy kinds), rollup distinct-count
    /// hashing (count-only kinds), and the compact-marker variation check
    /// (kinds with `variation_compares_values`).
    pub(crate) fn value_string(&self) -> String {
        match self {
            Token::Timestamp(s)
            | Token::IPv4(s)
            | Token::IPv6(s)
            | Token::Mac(s)
            | Token::Fqdn(s)
            | Token::Uuid(s)
            | Token::Path(s)
            | Token::Json(s)
            | Token::Duration(s)
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

/// Maximum whitespace tokens per line that the LCS similarity comparison
/// handles. 64 covers virtually all real log lines while bounding the DP at
/// 64×64 token comparisons on the stack with zero allocation.
pub(crate) const MAX_SIMILARITY_TOKENS: usize = 64;

/// Leading tokens an overflow line keeps in order, as message identity.
///
/// The multiset comparison is order-insensitive, which is fine for a record's
/// payload but not for the words that say what the record IS. On a real
/// Rancher log, "Active TLS secret ..." and "Updating TLS secret for ..." share
/// a several-hundred-token `map[...]` payload that swamps the four words
/// telling them apart, so multiset similarity alone merged 18 "Updating" lines
/// into an "Active" group. Requiring the head to match in order keeps distinct
/// messages apart while still folding records that differ only in their body.
///
/// Four, because that is the conventional log-line prefix — timestamp, level,
/// component, first word of the message — so it reaches the first word that
/// carries meaning without extending into the payload. Raising it to 8 was
/// measured as strictly worse: it pulls JSON field values into the identity
/// and cost 25 extra groups on the k8s fixture (165 vs 140) for no additional
/// separation. A discriminator sitting deeper than the fourth token would be
/// missed; the principled successor is an order-sensitive LCS over the first
/// `MAX_SIMILARITY_TOKENS` tokens, which is strictly more work than the
/// evidence so far justifies.
pub(crate) const MULTISET_LEAD: usize = 4;

/// Maximum tokens for which the multiset fallback keeps hashes.
///
/// Above [`MAX_SIMILARITY_TOKENS`] the LCS DP is too expensive, but a token
/// multiset is still O(n) and — unlike a positional byte comparison — is not
/// defeated by one value changing length. Keeping the hashes costs 8 bytes per
/// token, so the count is bounded: 4096 tokens is 32 KB per line, and a
/// structured record big enough to exceed it is well past the point where
/// order-insensitive matching would still be meaningful.
pub(crate) const MAX_MULTISET_TOKENS: usize = 4096;

/// One whitespace token of a normalized line: its ahash plus the byte range
/// into `LogLine::normalized`. Hash inequality proves token inequality, so
/// similarity comparisons only touch the bytes on a hash match.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SimTok {
    pub hash: u64,
    pub start: u32,
    pub end: u32,
}

/// Cached whitespace-token view of `LogLine::normalized`, computed once at
/// construction so the clustering buffer scan never re-tokenizes a line.
#[derive(Debug, Clone)]
pub(crate) enum SimTokens {
    /// At most [`MAX_SIMILARITY_TOKENS`] tokens: in line order, plus the
    /// same token hashes sorted ascending. The sorted view gives an O(n)
    /// upper bound on the LCS (multiset intersection) that rejects most
    /// dissimilar pairs before any DP.
    Tokens {
        toks: Vec<SimTok>,
        sorted_hashes: Vec<u64>,
    },
    /// Between [`MAX_SIMILARITY_TOKENS`] and [`MAX_MULTISET_TOKENS`] tokens:
    /// too many for the LCS DP, but the sorted hashes are kept so similarity
    /// can compare token multisets instead of byte positions, plus the first
    /// [`MULTISET_LEAD`] hashes in order as message identity.
    Overflow {
        lead: [u64; MULTISET_LEAD],
        sorted_hashes: Vec<u64>,
    },
    /// Past [`MAX_MULTISET_TOKENS`], or a line too long to index with u32.
    /// Similarity falls back to positional byte overlap. Truncating the hash
    /// set instead would let two records that agree only on their first few
    /// thousand tokens score as identical, which is a worse failure than the
    /// one the multiset path fixes.
    Unbounded,
}

impl SimTokens {
    /// Token hashes in ascending order, for the multiset comparison. Empty
    /// when the line carries none.
    pub(crate) fn sorted_hashes(&self) -> &[u64] {
        match self {
            SimTokens::Tokens { sorted_hashes, .. } | SimTokens::Overflow { sorted_hashes, .. } => {
                sorted_hashes
            }
            SimTokens::Unbounded => &[],
        }
    }

    /// The first [`MULTISET_LEAD`] token hashes in line order, for overflow
    /// lines only. `None` elsewhere: the LCS path already respects order, and
    /// an unbounded line has no hashes at all.
    pub(crate) fn lead(&self) -> Option<&[u64; MULTISET_LEAD]> {
        match self {
            SimTokens::Overflow { lead, .. } => Some(lead),
            SimTokens::Tokens { .. } | SimTokens::Unbounded => None,
        }
    }
}

/// A word separator as every reader of a normalized line sees it: the
/// similarity metric, the group template and the rollup all split here.
/// Whitespace, plus `,` `{` `}` so a compact JSON record (`{"a":1,"b":"x"}`)
/// is its fields rather than one word — one differing value in a spaceless
/// record used to make the whole line one unmatched token.
#[inline]
pub(crate) fn is_word_sep(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b',' | b'{' | b'}')
}

/// Byte spans `(start, len)` of the words of `s`, in order. Separators are
/// ASCII, so every span starts and ends on a char boundary. Inside a quoted
/// string only whitespace separates: a JSON `msg` sentence that names
/// `task[x] with args=&{Threshold:80}` keeps the words it had before, and
/// only the record around it is split at its fields.
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
            if b[i] == b'"' && (i == 0 || b[i - 1] != b'\\') {
                quoted = !quoted;
            }
            i += 1;
        }
        Some((start, i - start))
    })
}

/// A small integer left literal by design (`Port 5`, `GPS mode 3 -> 2`,
/// `rc=3`): one or two digits and nothing else.
#[inline]
pub(crate) fn is_small_int(tok: &str) -> bool {
    (1..=2).contains(&tok.len()) && tok.bytes().all(|b| b.is_ascii_digit())
}

/// What the similarity metric hashes for a token. Two small integers hash
/// alike: `Port 5 link up` and `Port 6 link up` are one shape, and the
/// shown line says so with `<VARIES>` and the counts of each — the digits
/// stay literal on the line, they just do not keep it from folding.
#[inline]
fn sim_key(tok: &str) -> &str {
    if is_small_int(tok) { "<d>" } else { tok }
}

/// The words of `s`.
pub(crate) fn words(s: &str) -> impl Iterator<Item = &str> + '_ {
    word_spans(s).map(move |(at, len)| &s[at..at + len])
}

impl SimTokens {
    fn from_normalized(s: &str) -> Self {
        use std::hash::{Hash, Hasher};
        if s.len() > u32::MAX as usize {
            return SimTokens::Unbounded;
        }
        let mut toks = Vec::with_capacity(16);
        for (start, len) in word_spans(s) {
            if toks.len() == MAX_SIMILARITY_TOKENS {
                return Self::overflow_from(s);
            }
            let tok = &s[start..start + len];
            let mut hasher = ahash::AHasher::default();
            sim_key(tok).hash(&mut hasher);
            toks.push(SimTok {
                hash: hasher.finish(),
                start: start as u32,
                end: (start + len) as u32,
            });
        }
        let mut sorted_hashes: Vec<u64> = toks.iter().map(|t| t.hash).collect();
        sorted_hashes.sort_unstable();
        SimTokens::Tokens {
            toks,
            sorted_hashes,
        }
    }

    /// Hash every token of a line that overran the LCS bound, keeping only the
    /// sorted hashes. Positions are dropped: the multiset comparison does not
    /// use them, and at these sizes they are the bulk of the memory.
    fn overflow_from(s: &str) -> Self {
        use std::hash::{Hash, Hasher};
        let mut sorted_hashes: Vec<u64> = Vec::with_capacity(MAX_SIMILARITY_TOKENS * 2);
        let mut lead = [0u64; MULTISET_LEAD];
        for tok in words(s) {
            if sorted_hashes.len() == MAX_MULTISET_TOKENS {
                return SimTokens::Unbounded;
            }
            let mut hasher = ahash::AHasher::default();
            sim_key(tok).hash(&mut hasher);
            let h = hasher.finish();
            if sorted_hashes.len() < MULTISET_LEAD {
                lead[sorted_hashes.len()] = h;
            }
            sorted_hashes.push(h);
        }
        sorted_hashes.sort_unstable();
        SimTokens::Overflow {
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
    /// Hash of this line's anchor values — the fields that must match exactly
    /// for two lines to fold together (see `normalize::anchor_hash`). Zero
    /// when the line carries no anchor, which is most lines.
    ///
    /// Already folded into `hash`, so the folder's exact-hash group index
    /// cannot attach a line to a group with a different anchor. Kept
    /// separately because the similarity path needs to reject on it.
    pub(crate) anchor: u64,
    /// Lazily computed similarity-token cache. Most lines in fold-heavy
    /// logs resolve through the folder's exact-hash group index and never
    /// enter a similarity comparison, so the tokenization cost is only
    /// paid by lines that actually need it — and then exactly once.
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

    /// Attach anchor values. Chained onto `new` so the many test call sites
    /// that build anchor-free lines stay as they are.
    pub(crate) fn anchored(mut self, anchor: u64) -> Self {
        self.anchor = anchor;
        self
    }

    pub(crate) fn sim(&self) -> &SimTokens {
        self.sim_cache
            .get_or_init(|| SimTokens::from_normalized(&self.normalized))
    }
}

/// The kubernetes deference rule for plain-text detectors: lines carrying
/// these indicators belong to KubernetesDetector, so the bracket and
/// log-module detectors skip them. Declared per-entry in the detector
/// ordering table in `normalize.rs` (`defers_to_kubernetes`).
/// Fold every match of `regex` that `recognise` accepts, pushing one token per
/// fold and leaving unrecognised matches in the text verbatim.
///
/// Detectors that scan a line for one shape and rewrite it in place all had the
/// same body: `replace_all` with a closure that either pushes a token and
/// returns a placeholder, or returns `caps[0]` unchanged. The second half is
/// the easy one to get wrong when copied, so it lives here once.
pub(crate) fn fold_matches(
    text: &mut String,
    tokens: &mut Vec<Token>,
    regex: &regex::Regex,
    recognise: impl Fn(&regex::Captures) -> Option<(Token, String)>,
) {
    let folded = regex.replace_all(text, |caps: &regex::Captures| match recognise(caps) {
        Some((token, replacement)) => {
            tokens.push(token);
            replacement
        }
        None => caps.get(0).unwrap().as_str().to_string(),
    });
    // a line nothing matched in is left as it is, uncopied
    if let std::borrow::Cow::Owned(s) = folded {
        *text = s;
    }
}

pub(crate) fn has_kubernetes_indicators(text: &str) -> bool {
    has_k8s_resource_indicators(text) || has_k8s_component_names(text)
}

/// The kubernetes deference rule for the structured detector: same
/// resource indicators, but component names only in their JSON / logfmt
/// quoted forms — the plain names are matched by the bracket and
/// log-module detectors instead.
pub(crate) fn has_kubernetes_structured_indicators(text: &str) -> bool {
    has_k8s_resource_indicators(text)
        || text.contains(r#""component":"kubelet"#)
        || text.contains(r#""component":"scheduler"#)
        || text.contains(r#""component":"proxy"#)
        || text.contains(r#""component":"controller"#)
        || text.contains(r#""component":"etcd"#)
        || text.contains(r#""component":"coredns"#)
        || text.contains("component=kubelet")
        || text.contains("component=scheduler")
        || text.contains("component=proxy")
        || text.contains("component=controller")
        || text.contains("component=etcd")
        || text.contains("component=coredns")
}

/// Shared Kubernetes-resource indicators (namespaces, volumes, API
/// prefixes). Lines matching these belong to KubernetesDetector; the
/// bracket, log-module and structured detectors all skip them.
#[cfg_attr(test, mutants::skip)] // kube-proxy/scheduler/controller always match the earlier "kube-" check, making their || equivalent
pub(crate) fn has_k8s_resource_indicators(text: &str) -> bool {
    text.contains("kubernetes.io/")
        || text.contains("namespace/")
        || text.contains("pod/")
        || text.contains("service/")
        || text.contains("configmap/")
        || text.contains("secret/")
        || text.contains("deployment/")
        || text.contains("volumes/")
        || text.contains("projected-")
        || text.contains("volume-subpath")
        || text.contains("projected")
        || text.contains("apiserver")
        || text.contains("kube-")
}

/// Plain-text Kubernetes component names (kubelet, etcd, ...). Used by the
/// bracket and log-module detectors; the structured detector matches the
/// JSON/logfmt-quoted forms instead.
#[cfg_attr(test, mutants::skip)] // kube-proxy/scheduler/controller always match has_k8s_resource_indicators' "kube-" check
pub(crate) fn has_k8s_component_names(text: &str) -> bool {
    text.contains("kubelet")
        || text.contains("kube-proxy")
        || text.contains("kube-scheduler")
        || text.contains("kube-controller")
        || text.contains("etcd")
        || text.contains("coredns")
}
