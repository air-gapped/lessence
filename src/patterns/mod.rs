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
    KeyValuePair { key: String, value_type: String },
    LogWithModule { level: String, module: String },
    StructuredMessage { component: String, level: String },

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
/// handles; longer lines fall back to the positional byte overlap. 64 covers
/// virtually all real log lines while bounding the DP at 64×64 token
/// comparisons on the stack with zero allocation.
pub(crate) const MAX_SIMILARITY_TOKENS: usize = 64;

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
    /// More tokens than the LCS comparison handles — similarity uses the
    /// positional byte-overlap fallback instead.
    Overflow,
}

impl SimTokens {
    fn from_normalized(s: &str) -> Self {
        use std::hash::{Hash, Hasher};
        if s.len() > u32::MAX as usize {
            return SimTokens::Overflow;
        }
        let mut toks = Vec::with_capacity(16);
        for tok in s.split_whitespace() {
            if toks.len() == MAX_SIMILARITY_TOKENS {
                return SimTokens::Overflow;
            }
            // split_whitespace yields subslices of `s`, so the offset is
            // recoverable from pointer distance.
            let start = tok.as_ptr() as usize - s.as_ptr() as usize;
            let mut hasher = ahash::AHasher::default();
            tok.hash(&mut hasher);
            toks.push(SimTok {
                hash: hasher.finish(),
                start: start as u32,
                end: (start + tok.len()) as u32,
            });
        }
        let mut sorted_hashes: Vec<u64> = toks.iter().map(|t| t.hash).collect();
        sorted_hashes.sort_unstable();
        SimTokens::Tokens {
            toks,
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
            sim_cache: std::sync::OnceLock::new(),
        }
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
