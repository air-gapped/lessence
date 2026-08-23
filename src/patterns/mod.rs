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
