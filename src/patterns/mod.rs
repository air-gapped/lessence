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

#[derive(Debug, Clone)]
pub struct LogLine {
    pub original: String,
    pub normalized: String,
    pub tokens: Vec<Token>,
    pub hash: u64,
}

impl LogLine {}

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
