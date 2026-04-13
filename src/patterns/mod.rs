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
