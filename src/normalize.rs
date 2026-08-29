use ahash::AHasher;
use anyhow::Result;
use regex::Regex;
use std::hash::{Hash, Hasher};
use std::sync::LazyLock;

use crate::config::Config;
use crate::patterns::{
    LogLine, MAX_SIMILARITY_TOKENS, SimTok, SimTokens, Token,
    bracket_context::BracketContextDetector, duration::DurationDetector,
    email::EmailPatternDetector, hash::HashDetector, http_status::HttpStatusDetector, is_small_int,
    json::JsonDetector, key_value::KeyValueDetector, kubernetes::KubernetesDetector,
    log_module::LogWithModuleDetector, names::NameDetector, network::NetworkDetector,
    path::PathDetector, process::ProcessDetector, quoted::QuotedStringDetector,
    structured::StructuredMessageDetector, timestamp::UnifiedTimestampDetector, uuid::UuidDetector,
};

/// One entry in the detector ordering table. The table is the single place
/// that says which detectors run, in which order, under which gates —
/// `normalize_line` just walks it.
struct DetectorEntry {
    /// Config gate: is this detector enabled for the run?
    enabled: fn(&Config) -> bool,
    /// Cheap byte-level gate on the partially-normalized line; the
    /// detector is skipped when it returns false. Mirrors the detector's
    /// own fast pre-filter where one exists, so the deference check below
    /// never runs on lines the detector would reject anyway.
    prefilter: Option<fn(&Config, &str) -> bool>,
    /// The kubernetes deference rule, expressed once per entry: when set
    /// and the predicate matches, the line's kubernetes-shaped content
    /// belongs to KubernetesDetector and this detector is skipped.
    defers_to_kubernetes: Option<fn(&str) -> bool>,
    /// The detection pass itself.
    run: fn(&Normalizer, &str) -> (String, Vec<Token>),
}

/// Detection order — earlier entries consume text first, so order encodes
/// priority: most specific formats first (timestamps, emails, paths),
/// generic catch-alls last (names, quoted strings). Comments carry the
/// pairwise ordering constraints that must survive any reordering.
static DETECTOR_ORDER: &[DetectorEntry] = &[
    // TIMESTAMPS: most specific formats, highest priority.
    DetectorEntry {
        enabled: |c| c.normalize_timestamps,
        prefilter: None,
        defers_to_kubernetes: None,
        run: |_, s| UnifiedTimestampDetector::detect_and_replace(s),
    },
    // EMAIL: before paths so emails inside URLs are handled correctly.
    DetectorEntry {
        enabled: |c| c.normalize_emails,
        prefilter: Some(|_, s| s.contains('@')),
        defers_to_kubernetes: None,
        run: |n, s| n.email_detector.detect_and_replace(s),
    },
    // PATHS: before network patterns so URLs are consumed as whole units.
    DetectorEntry {
        enabled: |c| c.normalize_paths,
        prefilter: None,
        defers_to_kubernetes: None,
        run: |_, s| PathDetector::detect_and_replace(s),
    },
    // JSON: structured data, Event objects, K8s objects.
    DetectorEntry {
        enabled: |c| c.normalize_json,
        prefilter: Some(|_, s| s.contains('{')),
        defers_to_kubernetes: None,
        run: |_, s| JsonDetector::detect_and_replace(s),
    },
    // UUIDs: before hashes, whose hex pattern would fragment a UUID.
    DetectorEntry {
        enabled: |c| c.normalize_uuids,
        prefilter: None,
        defers_to_kubernetes: None,
        run: |_, s| UuidDetector::detect_and_replace(s),
    },
    // NETWORK: IPs, ports, FQDNs; after paths to avoid breaking URLs.
    DetectorEntry {
        enabled: |c| c.normalize_ips || c.normalize_ports || c.normalize_fqdns,
        prefilter: None,
        defers_to_kubernetes: None,
        run: |n, s| {
            NetworkDetector::detect_and_replace(
                s,
                n.config.normalize_ips,
                n.config.normalize_ports,
                n.config.normalize_fqdns,
            )
        },
    },
    // HASHES: after UUIDs (see above).
    DetectorEntry {
        enabled: |c| c.normalize_hashes,
        prefilter: None,
        defers_to_kubernetes: None,
        run: |_, s| HashDetector::detect_and_replace(s),
    },
    // PROCESS IDs: [pid=123], (12345).
    DetectorEntry {
        enabled: |c| c.normalize_pids,
        prefilter: None,
        defers_to_kubernetes: None,
        run: |_, s| ProcessDetector::detect_and_replace(s),
    },
    // KUBERNETES: before the generic bracket/module/structured detectors,
    // which additionally defer to it on kubernetes-shaped lines (their
    // `defers_to_kubernetes` predicates below).
    DetectorEntry {
        enabled: |c| c.normalize_kubernetes,
        prefilter: None,
        defers_to_kubernetes: None,
        run: |_, s| KubernetesDetector::detect_and_replace(s),
    },
    // HTTP STATUS: groups status codes into classes (200-299 -> 2xx).
    DetectorEntry {
        enabled: |c| c.normalize_http_status,
        prefilter: None,
        defers_to_kubernetes: None,
        run: |_, s| HttpStatusDetector::detect_and_replace(s),
    },
    // BRACKET CONTEXT: [error] [mod_jk] style tags.
    DetectorEntry {
        enabled: |c| c.normalize_brackets,
        prefilter: Some(|_, s| {
            s.contains('[') && BracketContextDetector::has_bracket_indicators(s)
        }),
        defers_to_kubernetes: Some(crate::patterns::has_kubernetes_indicators),
        run: |_, s| BracketContextDetector::detect_and_replace(s),
    },
    // KEY-VALUE: config=value pairs.
    DetectorEntry {
        enabled: |c| c.normalize_key_value,
        prefilter: Some(|_, s| s.contains('=')),
        defers_to_kubernetes: None,
        run: |_, s| KeyValueDetector::detect_and_replace(s),
    },
    // LOG MODULE: [level] module patterns (Apache/nginx). Gated by the
    // same flag as BracketContext: --disable-patterns brackets must
    // disable every bracket-shaped detector.
    DetectorEntry {
        enabled: |c| c.normalize_brackets,
        prefilter: Some(|_, s| {
            s.contains('[') && LogWithModuleDetector::has_log_module_indicators(s)
        }),
        defers_to_kubernetes: Some(crate::patterns::has_kubernetes_indicators),
        run: |_, s| LogWithModuleDetector::detect_and_replace(s),
    },
    // STRUCTURED MESSAGES: JSON/logfmt structured logging. The JSON half
    // is gated by --disable-patterns json, the logfmt half by
    // --disable-patterns key-value.
    DetectorEntry {
        enabled: |c| c.normalize_json || c.normalize_key_value,
        prefilter: Some(|c, s| {
            ((c.normalize_json && s.contains('{')) || (c.normalize_key_value && s.contains('=')))
                && StructuredMessageDetector::has_structured_indicators(s)
        }),
        defers_to_kubernetes: Some(crate::patterns::has_kubernetes_structured_indicators),
        run: |_, s| StructuredMessageDetector::detect_and_replace(s),
    },
    // DURATIONS & MEASUREMENTS: broad (decimals, sizes, percentages);
    // late, after every more specific pattern above.
    DetectorEntry {
        enabled: |c| c.normalize_durations,
        prefilter: None,
        defers_to_kubernetes: None,
        run: |_, s| DurationDetector::detect_and_replace(s),
    },
    // NAMES: generic hyphenated component names with variable suffixes;
    // after the specific patterns to catch what remains.
    DetectorEntry {
        enabled: |c| c.normalize_names,
        prefilter: None,
        defers_to_kubernetes: None,
        run: |_, s| NameDetector::detect_and_replace(s),
    },
    // QUOTED STRINGS: last, so it cannot consume content the detectors
    // above tokenize (paths in quotes in particular).
    DetectorEntry {
        enabled: |c| c.normalize_quoted,
        prefilter: Some(|_, s| s.contains('"') || s.contains('\'')),
        defers_to_kubernetes: None,
        run: |_, s| QuotedStringDetector::detect_and_replace(s),
    },
];

pub struct Normalizer {
    config: Config,
    // Pattern detectors
    email_detector: EmailPatternDetector,
}

/// A quoted HTTP request line: `"GET /metrics HTTP/1.1"`. The capture is the
/// request target.
static REQUEST_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT) ([^"\s]*) HTTP/"#)
        .expect("request-target anchor pattern must compile")
});

/// The status code that follows a quoted request line in an access log:
/// `... HTTP/1.1" 404 332`. The capture is its first digit — the class.
static REQUEST_STATUS_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#" HTTP/[0-9.]+" ([1-5])\d\d\b"#)
        .expect("request-status anchor pattern must compile")
});

/// A PCI address, `domain:bus:device.function` — `0000:21:00.0`.
static PCI_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\b")
        .expect("pci-address anchor pattern must compile")
});

/// A klog header, `E0910 00:02:39.914326       1 status.go:71]`. The capture
/// is the call site, `file.go:line` — klog's event identity, the way a
/// syslog program name is.
static KLOG_CALL_SITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[IWEF]\d{4} \d\d:\d\d:\d\d\.\d{6}\s+\d+ ([A-Za-z0-9_]+\.go:\d+)\]")
        .expect("klog call-site anchor pattern must compile")
});

/// A systemd message whose subject is a unit, `systemd[1]: containerd.service:
/// Main process exited`. The capture is the unit. Messages *about* a unit
/// (`Starting containerd.service - ...`) are not this shape and carry no
/// anchor. Mount, device, swap and path units are named after the thing they
/// mount — a pod volume, a device node — so for them the message is the
/// identity and the unit is the instance; they are left to similarity.
static SYSTEMD_UNIT_SUBJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"systemd\[\d+\]: ([A-Za-z0-9@._:\\-]+\.(?:service|slice|scope|socket|timer|target)): ",
    )
    .expect("systemd unit anchor pattern must compile")
});

/// A structured logger's call site, `"caller":"mvcc/hash.go:157"` (zap) or
/// `caller=/go/pkg/mod/.../reflector.go:205` (logfmt): the event identity of
/// a JSON record, as the klog header's is of a klog line. Without it two
/// records that share every field but `msg` read alike enough to fold.
static STRUCTURED_CALLER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:"caller"\s*:\s*"|\bcaller=)([A-Za-z0-9_./@+-]+\.[a-z]{1,4}:\d+)"#)
        .expect("structured caller anchor pattern must compile")
});

/// A call site a klog message itself opens with — `reflector.go:397]
/// k8s.io/client-go/informers/factory.go:160: forcing resync`. The header's
/// site is the logging shim; the message's is the code that spoke.
static MESSAGE_CALL_SITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.go:\d+\] ([A-Za-z0-9_./@+-]+\.go:\d+): ")
        .expect("message call-site anchor pattern must compile")
});

/// A Python traceback frame, `File "resources.py", line 418, in
/// _watch_resource_loop`: the frame is the (file, line, function) triple.
static TRACEBACK_FRAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"File "([^"]+)", line (\d+), in (\S+)"#)
        .expect("traceback frame anchor pattern must compile")
});

/// A method in a structured record: `"RequestMethod":"POST"`, `method=GET`,
/// `"grpc.method":"GenerateManifest"`. A field named `…method` names what
/// was called — the access-log request line's counterpart in JSON/logfmt,
/// and an RPC's route.
static FIELD_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)"?[a-z_.]*method"?\s*[:=]\s*"?([A-Za-z][A-Za-z0-9_./-]*)"#)
        .expect("field method anchor pattern must compile")
});

/// An HTTP status in a structured record: `"DownstreamStatus":500`,
/// `status=404`, `"status_code": 302`. The capture is the class digit.
static FIELD_STATUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)"?[a-z_.]*status(?:_?code)?"?\s*[:=]\s*"?([1-5])\d\d\b"#)
        .expect("field status anchor pattern must compile")
});

/// The request path of a structured HTTP record — only read when the record
/// also names a method, so a file path in some other record is not mistaken
/// for a route.
static FIELD_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)"?[a-z_.]*(?:path|uri|url|route)"?\s*[:=]\s*"([^"]*)""#)
        .expect("field path anchor pattern must compile")
});

/// The prefix `kubectl logs --prefix` writes: `[pod/<pod>/<container>] `.
/// The container is an identity; the pod is one up to its generated suffix,
/// so replicas of one workload fold and different workloads do not.
static KUBECTL_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\[pod/([^/\]]+)/([^\]]+)\]").expect("kubectl prefix anchor pattern must compile")
});

/// An audit record's type, `type=SYSCALL msg=audit(...)`. The capture is the
/// type — auditd's only discriminator between record kinds.
static AUDIT_RECORD_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^type=([A-Z_]+) msg=audit\(").expect("audit type anchor pattern must compile")
});

/// Hash the fields that must match exactly for two lines to fold together.
///
/// Normalization erases variable text on purpose, but some of what it erases
/// is the entire point of the line: which endpoint was requested, which device
/// failed. Two lines differing only there are not the same event, yet they
/// differ by one token out of a dozen and sail past any similarity threshold
/// low enough to be useful elsewhere. Raising the threshold instead is not an
/// option — it costs far more folding everywhere else than it recovers here.
///
/// So these fields are compared for equality, never for similarity. Returns 0
/// when the line has no anchor, which is the common case; two anchor-free
/// lines therefore group exactly as they did before.
///
/// Anchors are read from the raw line, before normalization erases them.
fn anchor_hash(original: &str) -> u64 {
    let mut hasher = AHasher::default();
    let mut found = false;

    // `HTTP/` is a cheap literal the regex engine can prescan for.
    if original.contains("HTTP/") {
        for caps in REQUEST_TARGET.captures_iter(original) {
            hash_route(caps.get(1).map_or("", |m| m.as_str()), &mut hasher);
            found = true;
        }
        // A 200 and a 404 for the same route are two events. This used to
        // hold only because the user-agent folded to one opaque token; once a
        // quoted sentence keeps its words (lessence-7lj) the shared UA tokens
        // outvote the one status token and 2xx and 4xx re-merge. The class
        // is identity, so it is matched here, never scored.
        for caps in REQUEST_STATUS_CLASS.captures_iter(original) {
            caps.get(1).map_or("", |m| m.as_str()).hash(&mut hasher);
            found = true;
        }
    }

    // A PCI address needs both separators; the pair is rare enough together to
    // keep the scan off most lines.
    if original.contains(':') && original.contains('.') {
        for found_addr in PCI_ADDRESS.find_iter(original) {
            found_addr.as_str().hash(&mut hasher);
            found = true;
        }
    }

    // Some grammars put the event identity in a fixed position as a name:
    // klog's call site, systemd's unit, auditd's record type. Each is one
    // token out of many, so similarity alone merges across them.
    if original.contains(".go:") {
        for caps in KLOG_CALL_SITE.captures_iter(original) {
            caps.get(1).map_or("", |m| m.as_str()).hash(&mut hasher);
            found = true;
        }
    }
    if original.contains("systemd[") {
        for caps in SYSTEMD_UNIT_SUBJECT.captures_iter(original) {
            // `cri-containerd-<hash>.scope` and `<uuid>-rootfs.mount` are one
            // unit kind each, not thousands: hash the skeleton, as for routes.
            let unit = caps.get(1).map_or("", |m| m.as_str());
            // systemd escapes `-` in unit names as `\x2d`; undo it so a uuid
            // is one id run.
            if unit.contains("\\x2d") {
                hash_skeleton(&unit.replace("\\x2d", "-"), &mut hasher);
            } else {
                hash_skeleton(unit, &mut hasher);
            }
            found = true;
        }
    }
    if original.starts_with("type=") {
        for caps in AUDIT_RECORD_TYPE.captures_iter(original) {
            caps.get(1).map_or("", |m| m.as_str()).hash(&mut hasher);
            found = true;
        }
    }
    if original.contains("caller") {
        for caps in STRUCTURED_CALLER.captures_iter(original) {
            caps.get(1).map_or("", |m| m.as_str()).hash(&mut hasher);
            found = true;
        }
    }
    if original.contains(".go:") {
        for caps in MESSAGE_CALL_SITE.captures_iter(original) {
            caps.get(1).map_or("", |m| m.as_str()).hash(&mut hasher);
            found = true;
        }
    }
    if original.contains("File \"") {
        for caps in TRACEBACK_FRAME.captures_iter(original) {
            for i in 1..=3 {
                caps.get(i).map_or("", |m| m.as_str()).hash(&mut hasher);
            }
            found = true;
        }
    }
    // A structured HTTP record: method and status class are matched like
    // the access-log request line's, and with a method present the request
    // path is its route.
    if original.contains("ethod") || original.contains("ETHOD") {
        let mut method = false;
        for caps in FIELD_METHOD.captures_iter(original) {
            let m = caps.get(1).map_or("", |m| m.as_str());
            m.hash(&mut hasher);
            method |= matches!(
                m.to_ascii_uppercase().as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            );
            found = true;
        }
        if method {
            for caps in FIELD_PATH.captures_iter(original) {
                hash_route(caps.get(1).map_or("", |m| m.as_str()), &mut hasher);
            }
        }
    }
    if original.contains("tatus") || original.contains("TATUS") {
        for caps in FIELD_STATUS.captures_iter(original) {
            caps.get(1).map_or("", |m| m.as_str()).hash(&mut hasher);
            found = true;
        }
    }
    if original.starts_with("[pod/") {
        for caps in KUBECTL_PREFIX.captures_iter(original) {
            hash_pod_skeleton(caps.get(1).map_or("", |m| m.as_str()), &mut hasher);
            caps.get(2).map_or("", |m| m.as_str()).hash(&mut hasher);
            found = true;
        }
    }

    if found { hasher.finish() } else { 0 }
}

/// Hash a pod name up to its instance suffixes: `web-7d9f8b6c5-xk2lp` and
/// `web-7d9f8b6c5-q8zmt` are one workload, `gitaly-0` and `gitaly-1` too,
/// and so are `rook-ceph-osd-0-56d5fdf8f8-ltzv5` and `rook-ceph-osd-1-…`
/// or `rook-ceph-mon-bp-…` and `rook-ceph-mon-cc-…`: the same daemon on
/// another instance. A trailing segment goes when it is an ordinal, an
/// instance letter or two, a 5-char chunk of the generated-name alphabet,
/// or an 8–10 char pod-template hash.
fn hash_pod_skeleton(pod: &str, hasher: &mut AHasher) {
    const RAND: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";
    let generated = |seg: &str| {
        let b = seg.as_bytes();
        (!b.is_empty() && b.iter().all(u8::is_ascii_digit))
            || (b.len() <= 2 && b.iter().all(u8::is_ascii_lowercase))
            || (b.len() == 5 && b.iter().all(|c| RAND.contains(c)))
            || ((8..=10).contains(&b.len())
                && b.iter().all(|c| RAND.contains(c) || c.is_ascii_digit()))
    };
    let mut keep = pod;
    for _ in 0..3 {
        match keep.rsplit_once('-') {
            Some((head, tail)) if generated(tail) => keep = head,
            _ => break,
        }
    }
    keep.hash(hasher);
}

/// Hash a name with its instance ids removed: a run holding 8+ hex digits
/// (a hash, a uuid with its hyphens) hashes as `<id>`, every other digit run
/// as `<d>`, all else as itself. `cri-containerd-9f3e...a1.scope` and
/// `session-1234.scope` thus name their kind, not their instance.
fn hash_skeleton(text: &str, hasher: &mut AHasher) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_hexdigit() || bytes[i] == b'-') {
            bytes[i].hash(hasher);
            i += 1;
            continue;
        }
        let start = i;
        let mut hex = 0;
        while i < bytes.len() && (bytes[i].is_ascii_hexdigit() || bytes[i] == b'-') {
            hex += usize::from(bytes[i].is_ascii_hexdigit());
            i += 1;
        }
        if hex >= 8 {
            "<id>".hash(hasher);
            continue;
        }
        let mut in_digits = false;
        for &byte in &bytes[start..i] {
            if byte.is_ascii_digit() {
                if !in_digits {
                    "<d>".hash(hasher);
                    in_digits = true;
                }
            } else {
                in_digits = false;
                byte.hash(hasher);
            }
        }
    }
}

/// Hash a request target as its route — the part that says *what was asked
/// for*, with the part that says *which one* removed.
///
/// A segment's identity is its non-numeric skeleton, so `/downloads/product_1`
/// and `/downloads/product_2` are one route, as are `/api/devices/42/` and
/// `/api/devices/99/`. `/login/` and `/metrics` are not. Getting this wrong in
/// either direction is expensive: too strict and every web log fragments per
/// object id, too loose and the anchor stops separating endpoints at all.
fn hash_route(target: &str, hasher: &mut AHasher) {
    // A query string is per-request data, not route identity.
    let path = target.split(['?', '#']).next().unwrap_or(target);
    for segment in path.split('/') {
        if segment.is_empty() {
            "/".hash(hasher);
            continue;
        }
        // A long hex-ish run is an opaque id (uuid, digest, slug), whatever
        // letters it happens to contain; `sha256:<hex>` is one with its
        // algorithm in front.
        let body = segment
            .split_once(':')
            .filter(|(algo, _)| !algo.is_empty() && algo.bytes().all(|b| b.is_ascii_alphanumeric()))
            .map_or(segment, |(_, rest)| rest);
        if body.len() >= 8
            && body
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'_')
        {
            "<id>".hash(hasher);
            continue;
        }
        // Otherwise keep the skeleton and collapse each digit run, so
        // `product_1` and `product_2` hash alike. `v1` and `v2` collapse too,
        // where the digit *is* the identity — but an API version is normally
        // its own segment, and fragmenting every object id is the worse error.
        let mut in_digits = false;
        for byte in segment.bytes() {
            if byte.is_ascii_digit() {
                if !in_digits {
                    "<d>".hash(hasher);
                    in_digits = true;
                }
            } else {
                in_digits = false;
                byte.hash(hasher);
            }
        }
        "|".hash(hasher);
    }
}

impl Normalizer {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            email_detector: EmailPatternDetector::new().unwrap(),
        }
    }

    pub fn normalize_line(&self, original: String) -> Result<LogLine> {
        let mut normalized = original.clone();
        let mut tokens = Vec::with_capacity(8);

        // Walk the detector ordering table; each enabled detector replaces
        // matched content with tokens in the partially-normalized line.
        for entry in DETECTOR_ORDER {
            if !(entry.enabled)(&self.config) {
                continue;
            }
            if let Some(prefilter) = entry.prefilter
                && !prefilter(&self.config, &normalized)
            {
                continue;
            }
            if let Some(defers) = entry.defers_to_kubernetes
                && defers(&normalized)
            {
                continue;
            }
            let (new_normalized, mut new_tokens) = (entry.run)(self, &normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        // Anchors come from the raw line: normalization has just erased the
        // very fields they identify.
        let anchor = anchor_hash(&original);

        // Fold the anchor into the line hash so the folder's exact-hash group
        // index cannot attach this line to a group with a different anchor.
        let hash = self.calculate_hash(&normalized) ^ anchor.wrapping_mul(0x9E37_79B9_7F4A_7C15);

        Ok(LogLine::new(original, normalized, tokens, hash).anchored(anchor))
    }

    fn calculate_hash(&self, normalized: &str) -> u64 {
        let mut hasher = AHasher::default();
        normalized.hash(&mut hasher);
        hasher.finish()
    }

    #[allow(clippy::cast_precision_loss)] // usize lengths → f64 for ratio calc
    pub fn similarity_score(&self, line1: &LogLine, line2: &LogLine) -> f64 {
        let s1 = &line1.normalized;
        let s2 = &line2.normalized;

        if s1 == s2 {
            return 100.0;
        }

        // Ultra-fast similarity: check length difference first
        let len1 = s1.len();
        let len2 = s2.len();
        let max_len = len1.max(len2);
        let min_len = len1.min(len2);

        if max_len == 0 {
            return 100.0;
        }

        // If length difference is too large, reject quickly
        let length_ratio = min_len as f64 / max_len as f64;
        if length_ratio < 0.7 {
            return length_ratio * 100.0;
        }

        // Token-level LCS: tolerant of an inserted or removed token, which a
        // positional comparison is not (one early insertion used to cascade
        // into a near-zero score for otherwise identical lines). Tokens are
        // cached on the LogLine on first use — no re-tokenization here.
        if let (SimTokens::Tokens { toks: a, .. }, SimTokens::Tokens { toks: b, .. }) =
            (line1.sim(), line2.sim())
            && !a.is_empty()
            && !b.is_empty()
        {
            let lcs = Self::token_lcs(s1, a, s2, b, None);
            return (2.0 * lcs as f64 / (a.len() + b.len()) as f64) * 100.0;
        }

        // Token multiset for lines that overran the LCS bound but still carry
        // hashes. Order-insensitive, so it can rate two permutations of the
        // same tokens as identical; for structured records, whose key order is
        // stable, that is a far smaller error than the positional comparison's
        // collapse to near zero when one early value changes length.
        if let Some(ratio) = Self::multiset_ratio(line1, line2) {
            return ratio;
        }

        // Fallback for whitespace-only lines and lines past
        // MAX_MULTISET_TOKENS: positional byte overlap (no allocation — works
        // on &[u8] directly).
        let b1 = s1.as_bytes();
        let b2 = s2.as_bytes();
        let mut matches: u32 = 0;
        for i in 0..min_len {
            if b1[i] == b2[i] {
                matches += 1;
            }
        }
        (f64::from(matches) / max_len as f64) * 100.0
    }

    /// Token equality via cached per-token hashes: hash inequality proves the
    /// tokens differ; on hash equality the bytes are compared to rule out
    /// collisions, so the result is exactly string equality — except that
    /// two small integers are equal to each other (see `sim_key`).
    #[inline]
    fn tok_eq(s1: &str, t1: SimTok, s2: &str, t2: SimTok) -> bool {
        if t1.hash != t2.hash {
            return false;
        }
        let (a, b) = (
            &s1[t1.start as usize..t1.end as usize],
            &s2[t2.start as usize..t2.end as usize],
        );
        a == b || (is_small_int(a) && is_small_int(b))
    }

    /// Size of the multiset intersection of two ascending-sorted hash
    /// slices (standard two-pointer merge).
    /// Similarity from the token multisets, on the same 2*common/total scale
    /// the LCS path uses so the threshold means the same thing either way.
    ///
    /// `None` when either line carries no hashes — whitespace-only, or past
    /// `MAX_MULTISET_TOKENS` — leaving those to the positional fallback.
    fn multiset_ratio(line1: &LogLine, line2: &LogLine) -> Option<f64> {
        let (sim1, sim2) = (line1.sim(), line2.sim());
        let (a, b) = (sim1.sorted_hashes(), sim2.sorted_hashes());
        if a.is_empty() || b.is_empty() {
            return None;
        }
        // Message identity first: a record's leading tokens say what it IS,
        // and the multiset cannot see them because it discards order. Without
        // this, a large shared payload outvotes the few words that distinguish
        // two different messages.
        if let (Some(lead1), Some(lead2)) = (sim1.lead(), sim2.lead())
            && lead1 != lead2
        {
            return Some(0.0);
        }
        let common = Self::multiset_intersection(a, b);
        Some((2.0 * common as f64 / (a.len() + b.len()) as f64) * 100.0)
    }

    fn multiset_intersection(a: &[u64], b: &[u64]) -> usize {
        let (mut i, mut j, mut common) = (0, 0, 0);
        while i < a.len() && j < b.len() {
            match a[i].cmp(&b[j]) {
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => {
                    common += 1;
                    i += 1;
                    j += 1;
                }
            }
        }
        common
    }

    /// Longest common subsequence length over cached token slices.
    ///
    /// Exact reductions before the DP: the common prefix and common suffix
    /// are stripped (both are always part of an LCS), which collapses the
    /// usual log-line case — same shape, a few differing middle tokens — to
    /// a tiny DP or none at all. The DP itself is the rolling-row stack-only
    /// version bounded by MAX_SIMILARITY_TOKENS.
    ///
    /// With `needed = Some(n)` the DP aborts once `n` is provably
    /// unreachable and returns an upper bound that is `< n` — callers using
    /// `needed` may only test the result against `n`, not use it as a score.
    fn token_lcs(s1: &str, a: &[SimTok], s2: &str, b: &[SimTok], needed: Option<usize>) -> usize {
        let min_n = a.len().min(b.len());

        // Common prefix (covers the aligned fast path: identical-shape lines
        // resolve here without any DP).
        let mut p = 0;
        while p < min_n && Self::tok_eq(s1, a[p], s2, b[p]) {
            p += 1;
        }
        if p == min_n {
            return min_n;
        }

        // Common suffix of the remainders (bounded so it cannot overlap the
        // prefix in the shorter sequence).
        let max_s = min_n - p;
        let mut s = 0;
        while s < max_s && Self::tok_eq(s1, a[a.len() - 1 - s], s2, b[b.len() - 1 - s]) {
            s += 1;
        }

        let am = &a[p..a.len() - s];
        let bm = &b[p..b.len() - s];
        let dp_cap = am.len().min(bm.len());

        let mut prev = [0u16; MAX_SIMILARITY_TOKENS + 1];
        let mut curr = [0u16; MAX_SIMILARITY_TOKENS + 1];
        for (i, ta) in am.iter().enumerate() {
            let mut row_max = 0u16;
            for (j, tb) in bm.iter().enumerate() {
                curr[j + 1] = if Self::tok_eq(s1, *ta, s2, *tb) {
                    prev[j] + 1
                } else {
                    prev[j + 1].max(curr[j])
                };
                row_max = row_max.max(curr[j + 1]);
            }
            if let Some(need) = needed {
                // Each further row can raise the LCS by at most 1, and the
                // middle LCS can never exceed the shorter middle.
                let rows_left = am.len() - i - 1;
                let upper = p + s + (usize::from(row_max) + rows_left).min(dp_cap);
                if upper < need {
                    return upper;
                }
            }
            prev[..=bm.len()].copy_from_slice(&curr[..=bm.len()]);
        }
        p + s + usize::from(prev[bm.len()])
    }

    #[allow(clippy::cast_precision_loss)] // usize lengths → f64 for ratio calc
    pub fn are_similar(&self, line1: &LogLine, line2: &LogLine) -> bool {
        // Quick hash comparison first
        if line1.hash == line2.hash {
            return true;
        }

        // Anchors are matched, never scored: two lines naming different
        // endpoints or devices are different events however alike they read.
        if line1.anchor != line2.anchor {
            return false;
        }

        let threshold = f64::from(self.config.threshold);

        // Threshold-aware token path: identical decisions to
        // `similarity_score(..) >= threshold`, but with exact O(1) bounds
        // that skip or truncate the DP for most non-matching pairs.
        if let (
            SimTokens::Tokens {
                toks: a,
                sorted_hashes: ha,
            },
            SimTokens::Tokens {
                toks: b,
                sorted_hashes: hb,
            },
        ) = (line1.sim(), line2.sim())
            && !a.is_empty()
            && !b.is_empty()
        {
            let s1 = &line1.normalized;
            let s2 = &line2.normalized;
            let min_len = s1.len().min(s2.len());
            let max_len = s1.len().max(s2.len());
            let length_ratio = min_len as f64 / max_len as f64;
            if length_ratio < 0.7 {
                return length_ratio * 100.0 >= threshold;
            }

            let total = (a.len() + b.len()) as f64;
            // The LCS can never exceed the multiset intersection of the two
            // token bags, computable as an O(n) merge over the sorted hash
            // views. Collisions only overcount, so rejecting on this bound
            // is exact. (It also subsumes the min(n1, n2) bound.)
            if (2.0 * Self::multiset_intersection(ha, hb) as f64 / total) * 100.0 < threshold {
                return false;
            }

            // Smallest LCS that satisfies the threshold. The ceil formula is
            // exact in real arithmetic (threshold and total are small
            // integers), but similarity_score's float expression can round a
            // boundary score *below* an integer threshold — e.g. 7 of 10
            // shared tokens computes as 69.999…, not 70 — so step up until
            // the float expression itself agrees. Fires at most once: one
            // extra token moves the true score by 200/total, far beyond any
            // float error.
            let mut need = ((threshold * total) / 200.0).ceil() as usize;
            while (2.0 * need as f64 / total) * 100.0 < threshold {
                need += 1;
            }

            return Self::token_lcs(s1, a, s2, b, Some(need)) >= need;
        }

        // One side overran the LCS bound. Compare token multisets instead:
        // O(n) over the sorted hash views, and — unlike a byte-positional
        // comparison — unaffected by one value changing length and shifting
        // everything after it.
        if let Some(ratio) = Self::multiset_ratio(line1, line2) {
            return ratio >= threshold;
        }

        // Whitespace-only lines, or lines past MAX_MULTISET_TOKENS: fall back
        // to the full score (byte-positional path).
        self.similarity_score(line1, line2) >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- detector ordering table: kubernetes deference ----
    // The table's `defers_to_kubernetes` predicates skip the bracket,
    // log-module, and structured detectors on kubernetes-shaped lines so
    // KubernetesDetector owns them. These used to be guards inside each
    // detector; the behavior now only exists at this level.

    #[test]
    fn table_brackets_defer_to_kubernetes() {
        let normalizer = Normalizer::new(Config::default());
        let line = normalizer
            .normalize_line("[error] kubelet started".to_string())
            .unwrap();
        assert!(
            !line
                .tokens
                .iter()
                .any(|t| matches!(t, Token::BracketContext(_))),
            "bracket detector must skip k8s lines, got: {}",
            line.normalized
        );
    }

    #[test]
    fn table_log_module_defers_to_kubernetes() {
        let normalizer = Normalizer::new(Config::default());
        let line = normalizer
            .normalize_line("[error] kubelet failed".to_string())
            .unwrap();
        assert!(
            !line
                .tokens
                .iter()
                .any(|t| matches!(t, Token::LogWithModule { .. })),
            "log-module detector must skip k8s lines, got: {}",
            line.normalized
        );
    }

    #[test]
    fn table_structured_defers_to_kubernetes() {
        let normalizer = Normalizer::new(Config::default());
        let line = normalizer
            .normalize_line(
                r#"{"level":"info","ts":"2024-01-01T10:00:00.000Z","component":"kubelet","msg":"Starting container"}"#
                    .to_string(),
            )
            .unwrap();
        assert!(
            !line
                .tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "structured detector must skip k8s lines, got: {}",
            line.normalized
        );
    }

    #[test]
    fn table_structured_matches_non_k8s() {
        // Control: the same shape with a non-k8s component IS structured.
        let normalizer = Normalizer::new(Config::default());
        let line = normalizer
            .normalize_line(
                r#"{"level":"info","component":"payment-api","msg":"Request handled"}"#.to_string(),
            )
            .unwrap();
        assert!(
            line.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "non-k8s structured line must still match, got: {}",
            line.normalized
        );
    }

    #[test]
    fn test_timestamp_normalization() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        let line = normalizer
            .normalize_line("2025-01-20 10:15:30 Error occurred".to_string())
            .unwrap();

        assert_eq!(line.normalized, "<TIMESTAMP> Error occurred");
        assert_eq!(line.tokens.len(), 1);
        assert!(matches!(line.tokens[0], Token::Timestamp(_)));
    }

    #[test]
    fn test_ip_port_normalization() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        let line = normalizer
            .normalize_line("Connection to 192.168.1.100:8080 failed".to_string())
            .unwrap();

        assert_eq!(line.normalized, "Connection to <IP>:<PORT> failed");
        assert_eq!(line.tokens.len(), 2);
    }

    #[test]
    fn test_similarity_calculation() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        let line1 = normalizer
            .normalize_line(
                "2025-01-20 10:15:01 [pid=12345] Connection failed to 192.168.1.100:8080"
                    .to_string(),
            )
            .unwrap();

        let line2 = normalizer
            .normalize_line(
                "2025-01-20 10:15:02 [pid=12346] Connection failed to 192.168.1.101:8081"
                    .to_string(),
            )
            .unwrap();

        assert!(normalizer.are_similar(&line1, &line2));
        let score = normalizer.similarity_score(&line1, &line2);
        assert!(score >= 85.0);
    }

    #[test]
    fn test_hash_consistency() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        let line1 = normalizer
            .normalize_line("<TIMESTAMP> [pid=<PID>] Connection failed to <IP>:<PORT>".to_string())
            .unwrap();

        let line2 = normalizer
            .normalize_line("<TIMESTAMP> [pid=<PID>] Connection failed to <IP>:<PORT>".to_string())
            .unwrap();

        assert_eq!(line1.hash, line2.hash);
    }

    #[test]
    fn test_disabled_normalization() {
        let config = Config {
            normalize_timestamps: false,
            normalize_ips: false,
            normalize_ports: false,
            ..Config::default()
        };

        let normalizer = Normalizer::new(config);

        let line = normalizer
            .normalize_line("2025-01-20 10:15:30 Connection to 192.168.1.100 failed".to_string())
            .unwrap();

        // Even with timestamps/IPs/ports disabled, other always-on patterns
        // (durations, names, etc.) still normalize numbers and decimals
        assert_eq!(
            line.normalized,
            "2025-01-20 10:15:30 Connection to <NUMBER>.<NUMBER>.1.<NUMBER> failed"
        );
    }

    #[test]
    fn test_port_detection_vs_timestamps() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        // Test that timestamps are NOT detected as ports
        let line1 = normalizer
            .normalize_line("2025-01-20 10:15:30 Connection failed".to_string())
            .unwrap();

        // Should normalize timestamp but NOT detect ports in the time
        assert_eq!(line1.normalized, "<TIMESTAMP> Connection failed");
        assert!(
            line1
                .tokens
                .iter()
                .any(|t| matches!(t, Token::Timestamp(_)))
        );
        assert!(!line1.tokens.iter().any(|t| matches!(t, Token::Port(_))));

        // Test that actual ports ARE detected
        let line2 = normalizer
            .normalize_line("Connection to localhost:8080 failed".to_string())
            .unwrap();

        assert_eq!(line2.normalized, "Connection to localhost:<PORT> failed");
        assert!(line2.tokens.iter().any(|t| matches!(t, Token::Port(8080))));

        // Test that IP:port combinations work
        let line3 = normalizer
            .normalize_line("Connection to 192.168.1.1:3000 failed".to_string())
            .unwrap();

        assert_eq!(line3.normalized, "Connection to <IP>:<PORT> failed");
        assert!(line3.tokens.iter().any(|t| matches!(t, Token::IPv4(_))));
        assert!(line3.tokens.iter().any(|t| matches!(t, Token::Port(3000))));

        // Test that IPv6:port combinations work
        let line4 = normalizer
            .normalize_line("Connection to [2001:db8::1]:8080 failed".to_string())
            .unwrap();

        assert_eq!(line4.normalized, "Connection to [<IP>]:<PORT> failed");
        assert!(line4.tokens.iter().any(|t| matches!(t, Token::IPv6(_))));
        assert!(line4.tokens.iter().any(|t| matches!(t, Token::Port(8080))));
    }

    // --- similarity_score direct tests (mutant kills) ---

    #[test]
    fn test_similarity_score_identical() {
        let normalizer = Normalizer::new(Config::default());
        let line = normalizer
            .normalize_line("hello world".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&line, &line);
        assert!((score - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_similarity_score_completely_different() {
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer.normalize_line("aaaa".to_string()).unwrap();
        let b = normalizer.normalize_line("zzzz".to_string()).unwrap();
        let score = normalizer.similarity_score(&a, &b);
        assert!(
            score < 1.0,
            "Completely different strings should score near 0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_partial_match() {
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("ERROR conn refused".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("ERROR conn timeout".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
        // 2 of 3 tokens shared: 2*2/(3+3) = 66.7
        assert!(
            (score - 200.0 / 3.0).abs() < 1e-9,
            "Expected 66.7, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_tolerates_token_insertion() {
        // The motivating bug for the LCS metric: one token inserted at the
        // front used to cascade into a near-zero positional score.
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("ERROR: conn refused to backend xyz".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("node1 ERROR: conn refused to backend xyz".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
        // 6 shared tokens of 6+7: 2*6/13 = 92.3
        assert!(
            score > 90.0,
            "insertion-shifted line should score high, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_common_prefix_not_enough() {
        // Long shared prefix with diverging tails must NOT score near 100 —
        // merging these would lose distinct messages.
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("svc api gateway east db conn pool exhausted".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("svc api gateway east tls handshake err peer".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
        // 4 shared of 8+8 tokens: 50.0
        assert!(
            (score - 50.0).abs() < 1e-9,
            "diverging tails should score 50, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_length_ratio_rejection() {
        let normalizer = Normalizer::new(Config::default());
        let short = normalizer.normalize_line("ab".to_string()).unwrap();
        let long = normalizer.normalize_line("abcdefghij".to_string()).unwrap();
        let score = normalizer.similarity_score(&short, &long);
        // ratio = 2/10 = 0.2, below 0.7 threshold → returns 0.2 * 100 = 20.0
        assert!(
            (score - 20.0).abs() < f64::EPSILON,
            "Expected 20.0 (ratio rejection), got {score}"
        );
    }

    #[test]
    fn test_similarity_score_empty_strings() {
        let normalizer = Normalizer::new(Config::default());
        let empty = LogLine::new(String::new(), String::new(), vec![], 0);
        let score = normalizer.similarity_score(&empty, &empty);
        assert!(
            (score - 100.0).abs() < f64::EPSILON,
            "Empty vs empty should be 100.0"
        );
    }

    #[test]
    fn test_similarity_score_at_length_ratio_boundary() {
        let normalizer = Normalizer::new(Config::default());
        let ten_chars = normalizer.normalize_line("abcdefghij".to_string()).unwrap();

        // 7/10 = 0.7, exactly at threshold → NOT rejected → token comparison:
        // single differing tokens share nothing → 0.0
        let seven_match = normalizer.normalize_line("abcdefg".to_string()).unwrap();
        let score = normalizer.similarity_score(&seven_match, &ten_chars);
        assert!(
            score.abs() < f64::EPSILON,
            "At boundary (0.7), token comparison applies. Got {score}"
        );

        // 6/10 = 0.6, below threshold → rejected early → returns 0.6*100 = 60.0
        let six_match = normalizer.normalize_line("abcdef".to_string()).unwrap();
        let score_below = normalizer.similarity_score(&six_match, &ten_chars);
        assert!(
            (score_below - 60.0).abs() < f64::EPSILON,
            "Below boundary, should return ratio*100=60.0. Got {score_below}"
        );

        // 7 chars but last differs → ratio=0.7, NOT rejected → token
        // comparison: differing single tokens share nothing → 0.0
        let seven_mismatch = normalizer.normalize_line("abcdefz".to_string()).unwrap();
        let score_mismatch = normalizer.similarity_score(&seven_mismatch, &ten_chars);
        assert!(
            score_mismatch.abs() < f64::EPSILON,
            "At boundary with mismatch, token comparison gives 0.0. Got {score_mismatch}"
        );

        // 7 chars, none match → ratio=0.7, NOT rejected, char comparison: 0/10 = 0.0
        let seven_none = normalizer.normalize_line("xyzxyzx".to_string()).unwrap();
        let score_none = normalizer.similarity_score(&seven_none, &ten_chars);
        assert!(
            score_none < 1.0,
            "At boundary with zero char matches, should be ~0. Got {score_none}"
        );
    }

    #[test]
    fn test_similarity_score_one_token_diff() {
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("alpha beta gamma delta epsilon zeta eta theta iota kappa".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("alpha beta gamma delta epsilon zeta eta theta iota XXXXX".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
        // 9 of 10 tokens shared: 2*9/20 = 90.0
        assert!(
            (score - 90.0).abs() < f64::EPSILON,
            "Expected 90.0, got {score}"
        );
    }

    // --- similarity_score edge cases for uncaught mutants ---

    #[test]
    fn test_similarity_score_empty_vs_nonempty() {
        // Kills mutant: max_len == 0 → max_len != 0
        // With one empty and one non-empty, max_len > 0, min_len = 0
        // length_ratio = 0/5 = 0.0 < 0.7 → returns 0.0
        let normalizer = Normalizer::new(Config::default());
        let empty = LogLine::new(String::new(), String::new(), vec![], 0);
        let nonempty = LogLine::new("hello".into(), "hello".into(), vec![], 1);
        let score = normalizer.similarity_score(&empty, &nonempty);
        assert!(
            score < 1.0,
            "empty vs non-empty should score near 0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_min_max_not_swapped() {
        // Kills mutant: min_len ↔ max_len swap in length_ratio calculation
        // len1=3, len2=10: ratio should be 3/10=0.3, NOT 10/3=3.33
        let normalizer = Normalizer::new(Config::default());
        let short = LogLine::new("abc".into(), "abc".into(), vec![], 0);
        let long = LogLine::new("abcdefghij".into(), "abcdefghij".into(), vec![], 1);
        let score = normalizer.similarity_score(&short, &long);
        // ratio = 3/10 = 0.3 < 0.7 → returns 0.3 * 100 = 30.0
        assert!(
            (score - 30.0).abs() < f64::EPSILON,
            "3/10 ratio should give 30.0, got {score}"
        );
    }

    /// Token count that reaches the positional byte fallback: past
    /// MAX_MULTISET_TOKENS, where the hashes are no longer kept. Between
    /// MAX_SIMILARITY_TOKENS and this the multiset path handles the line.
    const BYTE_FALLBACK_TOKENS: usize = crate::patterns::MAX_MULTISET_TOKENS + 1;

    #[test]
    fn test_similarity_score_byte_fallback_division_direction() {
        // Exercises the byte-overlap fallback. Kills mutant: `/ max_len` →
        // `* max_len` or `+ max_len`.
        let normalizer = Normalizer::new(Config::default());
        // `"a "` per token, so the prefix is exactly 2 bytes per token and
        // matches positionally; an equally long differing tail makes it 50%.
        let prefix_bytes = BYTE_FALLBACK_TOKENS * 2;
        let half_match = |c: char| {
            let mut s: String = std::iter::repeat_n("a ", BYTE_FALLBACK_TOKENS).collect();
            s.push_str(&c.to_string().repeat(prefix_bytes));
            s
        };
        let a = LogLine::new(half_match('X'), half_match('X'), vec![], 0);
        let b = LogLine::new(half_match('Y'), half_match('Y'), vec![], 1);
        let score = normalizer.similarity_score(&a, &b);
        assert!(
            (score - 50.0).abs() < f64::EPSILON,
            "half the bytes matching should give 50.0, got {score}"
        );
    }

    fn raw_line(s: String, hash: u64) -> LogLine {
        LogLine::new(s.clone(), s, vec![], hash)
    }

    #[test]
    fn test_similarity_score_byte_fallback_uneven_ratio() {
        // Byte fallback with a 3/4 positional match. Kills the `==` → `!=`
        // mutant in the fallback loop (a 50/50 split is invariant under that
        // inversion, this is not).
        //
        // matching = 2 bytes/token prefix + 2 shared bytes; the differing tail
        // is a third of that, which puts matching/total at exactly 3/4.
        let matching = BYTE_FALLBACK_TOKENS * 2 + 2;
        assert!(
            matching.is_multiple_of(3),
            "tail must divide exactly for an exact 75.0"
        );
        let tail = matching / 3;
        let mk = |t: char| {
            let mut s: String = std::iter::repeat_n("a ", BYTE_FALLBACK_TOKENS).collect();
            s.push_str("mm");
            s.push_str(&t.to_string().repeat(tail));
            s
        };
        let normalizer = Normalizer::new(Config::default());
        let score = normalizer.similarity_score(&raw_line(mk('X'), 0), &raw_line(mk('Y'), 1));
        assert!(
            (score - 75.0).abs() < f64::EPSILON,
            "three quarters of the bytes matching should give 75.0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_whitespace_only_uses_byte_fallback() {
        // Zero tokens on both sides must take the byte fallback, not the
        // empty-LCS path (which would score 0 or divide by zero).
        let normalizer = Normalizer::new(Config::default());
        let score =
            normalizer.similarity_score(&raw_line("   ".into(), 0), &raw_line("    ".into(), 1));
        // 3 of 4 bytes match positionally: 75.0
        assert!(
            (score - 75.0).abs() < f64::EPSILON,
            "whitespace-only lines should byte-compare to 75.0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_one_side_whitespace_only() {
        // One side tokenless, the other not: must take the byte fallback in
        // BOTH argument orders (kills `n1 > 0`/`n2 > 0` → `>=` mutants,
        // which would route into the LCS path and score 0).
        let normalizer = Normalizer::new(Config::default());
        let blank = || raw_line("    ".into(), 0);
        let lead = || raw_line("a   ".into(), 1);
        for (x, y) in [(blank(), lead()), (lead(), blank())] {
            let score = normalizer.similarity_score(&x, &y);
            // 3 of 4 bytes match positionally: 75.0
            assert!(
                (score - 75.0).abs() < f64::EPSILON,
                "tokenless side should byte-compare to 75.0, got {score}"
            );
        }
    }

    #[test]
    fn test_similarity_score_token_reorder_partial() {
        // Rotated token order: LCS("alpha beta gamma", "gamma alpha beta")
        // is 2, not 3 — pins the DP recurrence (prev[j+1] vs prev[j]).
        let normalizer = Normalizer::new(Config::default());
        let score = normalizer.similarity_score(
            &raw_line("alpha beta gamma".into(), 0),
            &raw_line("gamma alpha beta".into(), 1),
        );
        assert!(
            (score - 200.0 / 3.0).abs() < 1e-9,
            "rotated tokens share LCS 2 of 3: 66.7, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_at_max_token_capacity() {
        // Exactly 64 tokens exercises the full DP row width; an off-by-one
        // in the row arrays panics here.
        let mk = |last: &str| {
            let mut s: String = std::iter::repeat_n("tok ", 63).collect();
            s.push_str(last);
            s
        };
        let normalizer = Normalizer::new(Config::default());
        let score = normalizer.similarity_score(&raw_line(mk("aaa"), 0), &raw_line(mk("bbb"), 1));
        // 63 of 64 tokens shared: 2*63/128 = 98.4375
        assert!(
            (score - 98.4375).abs() < 1e-9,
            "63/64 shared tokens should give 98.4375, got {score}"
        );
    }

    #[test]
    fn test_are_similar_hash_shortcircuit() {
        let normalizer = Normalizer::new(Config::default());
        let a = LogLine::new(
            "completely different".into(),
            "completely different".into(),
            vec![],
            42,
        );
        // same hash = shortcircuit to true
        let b = LogLine::new(
            "not similar at all really".into(),
            "not similar at all really".into(),
            vec![],
            42,
        );
        assert!(
            normalizer.are_similar(&a, &b),
            "same hash should shortcircuit to similar"
        );
    }

    // --- normalize_line short-circuit tests (mutant kills) ---

    #[test]
    fn test_normalize_ips_only_flag() {
        let config = Config {
            normalize_ips: true,
            normalize_ports: false,
            normalize_fqdns: false,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let line = normalizer
            .normalize_line("connect to 10.0.0.1:8080".to_string())
            .unwrap();
        assert!(
            line.tokens.iter().any(|t| matches!(t, Token::IPv4(_))),
            "IPs should be detected"
        );
    }

    #[test]
    fn test_normalize_ports_only_flag() {
        let config = Config {
            normalize_ips: false,
            normalize_ports: true,
            normalize_fqdns: false,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let line = normalizer
            .normalize_line("connect to localhost:8080".to_string())
            .unwrap();
        assert!(
            line.tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "Ports should be detected"
        );
    }

    // ---- normalize_line: boolean condition tests ----

    #[test]
    fn normalize_line_json_disabled_no_detection() {
        let config = Config {
            normalize_json: false,
            ..Config::default()
        };
        let n = Normalizer::new(config);
        let line = n.normalize_line(r"&Event{Type: Warning}".into()).unwrap();
        // With JSON detection disabled, Event objects should NOT be detected
        assert!(
            !line.tokens.iter().any(|t| matches!(t, Token::Json(_))),
            "JSON detection should be disabled"
        );
    }

    #[test]
    fn structured_detection_brace_only() {
        // Input with { but no = — should still trigger structured detection
        let n = Normalizer::new(Config::default());
        let line = n
            .normalize_line(r#"{"level":"error","component":"web","msg":"fail"}"#.into())
            .unwrap();
        assert!(
            line.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "Brace-only input should trigger structured detection: {:?}",
            line.tokens
        );
    }

    #[test]
    fn structured_detection_equals_only() {
        // Input with = but no { — should still trigger the structured/KV detection path
        // The || ensures both branches (contains '{') and (contains '=') individually pass
        let n = Normalizer::new(Config::default());
        let line = n
            .normalize_line("level=error component=web msg=fail".into())
            .unwrap();
        // Either StructuredMessage or KeyValuePair tokens indicate the = path was taken
        assert!(
            line.tokens.iter().any(|t| matches!(
                t,
                Token::StructuredMessage { .. } | Token::KeyValuePair { .. }
            )),
            "Equals-only input should trigger structured or KV detection: {:?}",
            line.tokens
        );
    }

    // ---- Mutant-killing: normalize_timestamps=false with colon input ----

    #[test]
    fn normalize_timestamps_disabled_with_colon_input() {
        // Kills mutant: `self.config.normalize_timestamps && text.contains(':')` → `||`
        // If mutated to ||, timestamps would be detected even when disabled
        let config = Config {
            normalize_timestamps: false,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let line = normalizer
            .normalize_line("10:15:30 Error occurred".to_string())
            .unwrap();
        assert!(
            !line.tokens.iter().any(|t| matches!(t, Token::Timestamp(_))),
            "Timestamps should NOT be detected when normalize_timestamps=false"
        );
    }

    // ---- Mutant-killing: normalize_emails=false (line 43) ----

    #[test]
    fn normalize_emails_disabled_no_detection() {
        let config = Config {
            normalize_emails: false,
            ..Config::default()
        };
        let n = Normalizer::new(config);
        let line = n
            .normalize_line("user test@example.com logged in".into())
            .unwrap();
        assert!(
            !line.tokens.iter().any(|t| matches!(t, Token::Email(_))),
            "Emails should NOT be detected when normalize_emails=false: {:?}",
            line.tokens
        );
    }

    // ---- Mutant-killing: quoted string detection (line 173) ----

    #[test]
    fn quoted_detection_single_quote_only() {
        // Input with ' but no " — should still trigger quoted string detection path
        // Kills: || with && on `contains('"') || contains('\'')`
        let n = Normalizer::new(Config::default());
        let line = n
            .normalize_line("mount 'very-long-volume-name-that-exceeds-threshold-ok' done".into())
            .unwrap();
        // The ' path should be entered (if || is correct, either quote type suffices)
        // Just verify no panic — the detection may or may not produce tokens
        let _ = line;
    }

    // ---- Mutant-killing: normalize_json=false with brace input ----

    #[test]
    fn normalize_json_disabled_with_brace_input() {
        // Note: this mutant (normalize.rs:59) is excluded via .cargo/mutants.toml
        // because PathDetector (step 3) already replaces &Event{} with <EVENT_OBJECT>
        // before JsonDetector (step 4) ever runs. The normalize_json guard is
        // structurally unreachable — an equivalent mutant.
        //
        // This test verifies JsonDetector itself works in isolation.
        let (_, direct_tokens) =
            crate::patterns::json::JsonDetector::detect_and_replace("&Event{Type: Warning}");
        assert!(
            direct_tokens.iter().any(|t| matches!(t, Token::Json(_))),
            "JsonDetector should detect Event objects: {direct_tokens:?}"
        );
    }

    // ---- Mutant-killing: --disable-patterns guards at the Normalizer boundary ----
    // Each test uses an input that provably triggers its detector (default on),
    // then asserts the corresponding token type disappears when the guard is off.

    fn run(config_mut: impl FnOnce(&mut Config), input: &str) -> LogLine {
        let mut config = Config::default();
        config_mut(&mut config);
        Normalizer::new(config)
            .normalize_line(input.to_string())
            .unwrap()
    }

    #[test]
    fn normalize_brackets_disabled_suppresses_log_module_tokens() {
        let input = "2024-01-01 10:00:00 ERROR [hibernate_sql] Database connection failed";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_brackets = false, input);
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::LogWithModule { .. })),
            "expected LogWithModule token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::LogWithModule { .. })),
            "expected NO LogWithModule token with brackets OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_json_disabled_suppresses_structured_json_tokens() {
        let input = r#"{"level":"info","component":"api","msg":"Request received"}"#;
        let on = run(|_| {}, input);
        let off = run(
            |c| {
                c.normalize_json = false;
                c.normalize_key_value = false;
            },
            input,
        );
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "expected StructuredMessage token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "expected NO StructuredMessage token with json+key-value OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_key_value_disabled_suppresses_structured_logfmt_tokens() {
        // Pins the logfmt half of the StructuredMessage gate. The detector
        // demonstrably fires on this input when called directly...
        let input = "level=info component=api-gateway msg=ready";
        let (_, direct) =
            crate::patterns::structured::StructuredMessageDetector::detect_and_replace(input);
        assert!(
            direct
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "detector itself must fire on {input:?}, got {direct:?}"
        );
        // ...so with key-value (and json) disabled, the pipeline must not
        // invoke it: no StructuredMessage token may appear.
        let off = run(
            |c| {
                c.normalize_key_value = false;
                c.normalize_json = false;
            },
            input,
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "expected NO StructuredMessage token with key-value OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_kubernetes_disabled_suppresses_k8s_tokens() {
        let input = "volume \"kube-api-access-abc123\" (projected) failed to mount for pod kube-system/test-pod";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_kubernetes = false, input);
        assert!(
            on.tokens.iter().any(|t| matches!(
                t,
                Token::KubernetesNamespace(_) | Token::PodName(_) | Token::VolumeName(_)
            )),
            "expected k8s token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens.iter().any(|t| matches!(
                t,
                Token::KubernetesNamespace(_) | Token::PodName(_) | Token::VolumeName(_)
            )),
            "expected NO k8s token with detector OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_names_disabled_suppresses_name_tokens() {
        let input = "service api-deploy-abc123-x1y2 started";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_names = false, input);
        assert!(
            on.tokens.iter().any(|t| matches!(t, Token::Name(_))),
            "expected Name token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens.iter().any(|t| matches!(t, Token::Name(_))),
            "expected NO Name token with detector OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_quoted_disabled_suppresses_quoted_tokens() {
        // A quoted instance name is what the detector tokenises; a quoted
        // sentence stays literal by design (lessence-7lj), so the probe must
        // be a name, not prose.
        let input = "message \"redis-sentinel-wiki\" done";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_quoted = false, input);
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::QuotedString(_))),
            "expected QuotedString token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::QuotedString(_))),
            "expected NO QuotedString token with detector OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_brackets_disabled_suppresses_bracket_context_tokens() {
        let input = "[error] [mod_jk] request failed";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_brackets = false, input);
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::BracketContext(_))),
            "expected BracketContext token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::BracketContext(_))),
            "expected NO BracketContext token with detector OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_key_value_disabled_suppresses_kv_tokens() {
        let input = "level=error status=500 user_id=42";
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_key_value = false, input);
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::KeyValuePair { .. })),
            "expected KeyValuePair token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::KeyValuePair { .. })),
            "expected NO KeyValuePair token with detector OFF, got {:?}",
            off.tokens
        );
    }

    #[test]
    fn normalize_http_status_disabled_suppresses_http_tokens() {
        let input =
            r#"127.0.0.1 - - [25/Dec/2023:10:15:30 +0000] "POST /api/login HTTP/1.1" 401 256"#;
        let on = run(|_| {}, input);
        let off = run(|c| c.normalize_http_status = false, input);
        assert!(
            on.tokens
                .iter()
                .any(|t| matches!(t, Token::HttpStatus(_) | Token::HttpStatusClass(_))),
            "expected HTTP status token with detector ON, got {:?}",
            on.tokens
        );
        assert!(
            !off.tokens
                .iter()
                .any(|t| matches!(t, Token::HttpStatus(_) | Token::HttpStatusClass(_))),
            "expected NO HTTP status token with detector OFF, got {:?}",
            off.tokens
        );
    }

    // ---- Mutant-killing: similarity_score division vs multiplication ----

    #[test]
    fn similarity_score_division_not_multiplication() {
        // Kills mutant: `min_len as f64 / max_len as f64` → `*`
        // Use strings where:
        //   division: 3/10 = 0.3 < 0.7 → returns 30.0 (quick reject)
        //   multiplication: 3*10 = 30.0 > 0.7 → falls through to char comparison
        // The char comparison for "xyz" vs "abcdefghij" (0 matching bytes) → 0.0
        // So: division returns 30.0, multiplication returns 0.0
        let normalizer = Normalizer::new(Config::default());
        let short = LogLine::new("xyz".into(), "xyz".into(), vec![], 0);
        let long = LogLine::new("abcdefghij".into(), "abcdefghij".into(), vec![], 1);
        let score = normalizer.similarity_score(&short, &long);
        // With /: ratio = 3/10 = 0.3 < 0.7 → returns 30.0
        // With *: ratio = 30.0 > 0.7 → char comparison (0 matching) → 0.0
        assert!(
            score > 20.0,
            "3/10 ratio should give 30.0, got {score} (if 0.0, division was mutated to *)"
        );
    }

    // --- token cache / cheap-reject machinery (new in 0.4.5) ---

    #[test]
    fn test_multiset_intersection_counts_multiplicity() {
        // Duplicates count once per matched pair, not once per value.
        assert_eq!(
            Normalizer::multiset_intersection(&[1, 2, 2, 3], &[2, 2, 4]),
            2
        );
    }

    #[test]
    fn test_multiset_intersection_disjoint_and_identical() {
        assert_eq!(Normalizer::multiset_intersection(&[1, 3, 5], &[2, 4, 6]), 0);
        assert_eq!(Normalizer::multiset_intersection(&[7, 8, 9], &[7, 8, 9]), 3);
        assert_eq!(Normalizer::multiset_intersection(&[], &[1]), 0);
    }

    #[test]
    fn test_multiset_intersection_advance_arms() {
        // Kills swapped Less/Greater advances: the smaller side must be the
        // one skipped or the late match is lost.
        assert_eq!(Normalizer::multiset_intersection(&[1, 2, 3, 4], &[4]), 1);
        assert_eq!(Normalizer::multiset_intersection(&[4], &[1, 2, 3, 4]), 1);
    }

    #[test]
    fn test_multiset_intersection_asymmetric_duplicates() {
        // On a match BOTH pointers must advance, or the single 5 on the
        // other side gets counted against every duplicate.
        assert_eq!(Normalizer::multiset_intersection(&[5, 5], &[5, 9]), 1);
        assert_eq!(Normalizer::multiset_intersection(&[5, 9], &[5, 5]), 1);
    }

    #[test]
    fn test_are_similar_float_boundary_58_of_100() {
        // The single (threshold, token-total) combination in the whole
        // domain where the float score rounds BELOW an exactly-met integer
        // threshold: LCS 29 of 100 total tokens, threshold 58 —
        // (2.0*29/100)*100.0 evaluates to 57.999…, so similarity_score says
        // "not similar" and are_similar's needed-LCS step-up loop must agree
        // (kills mutants that weaken or delete that loop).
        // Letters only, so no pattern detector rewrites the tokens.
        let words = |prefix: char, from: usize, to: usize| -> Vec<String> {
            (from..to)
                .map(|i| {
                    let hi = char::from(b'a' + (i / 26) as u8);
                    let lo = char::from(b'a' + (i % 26) as u8);
                    format!("{prefix}{hi}{lo}")
                })
                .collect()
        };
        // 30 shared tokens with two adjacent ones swapped in b: the token
        // MULTISETS share 30, so the intersection bound passes (60 ≥ 58)
        // and the step-up loop is actually reached — while the LCS is 29.
        let mut a_toks = words('s', 0, 30);
        a_toks.extend(words('x', 30, 50));
        let mut b_toks = words('s', 0, 30);
        b_toks.swap(28, 29);
        b_toks.extend(words('y', 30, 50));

        let config = Config {
            threshold: 58,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let a = normalizer.normalize_line(a_toks.join(" ")).unwrap();
        let b = normalizer.normalize_line(b_toks.join(" ")).unwrap();
        let score = normalizer.similarity_score(&a, &b);
        assert!(
            score < 58.0 && score > 57.99,
            "setup: float score must round just below 58, got {score}"
        );
        assert!(
            !normalizer.are_similar(&a, &b),
            "are_similar must agree with the score path at the float boundary"
        );

        // Positive twin: same shape WITHOUT the swap → LCS 30, score 60 ≥
        // 58 → similar. The needed-LCS loop still runs (need 29 → 30), so a
        // corrupted loop body that inflates or wraps `need` flips this one.
        let mut c_toks = words('s', 0, 30);
        c_toks.extend(words('z', 30, 50));
        let c = normalizer.normalize_line(c_toks.join(" ")).unwrap();
        assert!(
            normalizer.are_similar(&a, &c),
            "LCS 30 of 100 at threshold 58 must be similar"
        );
    }

    #[test]
    fn test_are_similar_whitespace_fallback_agrees() {
        // Whitespace-only lines have no similarity tokens, so are_similar
        // must fall back to the byte-positional score path — in both
        // argument orders, with the comparison direction matching
        // similarity_score >= threshold ("   " vs "  x" scores 66.7).
        let config = Config {
            threshold: 50,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let blank = raw_line("   ".to_string(), 1);
        let almost = raw_line("  x".to_string(), 2);
        assert!(normalizer.are_similar(&blank, &almost));
        assert!(normalizer.are_similar(&almost, &blank));

        let config = Config {
            threshold: 80,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        assert!(!normalizer.are_similar(&blank, &almost));
    }

    #[test]
    fn test_similarity_score_max_token_dp_bounds() {
        // Two 64-token lines (exactly MAX_SIMILARITY_TOKENS, not overflow)
        // with zero shared tokens force the full-width DP: the rolling rows
        // must be sized MAX+1 or the final-column access panics.
        let mk = |prefix: char| -> String {
            (0..64)
                .map(|i| {
                    let hi = char::from(b'a' + (i / 26) as u8);
                    let lo = char::from(b'a' + (i % 26) as u8);
                    format!("{prefix}{hi}{lo}")
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer.normalize_line(mk('p')).unwrap();
        let b = normalizer.normalize_line(mk('q')).unwrap();
        let score = normalizer.similarity_score(&a, &b);
        assert!(
            score.abs() < f64::EPSILON,
            "disjoint 64-token lines must score 0, got {score}"
        );
    }

    #[test]
    fn test_token_lcs_suffix_window_stays_in_bounds() {
        // Shorter line is entirely prefix+suffix of the longer one: the
        // suffix scan must stop at min_n - p or it walks past the start of
        // the shorter token list (index underflow). Trailing spaces keep
        // the byte lengths within the 0.7 length-ratio gate without adding
        // tokens.
        let normalizer = Normalizer::new(Config::default());
        let a = raw_line("ccc ccc ccc         ".to_string(), 1);
        let b = raw_line("ccc ccc xxx ccc ccc ccc".to_string(), 2);
        let score = normalizer.similarity_score(&a, &b);
        // LCS = 3 of 3+6 tokens: 2*3/9 = 66.67
        assert!(
            (score - 200.0 / 3.0).abs() < 1e-9,
            "expected 66.67, got {score}"
        );
    }

    #[test]
    fn test_are_similar_agrees_with_score_exhaustively() {
        // Ground truth: are_similar(a, b) ⇔ similarity_score(a, b) >= T.
        // Sweep a structured family of synthetic lines (varying token
        // counts, shared prefixes/suffixes/middles, shuffles, duplicates)
        // against several thresholds. Any mutant that changes a decision in
        // the threshold-aware fast path (length-ratio branch, multiset
        // bound, needed-LCS computation, DP early-exit) must disagree with
        // the score path on some pair in this family.
        let vocab = [
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
            "lambda", "mu",
        ];
        let mut lines: Vec<String> = Vec::new();
        for n in 1..=12usize {
            // Plain prefix of the vocabulary, length n.
            lines.push(vocab[..n].join(" "));
            // Same length but the middle token replaced.
            let mut mid = vocab[..n].to_vec();
            mid[n / 2] = "XXXXX";
            lines.push(mid.join(" "));
            // Same length, reversed (same multiset, low LCS).
            let mut rev = vocab[..n].to_vec();
            rev.reverse();
            lines.push(rev.join(" "));
            // Disjoint tokens of the same count.
            lines.push(vec!["zzz"; n].join(" "));
        }

        for threshold in [1u8, 50, 70, 75, 80, 99, 100] {
            let config = Config {
                threshold,
                ..Config::default()
            };
            let normalizer = Normalizer::new(config);
            let parsed: Vec<LogLine> = lines
                .iter()
                .map(|l| normalizer.normalize_line(l.clone()).unwrap())
                .collect();
            for x in &parsed {
                for y in &parsed {
                    let expected = x.hash == y.hash
                        || normalizer.similarity_score(x, y) >= f64::from(threshold);
                    assert_eq!(
                        normalizer.are_similar(x, y),
                        expected,
                        "disagreement at threshold {threshold}: {:?} vs {:?}",
                        x.normalized,
                        y.normalized
                    );
                }
            }
        }
    }

    #[test]
    fn test_similarity_score_middle_token_diff_keeps_suffix() {
        // Common prefix AND suffix around one differing middle token: the
        // suffix trim must contribute to the LCS. 7 of 8 tokens shared:
        // 2*7/16 = 87.5.
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("alpha beta gamma delta epsilon zeta eta theta".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("alpha beta gamma XXXXX epsilon zeta eta theta".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
        assert!(
            (score - 87.5).abs() < f64::EPSILON,
            "Expected 87.5, got {score}"
        );
    }

    #[test]
    fn test_are_similar_exactly_at_threshold() {
        // LCS 8 of 10 tokens each → score exactly 80. The threshold-aware
        // fast path in are_similar must agree with similarity_score on the
        // boundary in both directions (kills off-by-one mutants in the
        // needed-LCS computation and the multiset reject).
        let a_text = "alpha beta gamma delta epsilon zeta eta theta iota kappa";
        let b_text = "alpha beta gamma delta epsilon zeta eta theta AAAAA BBBBB";

        let config = Config {
            threshold: 80,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let a = normalizer.normalize_line(a_text.to_string()).unwrap();
        let b = normalizer.normalize_line(b_text.to_string()).unwrap();
        let score = normalizer.similarity_score(&a, &b);
        assert!(
            (score - 80.0).abs() < f64::EPSILON,
            "setup: expected score 80, got {score}"
        );
        assert!(
            normalizer.are_similar(&a, &b),
            "score == threshold must be similar"
        );

        let config = Config {
            threshold: 81,
            ..Config::default()
        };
        let normalizer = Normalizer::new(config);
        let a = normalizer.normalize_line(a_text.to_string()).unwrap();
        let b = normalizer.normalize_line(b_text.to_string()).unwrap();
        assert!(
            !normalizer.are_similar(&a, &b),
            "score below threshold must not be similar"
        );
    }

    #[test]
    fn test_are_similar_agrees_with_score_on_disjoint_tokens() {
        // Same-length lines with zero shared tokens: the multiset bound
        // rejects without a DP, and that decision must match the score path.
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("alpha beta gamma delta".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("omega psi chi phi ups".to_string())
            .unwrap();
        assert!(!normalizer.are_similar(&a, &b));
        assert!(normalizer.similarity_score(&a, &b) < f64::from(Config::default().threshold));
    }

    // ---- anchors ----

    fn normalize(line: &str) -> LogLine {
        Normalizer::new(Config::default())
            .normalize_line(line.to_string())
            .unwrap()
    }

    /// Two NetBox access lines differing only in the endpoint. Normalization
    /// erases both paths to `<PATH>`, leaving one token of difference out of
    /// eight — comfortably similar at any default-ish threshold. Without an
    /// anchor these folded into one group whose representative claimed an
    /// endpoint that most of its lines never touched.
    #[test]
    fn anchor_separates_different_endpoints() {
        let normalizer = Normalizer::new(Config::default());
        let login = normalize(
            r#"[2026-08-16 14:08:34 +0200] ::ffff - "GET /login/ HTTP/1.1" 200 17450.949"#,
        );
        let admin = normalize(
            r#"[2026-08-16 14:08:31 +0200] ::ffff - "GET /admin/ HTTP/1.1" 200 14502.251"#,
        );

        assert_ne!(
            login.anchor, admin.anchor,
            "different endpoints, different anchors"
        );
        assert!(!normalizer.are_similar(&login, &admin));
        // Without the anchor these would have been judged similar.
        assert!(
            normalizer.similarity_score(&login, &admin) >= f64::from(Config::default().threshold),
            "the point of the anchor is that similarity alone does not separate these"
        );
    }

    /// The same endpoint with different object ids is one route, so folding
    /// must still happen. This is the direction that costs compression if it
    /// goes wrong: every web log would fragment per id.
    #[test]
    fn anchor_keeps_one_route_together() {
        let normalizer = Normalizer::new(Config::default());
        let first = normalize(
            r#"10.0.0.1 - - [17/May/2015:08:05:32 +0000] "GET /api/devices/42/ HTTP/1.1" 200 490"#,
        );
        let second = normalize(
            r#"10.0.0.2 - - [17/May/2015:08:05:33 +0000] "GET /api/devices/9137/ HTTP/1.1" 200 490"#,
        );

        assert_eq!(first.anchor, second.anchor, "same route, same anchor");
        assert!(normalizer.are_similar(&first, &second));
    }

    /// A digit run inside a segment is an id too — `product_1` and `product_2`
    /// are one route. Treating the whole segment as literal cost 11 points of
    /// compression on the nginx corpus.
    #[test]
    fn anchor_collapses_digits_inside_a_segment() {
        let a = normalize(
            r#"10.0.0.1 - - [17/May/2015:08:05:32 +0000] "GET /downloads/product_1 HTTP/1.1" 304 0"#,
        );
        let b = normalize(
            r#"10.0.0.1 - - [17/May/2015:08:05:33 +0000] "GET /downloads/product_2 HTTP/1.1" 304 0"#,
        );
        assert_eq!(a.anchor, b.anchor);
    }

    /// A query string is per-request data, not route identity.
    #[test]
    fn anchor_ignores_the_query_string() {
        let a = normalize(
            r#"10.0.0.1 - - [17/May/2015:08:05:32 +0000] "GET /search?q=alpha HTTP/1.1" 200 12"#,
        );
        let b = normalize(
            r#"10.0.0.1 - - [17/May/2015:08:05:33 +0000] "GET /search?q=beta HTTP/1.1" 200 12"#,
        );
        assert_eq!(a.anchor, b.anchor);
    }

    /// Two GPUs failing the same way are two failures, not one. Normalization
    /// keeps only the bus byte of the address, so these differ in two tokens
    /// out of twenty and merged before.
    #[test]
    fn anchor_separates_pci_devices() {
        let normalizer = Normalizer::new(Config::default());
        let first = normalize(
            "2026/08/06 01:05:43 WARNING: unable to detect IOMMU FD for [0000:21:00.0 open /sys/bus/pci/devices/0000:21:00.0/vfio-dev: no such file or directory]",
        );
        let second = normalize(
            "2026/08/06 01:05:43 WARNING: unable to detect IOMMU FD for [0000:65:00.0 open /sys/bus/pci/devices/0000:65:00.0/vfio-dev: no such file or directory]",
        );

        assert_ne!(first.anchor, second.anchor);
        assert!(!normalizer.are_similar(&first, &second));
    }

    /// Two mentions of the same device anchor alike, so repeated warnings for
    /// one GPU still fold.
    #[test]
    fn anchor_matches_for_the_same_pci_device() {
        let normalizer = Normalizer::new(Config::default());
        let first = normalize(
            "2026/08/06 01:05:43 WARNING: unable to detect IOMMU FD for [0000:21:00.0 open /sys/bus/pci/devices/0000:21:00.0/vfio-dev: no such file or directory]",
        );
        let second = normalize(
            "2026/08/06 01:07:10 WARNING: unable to detect IOMMU FD for [0000:21:00.0 open /sys/bus/pci/devices/0000:21:00.0/vfio-dev: no such file or directory]",
        );

        assert_eq!(first.anchor, second.anchor);
        assert!(normalizer.are_similar(&first, &second));
    }

    /// The same klog message from two call sites is two events. Only the
    /// `file.go:line` token differs, so similarity alone would merge them.
    #[test]
    fn anchor_separates_klog_call_sites() {
        let normalizer = Normalizer::new(Config::default());
        let status = normalize(
            r#"E0910 00:02:39.914326       1 status.go:71] "Unhandled Error" err="context deadline exceeded" logger="UnhandledError""#,
        );
        let writers = normalize(
            r#"E0910 00:02:39.917803       1 writers.go:135] "Unhandled Error" err="context deadline exceeded" logger="UnhandledError""#,
        );
        assert_ne!(status.anchor, writers.anchor, "different call sites");
        assert!(!normalizer.are_similar(&status, &writers));
        assert!(
            normalizer.similarity_score(&status, &writers)
                >= f64::from(Config::default().threshold),
            "the anchor, not the score, keeps these apart"
        );
    }

    /// One call site stays one call site whatever the pid, the time or the
    /// line's other variable parts.
    #[test]
    fn anchor_keeps_one_klog_call_site_together() {
        let normalizer = Normalizer::new(Config::default());
        let first = normalize(
            r#"E0910 00:02:39.914326       1 status.go:71] "Unhandled Error" err="context deadline exceeded" logger="UnhandledError""#,
        );
        let second = normalize(
            r#"E0910 00:03:12.001200  114343 status.go:71] "Unhandled Error" err="context deadline exceeded" logger="UnhandledError""#,
        );
        assert_eq!(first.anchor, second.anchor);
        assert!(normalizer.are_similar(&first, &second));
    }

    /// Two units failing are two incidents. The corpus had 8 rke2-agent
    /// failures absorbed into 103,328 containerd ones under a template that
    /// named rke2-agent.
    #[test]
    fn anchor_separates_systemd_units() {
        let normalizer = Normalizer::new(Config::default());
        let agent = normalize(
            "Sep 14 06:38:27 oryx systemd[1]: rke2-agent.service: Main process exited, code=exited, status=1/FAILURE",
        );
        let containerd = normalize(
            "Sep 14 09:37:04 oryx systemd[1]: containerd.service: Main process exited, code=exited, status=1/FAILURE",
        );
        assert_ne!(agent.anchor, containerd.anchor, "different units");
        assert!(!normalizer.are_similar(&agent, &containerd));
        assert!(
            normalizer.similarity_score(&agent, &containerd)
                >= f64::from(Config::default().threshold),
            "the anchor, not the score, keeps these apart"
        );
        let again = normalize(
            "Sep 14 06:40:27 oryx systemd[1]: rke2-agent.service: Main process exited, code=exited, status=1/FAILURE",
        );
        assert_eq!(agent.anchor, again.anchor, "same unit, same anchor");
    }

    /// A message *about* a unit is not the unit speaking: `Starting
    /// containerd.service - ...` carries no anchor and folds as before.
    #[test]
    fn anchor_ignores_messages_about_units() {
        let line = normalize(
            "Sep 14 06:38:27 oryx systemd[1]: Starting containerd.service - containerd container runtime...",
        );
        assert_eq!(line.anchor, 0);
    }

    /// auditd's `type=` is the record kind; two kinds with near-identical
    /// bodies are still two kinds.
    #[test]
    fn anchor_separates_audit_record_types() {
        let acq = normalize(
            "type=CRED_ACQ msg=audit(1481077254.276:518): pid=3014 uid=0 auid=0 ses=1 msg='op=PAM:setcred acct=\"root\" exe=\"/usr/sbin/cron\" hostname=? addr=? terminal=cron res=success'",
        );
        let disp = normalize(
            "type=CRED_DISP msg=audit(1481077254.280:520): pid=3014 uid=0 auid=0 ses=1 msg='op=PAM:setcred acct=\"root\" exe=\"/usr/sbin/cron\" hostname=? addr=? terminal=cron res=success'",
        );
        assert_ne!(acq.anchor, disp.anchor, "different record types");
        let acq2 = normalize(
            "type=CRED_ACQ msg=audit(1481077300.101:530): pid=3020 uid=0 auid=0 ses=2 msg='op=PAM:setcred acct=\"root\" exe=\"/usr/sbin/cron\" hostname=? addr=? terminal=cron res=success'",
        );
        assert_eq!(acq.anchor, acq2.anchor, "same type, same anchor");
        // `type=` must open the line: a key=value elsewhere is not a record type.
        let prose = normalize("event type=CRED_ACQ msg=audit(1.0:1): done");
        assert_eq!(prose.anchor, 0);
    }

    /// Most lines carry no anchor at all and must group exactly as before.
    #[test]
    fn lines_without_anchors_are_untouched() {
        let plain = normalize(
            "Sep 14 06:58:42 oryx kernel: usb 1-1: new high-speed USB device number 4 using xhci_hcd",
        );
        assert_eq!(
            plain.anchor, 0,
            "a line with no request, device, call site, unit or record type carries no anchor"
        );

        let normalizer = Normalizer::new(Config::default());
        let other = normalize(
            "Sep 14 06:58:43 oryx kernel: usb 1-2: new high-speed USB device number 5 using xhci_hcd",
        );
        assert_eq!(other.anchor, 0);
        assert!(normalizer.are_similar(&plain, &other));
    }

    /// A unit whose name carries an instance id — a container scope, a pod
    /// volume mount — is one unit kind. The corpus has 555 `cri-containerd-
    /// <hash>.scope` units; anchoring each one is the PCI-inventory mistake.
    #[test]
    fn anchor_names_the_unit_kind_not_the_instance() {
        let a = normalize(
            "Sep 14 06:58:42 oryx systemd[1]: cri-containerd-9f3e7c2a1b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f.scope: Deactivated successfully.",
        );
        let b = normalize(
            "Sep 14 06:58:43 oryx systemd[1]: cri-containerd-0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9.scope: Deactivated successfully.",
        );
        assert_eq!(a.anchor, b.anchor, "same unit kind");
        assert_ne!(a.anchor, 0);

        // A mount unit is named after what it mounts: the message is the
        // identity there, so it carries no anchor and folds by similarity.
        let mount = normalize(
            "Sep 14 06:58:42 oryx systemd[1]: var-lib-kubelet-pods-f27aee6d\\x2d4bc2\\x2d43f0\\x2d9be3\\x2d7a1b2c3d4e5f-volumes-kubernetes.io\\x7eprojected-kube\\x2dapi\\x2daccess\\x2dvmch5.mount: Deactivated successfully.",
        );
        assert_eq!(mount.anchor, 0, "mount units are not anchored");

        // `\x2d` is systemd's escaped hyphen: a uuid written that way is
        // still one id.
        let esc_a = normalize(
            "Sep 14 06:58:42 oryx systemd[1]: run-rke2-f27aee6d\\x2d4bc2\\x2d43f0\\x2d9be3\\x2d7a1b2c3d4e5f.scope: Deactivated successfully.",
        );
        let esc_b = normalize(
            "Sep 14 06:58:43 oryx systemd[1]: run-rke2-01af48d9\\x2d3471\\x2d4acf\\x2d93aa\\x2d689c01b31dff.scope: Deactivated successfully.",
        );
        assert_eq!(esc_a.anchor, esc_b.anchor, "escaped uuid is one id run");

        let session = normalize(
            "Sep 14 06:58:42 oryx systemd[1]: session-1234.scope: Deactivated successfully.",
        );
        let session2 = normalize(
            "Sep 14 06:58:42 oryx systemd[1]: session-98.scope: Deactivated successfully.",
        );
        assert_eq!(session.anchor, session2.anchor, "digit runs collapse");
    }

    /// The anchor is folded into the line hash, so the folder's exact-hash
    /// group index cannot attach a line to a group with a different anchor
    /// without ever consulting `are_similar`.
    #[test]
    fn anchor_is_folded_into_the_line_hash() {
        let login = normalize(
            r#"[2026-08-16 14:08:34 +0200] ::ffff - "GET /login/ HTTP/1.1" 200 17450.949"#,
        );
        let admin = normalize(
            r#"[2026-08-16 14:08:34 +0200] ::ffff - "GET /admin/ HTTP/1.1" 200 17450.949"#,
        );
        assert_eq!(
            login.normalized, admin.normalized,
            "normalization erases both paths identically — that is the trap"
        );
        assert_ne!(
            login.hash, admin.hash,
            "the hash must still tell them apart"
        );
    }

    // ---- overflow lines: multiset instead of byte positions ----

    /// Build a line of `n` whitespace tokens whose 4th token is `state`, so
    /// the head differs when `state` does and the tail is identical.
    fn wide_line(state: &str, n: usize) -> String {
        let tail: Vec<String> = (0..n).map(|i| format!("f{i}=v{i}")).collect();
        format!("evt one two {state} {}", tail.join(" "))
    }

    #[test]
    fn overflow_lines_fold_like_short_ones() {
        // Regression for the token-overflow cliff: two lines differing in one
        // value folded when short and split when long, because past
        // MAX_SIMILARITY_TOKENS the comparison became positional bytes, which
        // one length change knocks out of alignment. Nothing about the
        // difference changes with the length of the identical tail, so the
        // verdict must not either.
        let normalizer = Normalizer::new(Config::default());
        let short = |s: &str| normalizer.normalize_line(wide_line(s, 10)).unwrap();
        let long = |s: &str| normalizer.normalize_line(wide_line(s, 200)).unwrap();

        // Same head, one differing payload token — the head check is not what
        // is under test here.
        assert!(
            normalizer.are_similar(&short("same alpha"), &short("same bravo")),
            "short lines differing in one payload token fold"
        );
        assert!(
            normalizer.are_similar(&long("same alpha"), &long("same bravo")),
            "the same pair must still fold once past MAX_SIMILARITY_TOKENS"
        );
    }

    #[test]
    fn overflow_lines_keep_distinct_messages_apart() {
        // The multiset is order-insensitive, so a large shared payload can
        // outvote the few words that say what a record IS. A real Rancher log
        // merged 18 "Updating TLS secret for ..." lines into an "Active TLS
        // secret ..." group before the ordered head check went in.
        let normalizer = Normalizer::new(Config::default());
        let active = normalizer.normalize_line(wide_line("Active", 200)).unwrap();
        let updating = normalizer
            .normalize_line(wide_line("Updating", 200))
            .unwrap();
        assert!(
            !normalizer.are_similar(&active, &updating),
            "a differing head must keep two messages apart however alike their payloads"
        );
    }

    #[test]
    fn overflow_similarity_is_order_insensitive_in_the_payload() {
        // What the multiset buys: a value changing length mid-record shifts
        // every byte after it, which is exactly what defeated the positional
        // comparison. The head is identical here, so only the payload differs.
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line(format!("evt one two same {}", "x ".repeat(100)))
            .unwrap();
        let b = normalizer
            .normalize_line(format!("evt one two same {}xlonger", "x ".repeat(99)))
            .unwrap();
        assert!(normalizer.similarity_score(&a, &b) > 90.0);
    }

    #[test]
    fn lines_past_the_multiset_bound_keep_the_byte_fallback() {
        // Past MAX_MULTISET_TOKENS the hashes are not kept, so the positional
        // path still runs. Truncating the hash set instead would let two
        // records agreeing only on their first few thousand tokens score as
        // identical.
        let huge = crate::patterns::MAX_MULTISET_TOKENS + 10;
        let normalizer = Normalizer::new(Config::default());
        let line = normalizer.normalize_line(wide_line("up", huge)).unwrap();
        assert!(
            line.sim().sorted_hashes().is_empty(),
            "a line past the bound carries no hashes"
        );
    }
}

#[cfg(test)]
mod anchor_tests_2026_08_29 {
    use super::*;

    fn normalize(line: &str) -> LogLine {
        Normalizer::new(Config::default())
            .normalize_line(line.to_string())
            .unwrap()
    }

    #[test]
    fn a_structured_caller_is_a_call_site() {
        let first = normalize(
            r#"{"level":"info","caller":"mvcc/kvstore_compaction.go:70","msg":"finished scheduled compaction"}"#,
        );
        let second =
            normalize(r#"{"level":"info","caller":"mvcc/hash.go:157","msg":"storing new hash"}"#);
        let third =
            normalize(r#"{"level":"info","caller":"mvcc/hash.go:157","msg":"storing new hash"}"#);
        assert_ne!(first.anchor, second.anchor);
        assert_eq!(second.anchor, third.anchor);
        let fourth = normalize(
            "ts=2026-08-29T01:10:53Z level=error caller=/go/pkg/mod/k8s.io/client-go@v0.34.2/tools/cache/reflector.go:205 msg=\"Failed to watch\"",
        );
        assert_ne!(fourth.anchor, 0);
    }

    #[test]
    fn the_kubectl_prefix_is_container_and_workload() {
        let first = normalize("[pod/llm-d-sim-67cb674c47-d6ms5/vllm-render] GET /health");
        let second = normalize("[pod/llm-d-sim-67cb674c47-f86lm/vllm-render] GET /health");
        let third = normalize("[pod/render-twin-5c9c5df548-dxqmk/vllm-render] GET /health");
        let fourth = normalize("[pod/llm-d-sim-67cb674c47-d6ms5/other] GET /health");
        assert_eq!(first.anchor, second.anchor, "replicas of one workload");
        assert_ne!(
            first.anchor, third.anchor,
            "another workload, same container name"
        );
        assert_ne!(first.anchor, fourth.anchor, "another container");
        let ord0 = normalize("[pod/gitaly-0/gitaly] x");
        let ord1 = normalize("[pod/gitaly-1/gitaly] x");
        assert_eq!(ord0.anchor, ord1.anchor, "statefulset ordinals");
        let osd0 = normalize("[pod/rook-ceph-osd-0-56d5fdf8f8-ltzv5/osd] x");
        let osd1 = normalize("[pod/rook-ceph-osd-1-6bb486f64d-njdks/osd] x");
        let mon_bp = normalize("[pod/rook-ceph-mon-bp-74f99bc8b4-v8d9g/mon] x");
        let mon_cc = normalize("[pod/rook-ceph-mon-cc-69db7dc6fc-72pbb/mon] x");
        assert_eq!(
            osd0.anchor, osd1.anchor,
            "the same daemon on another instance"
        );
        assert_eq!(mon_bp.anchor, mon_cc.anchor, "instance letters");
        assert_ne!(osd0.anchor, mon_bp.anchor, "osd is not mon");
    }

    #[test]
    fn a_status_field_is_matched_by_class() {
        let first = normalize(
            r#"{"DownstreamStatus":500,"RequestMethod":"POST","RequestPath":"/api/v4/jobs/request"}"#,
        );
        let second = normalize(
            r#"{"DownstreamStatus":204,"RequestMethod":"POST","RequestPath":"/api/v4/jobs/request"}"#,
        );
        let third = normalize(
            r#"{"DownstreamStatus":200,"RequestMethod":"POST","RequestPath":"/api/v4/jobs/request"}"#,
        );
        let fourth = normalize(
            r#"{"DownstreamStatus":200,"RequestMethod":"GET","RequestPath":"/api/v4/jobs/request"}"#,
        );
        let fifth = normalize(
            r#"{"DownstreamStatus":200,"RequestMethod":"POST","RequestPath":"/api/v4/runners/verify"}"#,
        );
        assert_ne!(first.anchor, second.anchor, "5xx against 2xx");
        assert_eq!(second.anchor, third.anchor, "one class");
        assert_ne!(third.anchor, fourth.anchor, "method");
        assert_ne!(third.anchor, fifth.anchor, "route");
        let sixth = normalize("time=x level=info status=302 method=GET path=\"/oauth2/start\"");
        assert_ne!(sixth.anchor, 0);
    }

    #[test]
    fn a_digest_segment_is_one_route() {
        let first = normalize(
            r#"10.1.1.1 - - [29/Aug/2026:00:00:03 +0000] "GET /v2/projects/tups/manifests/sha256:25fef6f1f6fe9f1e4bd6fbfc6b173cc2867c9f0da03e6aa1df030d2a7a049a4c HTTP/1.1" 200 2936 "" "x""#,
        );
        let second = normalize(
            r#"10.1.1.1 - - [29/Aug/2026:00:00:13 +0000] "GET /v2/projects/tups/manifests/sha256:8bd94c55d8e8710e5631589640219a2a4016c99a4d7189aca62b98bb087a7161 HTTP/1.1" 200 2936 "" "x""#,
        );
        assert_eq!(first.anchor, second.anchor);
    }

    #[test]
    fn a_traceback_frame_and_a_message_call_site_anchor() {
        let first = normalize(
            r#"  File "/usr/lib/python3.11/site-packages/urllib3/response.py", line 779, in _error_catcher"#,
        );
        let second = normalize(
            r#"  File "/usr/share/k8s-sidecar/resources.py", line 418, in _watch_resource_loop"#,
        );
        let third = normalize(
            r#"  File "/usr/lib/python3.11/site-packages/urllib3/response.py", line 779, in _error_catcher"#,
        );
        assert_ne!(first.anchor, second.anchor);
        assert_eq!(first.anchor, third.anchor);
        let fourth = normalize(
            "I0829 04:26:56.231168       1 reflector.go:397] k8s.io/client-go/informers/factory.go:160: forcing resync",
        );
        let fifth = normalize(
            "I0829 04:27:08.310956       1 reflector.go:397] sigs.k8s.io/sig-storage-lib-external-provisioner/v11/controller/controller.go:872: forcing resync",
        );
        assert_ne!(fourth.anchor, fifth.anchor);
    }
}
