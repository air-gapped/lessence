use ahash::AHasher;
use anyhow::Result;
use regex::Regex;
use std::hash::{Hash, Hasher};
use std::sync::LazyLock;

use crate::config::Config;
use crate::patterns::{
    AnchorSentinel, LogLine, MAX_SIMILARITY_TOKENS, SimTok, SimTokens, Token,
    bracket_context::BracketContextDetector, duration::DurationDetector,
    email::EmailPatternDetector, hash::HashDetector, http_status::HttpStatusDetector, is_small_int,
    json::JsonDetector, key_value::KeyValueDetector, kubernetes::KubernetesDetector,
    log_module::LogWithModuleDetector, names::K8S_RAND_ALPHABET, names::NameDetector,
    network::NetworkDetector, path::PathDetector, process::ProcessDetector, quoted::NestedGates,
    quoted::QuotedStringDetector, small_int_tail, structured::StructuredMessageDetector,
    timestamp::UnifiedTimestampDetector, uuid::UuidDetector,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    Specific,
    Broad,
    Generic,
    Last,
}

struct DetectorEntry {
    name: &'static str,
    tier: Tier,
    after: &'static [(&'static str, &'static str)],
    enabled: fn(&Config) -> bool,
    only_when: Option<fn(&Config, &str, &str) -> bool>,
    prefilter: Option<fn(&Config, &str, &str) -> bool>,
    run: fn(&Normalizer, &str) -> (String, Vec<Token>),
}

static DETECTOR_ORDER: &[DetectorEntry] = &[
    DetectorEntry {
        name: "cpu-quantity",
        tier: Tier::Specific,
        after: &[],
        enabled: |c| c.normalize_durations,
        only_when: None,
        prefilter: Some(|_, _, s| s.contains('m') && (s.contains("cpu") || s.contains("CPU"))),
        run: |_, s| DurationDetector::cpu_quantities(s),
    },
    DetectorEntry {
        name: "timestamp",
        tier: Tier::Specific,
        after: &[],
        enabled: |c| c.normalize_timestamps,
        only_when: None,
        prefilter: None,
        run: |_, s| UnifiedTimestampDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "email",
        tier: Tier::Specific,
        after: &[],
        enabled: |c| c.normalize_emails,
        only_when: None,
        prefilter: Some(|_, _, s| s.contains('@')),
        run: |n, s| n.email_detector.detect_and_replace(s),
    },
    DetectorEntry {
        name: "path",
        tier: Tier::Specific,
        after: &[("timestamp", r"client [16/Sep/2026:11:20:30 +0000] ready")],
        enabled: |c| c.normalize_paths,
        only_when: None,
        prefilter: None,
        run: |n, s| PathDetector::detect_and_replace_with(s, n.config.normalize_json),
    },
    DetectorEntry {
        name: "json",
        tier: Tier::Specific,
        after: &[],
        enabled: |c| c.normalize_json,
        only_when: None,
        prefilter: Some(|_, _, s| s.contains('{')),
        run: |_, s| JsonDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "uuid",
        tier: Tier::Specific,
        after: &[
            (
                "timestamp",
                r"00:00:23 default: Job OK (11111111-2222-4333-8444-555555555555)",
            ),
            (
                "path",
                r"open /tmp/repo/74ac195d-3097-4be6-b28c-c95067e201ab done",
            ),
        ],
        enabled: |c| c.normalize_uuids,
        only_when: None,
        prefilter: None,
        run: |_, s| UuidDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "network",
        tier: Tier::Specific,
        after: &[
            (
                "timestamp",
                r"type=SOCKADDR msg=audit(1500000000.276:518): ok",
            ),
            ("path", r"received block from /10.20.30.40"),
        ],
        enabled: |c| c.normalize_ips || c.normalize_ports || c.normalize_fqdns,
        only_when: None,
        prefilter: None,
        run: |n, s| {
            NetworkDetector::detect_and_replace(
                s,
                n.config.normalize_ips,
                n.config.normalize_ports,
                n.config.normalize_fqdns,
            )
        },
    },
    DetectorEntry {
        name: "hash",
        tier: Tier::Specific,
        after: &[
            (
                "path",
                r"open /tmp/repo/74ac195d-3097-4be6-b28c-c95067e201ab done",
            ),
            ("uuid", r"id=00000000-0000-4000-8000-00000000003f"),
            ("network", r"[    4.890000] 79792103.uart: ttyS0 ready"),
        ],
        enabled: |c| c.normalize_hashes,
        only_when: None,
        prefilter: None,
        run: |_, s| HashDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "process",
        tier: Tier::Specific,
        after: &[
            (
                "timestamp",
                r"I1102 09:10:00.000004    3310 mounter.go:51] done",
            ),
            (
                "path",
                r"2026-08-26T09:19:07+02:00 host1 /usr/libexec/portal-helper[4242]: started",
            ),
        ],
        enabled: |c| c.normalize_pids,
        only_when: None,
        prefilter: None,
        run: |_, s| ProcessDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "syslog-host",
        tier: Tier::Specific,
        after: &[
            (
                "timestamp",
                r"Aug 29 03:10:09 gw-lab-1 daemon.err sshd: bad key",
            ),
            (
                "network",
                r"Mar  3 10:00:00 web01.example.com sshd[123]: session opened",
            ),
        ],
        enabled: |c| c.normalize_fqdns,
        only_when: Some(|_, original, _| {
            !UnifiedTimestampDetector::opens_with_kernel_uptime(original)
        }),
        prefilter: Some(|_, _, s| s.starts_with("<TIMESTAMP> ")),
        run: |_, s| replace_syslog_host(s),
    },
    DetectorEntry {
        name: "kubernetes",
        tier: Tier::Specific,
        after: &[
            ("path", r#"agent "containerd/v2.1.4" connected"#),
            (
                "uuid",
                r#"Operation for "{volumeName:kubernetes.io/secret/11111111-2222-4333-8444-555555555555-app-secret podName:11111111-2222-4333-8444-555555555555 nodeName:}" failed"#,
            ),
            (
                "network",
                r#"grantors=pam_namespace,pam_unix acct="some_user" exe="/usr/sbin/sshd" hostname=gw-204.286.40.28.lab.example.net addr=10.20.30.40 terminal=ssh res=success"#,
            ),
        ],
        enabled: |c| c.normalize_kubernetes,
        only_when: None,
        prefilter: None,
        run: |_, s| KubernetesDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "http-status",
        tier: Tier::Specific,
        after: &[],
        enabled: |c| c.normalize_http_status,
        only_when: None,
        prefilter: None,
        run: |_, s| HttpStatusDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "bracket",
        tier: Tier::Specific,
        after: &[],
        enabled: |c| c.normalize_brackets,
        only_when: None,
        prefilter: Some(|_, _, s| {
            s.contains('[') && BracketContextDetector::contains_bracket_pair(s)
        }),
        run: |_, s| BracketContextDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "key-value",
        tier: Tier::Specific,
        after: &[
            (
                "timestamp",
                r#"ts=2026-01-02T03:04:05.678Z caller=checkpoint.go:101 level=info component=tsdb msg="Creating checkpoint" from_segment=138 to_segment=140 mint=1767323045000"#,
            ),
            (
                "path",
                r#"rpc error: code = Unknown desc = failed (add): no agent client after 30.000000 seconds timeout: Get "http://localhost/v1/config": dial unix /var/run/app/app.sock: connect: no such file or directory"#,
            ),
        ],
        enabled: |c| c.normalize_key_value,
        only_when: Some(|_, _, s| KeyValueDetector::has_pair_outside_quotes(s)),
        prefilter: None,
        run: |_, s| KeyValueDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "log-module",
        tier: Tier::Specific,
        after: &[],
        enabled: |c| c.normalize_brackets,
        only_when: None,
        prefilter: Some(|_, _, s| {
            s.contains('[') && LogWithModuleDetector::has_log_module_indicators(s)
        }),
        run: |_, s| LogWithModuleDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "structured-json",
        tier: Tier::Specific,
        after: &[],
        enabled: |c| c.normalize_json,
        only_when: None,
        prefilter: Some(|_, _, s| StructuredMessageDetector::has_structured_indicators(s)),
        run: |_, s| StructuredMessageDetector::detect_json_records(s),
    },
    DetectorEntry {
        name: "structured-logfmt",
        tier: Tier::Specific,
        after: &[],
        enabled: |c| c.normalize_key_value,
        only_when: None,
        prefilter: Some(|_, _, s| StructuredMessageDetector::has_structured_indicators(s)),
        run: |_, s| StructuredMessageDetector::detect_logfmt_records(s),
    },
    DetectorEntry {
        name: "duration",
        tier: Tier::Broad,
        after: &[
            (
                "timestamp",
                r"I1102 09:10:00.000004    3310 mounter.go:51] done",
            ),
            (
                "path",
                r"2026-08-26T09:19:07+02:00 host1 /usr/libexec/portal-helper[4242]: started",
            ),
            (
                "uuid",
                r"mounted filesystem cd1bccc7-a21f-4587-b414-3aa56a7c3f70 r/w",
            ),
            ("network", r"client 172.20.5.11:53212 connected"),
            (
                "hash",
                r"Module libx.so.6 from rpm ncurses-6.5-7.20250614.fc43.x86_64",
            ),
            (
                "process",
                r"I1102 09:10:00.000004    3310 mounter.go:51] done",
            ),
            (
                "http-status",
                r"GET /api upstream 502 -> cache miss then 200",
            ),
            ("key-value", r"client ready timeout=1m0s"),
        ],
        enabled: |c| c.normalize_durations,
        only_when: None,
        prefilter: None,
        run: |_, s| DurationDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "name",
        tier: Tier::Generic,
        after: &[
            (
                "path",
                r"open /tmp/repo/74ac195d-3097-4be6-b28c-c95067e201ab done",
            ),
            (
                "uuid",
                r"var-lib-kubelet-pods-438a97c2\x2d7b77\x2d466d\x2d964d\x2da94c97935530-volumes.mount: Deactivated",
            ),
            (
                "hash",
                r"assigned ledger-worker-all-in-1-v2-7d4b9c2f8e-b6w8n to node3",
            ),
            (
                "kubernetes",
                r"&Event{ObjectMeta:{virt-handler-vhjp6.1862d2cbe90da39f  kubevirt    0 0001-01-01 00:00:00 +0000 UTC <nil> <nil> map[] map[] [] [] []},InvolvedObject:ObjectReference{Kind:Pod,Namespace:kubevirt,Name:virt-handler-vhjp6,UID:11111111-2222-4333-8444-555555555555,APIVersion:v1,ResourceVersion:4242,FieldPath:,},Reason:Started,}",
            ),
            ("duration", r"Stopped user-runtime-dir@1000.service - done"),
        ],
        enabled: |c| c.normalize_names,
        only_when: None,
        prefilter: None,
        run: |_, s| NameDetector::detect_and_replace(s),
    },
    DetectorEntry {
        name: "quoted",
        tier: Tier::Last,
        after: &[
            ("cpu-quantity", r#"{"cpu":"750m","wait":"40m"}"#),
            (
                "path",
                r#"profile="unconfined" label="libvirt-d10f7a21-c572-4cab-95a9-51ad8f00f121//passt" pid=2415"#,
            ),
            (
                "uuid",
                r#"{"dir":"/tmp/repo/74ac195d-3097-4be6-b28c-c95067e201ab","execID":"e01b2"}"#,
            ),
            (
                "network",
                r#"{"url":"grpc:10.54.37.131//kas.example.svc|8155"}"#,
            ),
            ("kubernetes", r#"tracker pod="ns/web-1" status=observed"#),
            (
                "key-value",
                r#""Allocatable" allocatable={"hugepages-1Gi":"0","pods":"110"}"#,
            ),
            (
                "duration",
                r#""pod \"nightly-backup-wiki-db-29304410-77kp4\" started" pod="wiki-db/nightly-backup-wiki-db-29304410-77kp4""#,
            ),
            (
                "name",
                r#""pod \"nightly-backup-wiki-db-29304410-77kp4\" started" pod="wiki-db/nightly-backup-wiki-db-29304410-77kp4""#,
            ),
        ],
        enabled: |c| c.normalize_quoted,
        only_when: None,
        prefilter: Some(|_, _, s| s.contains('"') || s.contains('\'')),
        run: |n, s| {
            QuotedStringDetector::detect_and_replace_with(s, NestedGates::from_config(&n.config))
        },
    },
];

fn order_complaints(order: &[&DetectorEntry]) -> Vec<String> {
    let mut complaints = Vec::new();
    for (at, entry) in order.iter().enumerate() {
        if order[..at].iter().any(|e| e.name == entry.name) {
            complaints.push(format!("`{}` is in the table twice", entry.name));
        }
        if at > 0 && order[at - 1].tier > entry.tier {
            complaints.push(format!(
                "`{}` ({:?}) comes after `{}` ({:?})",
                entry.name,
                entry.tier,
                order[at - 1].name,
                order[at - 1].tier
            ));
        }
        for (earlier, _) in entry.after {
            if !order[..at].iter().any(|e| e.name == *earlier) {
                complaints.push(format!("`{}` must come after `{earlier}`", entry.name));
            }
        }
    }
    complaints
}

pub struct Normalizer {
    config: Config,
    email_detector: EmailPatternDetector,
}

const REQUEST_METHODS: &str = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT";
static REQUEST_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r#""(?:{REQUEST_METHODS}) ([^"\s]*) HTTP/"#))
        .expect("request-target anchor pattern must compile")
});

static PROSE_REQUEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?:^|[\s"'(])({REQUEST_METHODS})[ \t]+(?:(?i:https?)[ \t]+request:?[ \t]+((?:https?://[^\s"'\\]+|/[^\s"'\\]*))|(https?://[^\s"'\\]+))"#
    ))
    .expect("prose HTTP request pattern must compile")
});

struct ProseRequest {
    method: std::ops::Range<usize>,
    target: std::ops::Range<usize>,
}

fn prose_requests(text: &str) -> impl Iterator<Item = ProseRequest> + '_ {
    (text.contains("://") || text.contains("request"))
        .then(|| PROSE_REQUEST.captures_iter(text))
        .into_iter()
        .flatten()
        .filter(|caps| {
            let method = caps.get(1).unwrap();
            !(caps.get(3).is_some()
                && text[..method.start()].ends_with('"')
                && text[caps.get(0).unwrap().end()..].starts_with(" HTTP/"))
        })
        .map(|caps| {
            let target = caps.get(2).or_else(|| caps.get(3)).unwrap();
            let trimmed = target.as_str().trim_end_matches([')', ']', ',', '.', ';']);
            ProseRequest {
                method: caps.get(1).unwrap().range(),
                target: target.start()..target.start() + trimmed.len(),
            }
        })
}

fn prose_target_parts(target: &str) -> (&str, &str) {
    if let Some((scheme, rest)) = target.split_once("://") {
        let start = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let path = &rest[start..];
        (
            scheme,
            if path.starts_with(['/', '?']) {
                path
            } else {
                "/"
            },
        )
    } else {
        ("", target)
    }
}

fn render_prose_target(target: &str, named: u64) -> String {
    let (scheme, path) = prose_target_parts(target);
    let route = render_named_route(path, named);
    if scheme.is_empty() {
        route
    } else {
        format!("{scheme}://<HOST>{route}")
    }
}

static REQUEST_TEMPLATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#""(?:{REQUEST_METHODS}|<VARIES>) [^"\r\n]*? (HTTP/)[^"\s]*"?"#
    ))
    .expect("request-template pattern must compile")
});

pub(crate) fn quoted_request_templates(
    text: &str,
) -> impl Iterator<Item = (regex::Match<'_>, regex::Match<'_>)> {
    text.contains("HTTP/")
        .then(|| REQUEST_TEMPLATE.captures_iter(text))
        .into_iter()
        .flatten()
        .map(|caps| (caps.get(0).unwrap(), caps.get(1).unwrap()))
}

static REQUEST_STATUS_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#" HTTP/[0-9.]+" ([1-5])(\d\d)\b"#)
        .expect("request-status anchor pattern must compile")
});

static PCI_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\b")
        .expect("pci-address anchor pattern must compile")
});

pub(crate) fn pci_addresses(original: &str) -> impl Iterator<Item = regex::Match<'_>> {
    let bytes = original.as_bytes();
    (original.contains(':')
        && original
            .match_indices('.')
            .any(|(at, _)| bytes.get(at + 1).is_some_and(|b| matches!(b, b'0'..=b'7'))))
    .then(|| PCI_ADDRESS.find_iter(original))
    .into_iter()
    .flatten()
}

static KLOG_CALL_SITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[IWEF]\d{4} \d\d:\d\d:\d\d\.\d{6}\s+\d+ ([A-Za-z0-9_]+\.go:\d+)\]")
        .expect("klog call-site anchor pattern must compile")
});

static SYSTEMD_UNIT_SUBJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"systemd\[\d+\]: ([A-Za-z0-9@._:\\-]+\.(?:service|slice|scope|socket|timer|target)): ",
    )
    .expect("systemd unit anchor pattern must compile")
});

static STRUCTURED_CALLER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:"caller"\s*:\s*"|\bcaller=)([A-Za-z0-9_./@+-]+\.[a-z]{1,4}:\d+)"#)
        .expect("structured caller anchor pattern must compile")
});

static MESSAGE_CALL_SITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.go:\d+\] ([A-Za-z0-9_./@+-]+\.go:\d+): ")
        .expect("message call-site anchor pattern must compile")
});

static TRACEBACK_FRAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"File "([^"]+)", line (\d+), in (\S+)"#)
        .expect("traceback frame anchor pattern must compile")
});

fn exact_anchor_fields<'a>(
    original: &'a str,
    pattern: &'a Regex,
) -> impl Iterator<Item = regex::Match<'a>> + 'a {
    pattern
        .captures_iter(original)
        .flat_map(|caps| (1..caps.len()).filter_map(move |i| caps.get(i)))
}

static FIELD_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)"?[a-z_.]*method"?\s*[:=]\s*"?([A-Za-z][A-Za-z0-9_./-]*)"#)
        .expect("field method anchor pattern must compile")
});

static FIELD_STATUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)"?[a-z_.]*status(?:_?code)?"?\s*[:=]\s*"?([1-5])(\d\d)\b"#)
        .expect("field status anchor pattern must compile")
});

fn http_status_anchors<'a>(
    original: &'a str,
    pattern: &'a Regex,
) -> impl Iterator<Item = (std::ops::Range<usize>, &'a str)> + 'a {
    pattern.captures_iter(original).map(|caps| {
        let class = caps.get(1).expect("status class capture");
        let rest = caps.get(2).expect("remaining status digits");
        (class.start()..rest.end(), class.as_str())
    })
}

static STATUS_OBJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)"[a-z_]*status[a-z_]*"\s*:\s*\{"#)
        .expect("status object anchor pattern must compile")
});

fn status_object_codes(original: &str) -> impl Iterator<Item = (std::ops::Range<usize>, &str)> {
    STATUS_OBJECT
        .find_iter(original)
        .filter_map(|object| code_member_of_object(original, object.end()))
}

fn code_member_of_object(text: &str, body: usize) -> Option<(std::ops::Range<usize>, &str)> {
    let bytes = text.as_bytes();
    let mut depth = 1usize;
    let mut at = body;
    while at < bytes.len() {
        match bytes[at] {
            b'"' => {
                let start = at + 1;
                let end = start + closing_quote_offset(&bytes[start..])?;
                at = end + 1;
                if depth == 1
                    && &text[start..end] == "code"
                    && let Some(found) = http_status_value_after_key(text, at)
                {
                    return Some(found);
                }
                continue;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return None;
                }
            }
            _ => {}
        }
        at += 1;
    }
    None
}

fn closing_quote_offset(bytes: &[u8]) -> Option<usize> {
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at += 2,
            b'"' => return Some(at),
            _ => at += 1,
        }
    }
    None
}

fn http_status_value_after_key(
    text: &str,
    after_key: usize,
) -> Option<(std::ops::Range<usize>, &str)> {
    let bytes = text.as_bytes();
    let skip_space = |mut at: usize| {
        while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        at
    };
    let colon = skip_space(after_key);
    if bytes.get(colon) != Some(&b':') {
        return None;
    }
    let start = skip_space(colon + 1);
    let digits = bytes[start..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    let ends_the_value = matches!(
        bytes.get(start + digits),
        None | Some(b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
    );
    (digits == 3 && (b'1'..=b'5').contains(&bytes[start]) && ends_the_value)
        .then(|| (start..start + 3, &text[start..=start]))
}

static RECORD_IDENTITY_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(name|namespace|resource)"\s*:\s*"([^"\\]+)""#)
        .expect("record identity field pattern must compile")
});

#[derive(Default)]
struct RecordIdentity<'a> {
    names: Vec<&'a str>,
    resources: Vec<&'a str>,
}

impl<'a> RecordIdentity<'a> {
    fn of(original: &'a str) -> Self {
        let mut identity = Self::default();
        if !original.contains("\"name") && !original.contains("\"resource") {
            return identity;
        }
        for caps in RECORD_IDENTITY_FIELD.captures_iter(original) {
            let value = caps.get(2).map_or("", |m| m.as_str());
            if &caps[1] == "resource" {
                identity.resources.push(value);
            } else {
                identity.names.push(value);
            }
        }
        identity
    }

    fn named_segments(&self, target: &str) -> u64 {
        if self.names.is_empty() {
            return 0;
        }
        let (path, _) = route_path(prose_target_parts(target).1);
        let segments: Vec<&str> = path.split('/').collect();
        let mut named = 0;
        for at in 1..segments.len().min(MAX_NAMED_SEGMENTS) {
            let (collection, segment) = (segments[at - 1], segments[at]);
            if self.names.contains(&segment)
                && !self.resources.contains(&segment)
                && !segments[at + 1..].contains(&segment)
                && !collection.is_empty()
                && !self.names.contains(&collection)
            {
                named |= 1 << at;
            }
        }
        named
    }
}

const MAX_NAMED_SEGMENTS: usize = 64;

fn is_named_segment(named: u64, at: usize) -> bool {
    at < MAX_NAMED_SEGMENTS && named & (1 << at) != 0
}

fn named_segment_values(target: &str, named: u64) -> impl Iterator<Item = &str> {
    route_path(prose_target_parts(target).1)
        .0
        .split('/')
        .enumerate()
        .filter(move |&(at, _)| is_named_segment(named, at))
        .map(|(_, segment)| segment)
}

static FIELD_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)"?[a-z_.]*(?:path|uri|url|route)"?\s*(?:[:=]\s*"([^"]*)"|=([^\s"'\\,]+))"#)
        .expect("field path anchor pattern must compile")
});

fn is_route_shaped(value: &str) -> bool {
    value.starts_with('/')
        || value.split_once("://").is_some_and(|(scheme, _)| {
            !scheme.is_empty() && scheme.bytes().all(|b| b.is_ascii_alphabetic())
        })
}

#[inline]
fn gate(open: bool, what: &str, original: &str, finds: impl FnOnce() -> bool) -> bool {
    debug_assert!(
        open || !finds(),
        "the gate before the {what} anchor turned away a line its pattern matches:\n  {original}"
    );
    open
}

fn field_routes(original: &str, has_method: bool) -> impl Iterator<Item = (usize, &str)> {
    FIELD_PATH.captures_iter(original).filter_map(move |caps| {
        let m = match (caps.get(1), caps.get(2)) {
            (Some(_), _) if has_method => return None,
            (Some(m), _) | (None, Some(m)) => m,
            (None, None) => return None,
        };
        let value = m.as_str().trim_end_matches([')', ']', '}', '.', ';']);
        (!value.is_empty() && is_route_shaped(value)).then_some((m.start(), value))
    })
}

fn may_hold_route_field(original: &str) -> bool {
    original.contains("://") || original.contains("=/") || quoted_route_after_separator(original)
}

fn quoted_route_after_separator(original: &str) -> bool {
    let bytes = original.as_bytes();
    original.match_indices("\"/").any(|(at, _)| {
        bytes[..at]
            .iter()
            .rev()
            .find(|b| !b.is_ascii_whitespace())
            .is_some_and(|&b| b == b'=' || b == b':')
    })
}

static PROGRAM_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:\b(?:exe|comm)=|"(?:binary|exe|comm)"\s*:\s*)"([^"]+)""#)
        .expect("program field anchor pattern must compile")
});

static KUBECTL_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\[pod/([^/\]]+)/([^\]]+)\]").expect("kubectl prefix anchor pattern must compile")
});

static AUDIT_RECORD_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^type=([A-Z_]+) msg=audit\(").expect("audit type anchor pattern must compile")
});

static AUDIT_SYSCALL_OUTCOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^type=SYSCALL msg=audit\([0-9]+\.[0-9]+:[0-9]+\): arch=[0-9a-fA-F]+ syscall=[0-9]+ (success=(?:yes|no))(?: |$)",
    )
    .expect("audit syscall outcome anchor pattern must compile")
});

static CLI_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s"'])(--[A-Za-z][A-Za-z0-9_-]*|-[A-Za-z]\b)"#)
        .expect("CLI option anchor pattern must compile")
});

pub(crate) fn cli_option_names(original: &str) -> impl Iterator<Item = regex::Match<'_>> {
    original
        .contains('-')
        .then(|| CLI_OPTION.captures_iter(original))
        .into_iter()
        .flatten()
        .filter_map(|caps| caps.get(1))
}

static SYSLOG_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^<TIMESTAMP> (\S+) (?:[A-Za-z/]\S*:|[a-z]+\.[a-z]+\b)")
        .expect("syslog host anchor pattern must compile")
});

fn is_facility_level_shape(word: &str) -> bool {
    match word.split_once('.') {
        Some((facility, level)) => {
            !facility.is_empty()
                && !level.is_empty()
                && !level.contains('.')
                && facility.bytes().all(|b| b.is_ascii_lowercase())
                && level.bytes().all(|b| b.is_ascii_lowercase())
        }
        None => false,
    }
}

fn is_host_candidate(word: &str) -> bool {
    if word.starts_with('<') && word.ends_with('>') {
        return false;
    }
    if word.contains('=') || word.contains(':') {
        return false;
    }
    if is_facility_level_shape(word) {
        return false;
    }
    word.chars().any(|c| c.is_ascii_lowercase())
}

fn replace_syslog_host(s: &str) -> (String, Vec<Token>) {
    if let Some(caps) = SYSLOG_HOST.captures(s) {
        let m = caps.get(1).expect("group 1 always present on a match");
        let word = m.as_str();
        if is_host_candidate(word) {
            let mut result = String::with_capacity(s.len());
            result.push_str(&s[..m.start()]);
            result.push_str("<HOST>");
            result.push_str(&s[m.end()..]);
            return (result, vec![Token::SyslogHost(word.to_string())]);
        }
    }
    (s.to_string(), Vec::new())
}

fn anchor_hash(identities: &mut [(AnchorClass, AnchorIdentity<'_>)]) -> u64 {
    if identities.is_empty() {
        return 0;
    }
    identities.sort_by_key(|&(class, _)| class);
    let mut hasher = AHasher::default();
    for &(class, identity) in identities.iter() {
        class.hash(&mut hasher);
        match identity {
            AnchorIdentity::Route(route) => hash_route(route, &mut hasher),
            AnchorIdentity::Text(text) => text.hash(&mut hasher),
            AnchorIdentity::ProseTarget(target, named) => {
                let (scheme, route) = prose_target_parts(target);
                scheme.hash(&mut hasher);
                hash_named_route(route, named, &mut hasher);
            }
            AnchorIdentity::Unit(unit) => visit_unit_skeleton(unit, |part| match part {
                UnitPart::Byte(byte) => byte.hash(&mut hasher),
                UnitPart::Id => "<id>".hash(&mut hasher),
                UnitPart::Number => "<d>".hash(&mut hasher),
            }),
            AnchorIdentity::Pod(pod, container) => {
                pod_skeleton(pod).hash(&mut hasher);
                container.hash(&mut hasher);
            }
        }
    }
    hasher.finish()
}

fn is_generated_pod_part(seg: &str) -> bool {
    let b = seg.as_bytes();
    (!b.is_empty() && b.iter().all(u8::is_ascii_digit))
        || (b.len() <= 2 && b.iter().all(u8::is_ascii_lowercase))
        || (b.len() == 5 && b.iter().all(|c| K8S_RAND_ALPHABET.contains(c)))
        || ((8..=10).contains(&b.len())
            && b.iter()
                .all(|c| K8S_RAND_ALPHABET.contains(c) || c.is_ascii_digit()))
}

fn pod_skeleton(pod: &str) -> &str {
    let mut keep = pod;
    for _ in 0..3 {
        match keep.rsplit_once('-') {
            Some((head, tail)) if is_generated_pod_part(tail) => keep = head,
            _ => break,
        }
    }
    keep
}

fn generated_pod_stem(segment: &str) -> Option<&str> {
    let stem = pod_skeleton(segment);
    let suffix = segment.get(stem.len() + 1..)?;
    let random = suffix
        .split('-')
        .any(|part| part.len() >= 5 && !part.bytes().all(|b| b.is_ascii_digit()));
    (!stem.is_empty() && random).then_some(stem)
}

fn systemd_units(original: &str) -> impl Iterator<Item = regex::Match<'_>> {
    original
        .contains("systemd[")
        .then(|| SYSTEMD_UNIT_SUBJECT.captures_iter(original))
        .into_iter()
        .flatten()
        .filter_map(|caps| caps.get(1))
}

enum UnitPart {
    Byte(u8),
    Id,
    Number,
}

fn visit_unit_skeleton(text: &str, mut visit: impl FnMut(UnitPart)) {
    let decoded;
    let text = if text.contains("\\x2d") {
        decoded = text.replace("\\x2d", "-");
        &decoded
    } else {
        text
    };
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_hexdigit() || bytes[i] == b'-') {
            visit(UnitPart::Byte(bytes[i]));
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
            visit(UnitPart::Id);
            continue;
        }
        let mut in_digits = false;
        for &byte in &bytes[start..i] {
            if byte.is_ascii_digit() {
                if !in_digits {
                    visit(UnitPart::Number);
                    in_digits = true;
                }
            } else {
                in_digits = false;
                visit(UnitPart::Byte(byte));
            }
        }
    }
}

fn render_systemd_unit(unit: &str) -> String {
    let mut rendered = String::with_capacity(unit.len());
    visit_unit_skeleton(unit, |part| match part {
        UnitPart::Byte(byte) => rendered.push(char::from(byte)),
        UnitPart::Id => rendered.push_str("<ID>"),
        UnitPart::Number => rendered.push_str("<N>"),
    });
    rendered
}

enum RouteSegment {
    Slash,
    Id,
    Skeleton(String),
}

fn classify_route_segment(segment: &str) -> RouteSegment {
    if segment.is_empty() {
        return RouteSegment::Slash;
    }
    if let Some((head, tail)) = segment.rsplit_once('.')
        && tail.len() >= OPAQUE_TAIL_HEX_DIGITS
        && tail.bytes().all(|b| b.is_ascii_hexdigit())
    {
        let head = match classify_route_segment(head) {
            RouteSegment::Slash => String::new(),
            RouteSegment::Id => "<ID>".to_string(),
            RouteSegment::Skeleton(skeleton) => skeleton,
        };
        return RouteSegment::Skeleton(format!("{head}.<ID>"));
    }
    let body = segment
        .split_once(':')
        .filter(|(algo, _)| !algo.is_empty() && algo.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map_or(segment, |(_, rest)| rest);
    let (stem, ext) = match body.rsplit_once('.') {
        Some((stem, ext))
            if ext.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && ext.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            (stem, Some(ext))
        }
        _ => (body, None),
    };
    if stem.len() >= 8
        && stem
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'_')
    {
        return match ext {
            None => RouteSegment::Id,
            Some(ext) => RouteSegment::Skeleton(format!("<ID>.{ext}")),
        };
    }
    if let Some(stem) = generated_pod_stem(segment) {
        return RouteSegment::Skeleton(format!("{stem}-<SUFFIX>"));
    }
    let b = segment.as_bytes();
    let mut out = String::with_capacity(segment.len());
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let inside_a_word = start > 0
            && b[start - 1].is_ascii_alphabetic()
            && i < b.len()
            && b[i].is_ascii_alphabetic();
        if inside_a_word {
            out.push_str(&segment[start..i]);
        } else {
            out.push_str("<N>");
        }
    }
    RouteSegment::Skeleton(out)
}

fn route_path(target: &str) -> (&str, bool) {
    match target.find(['?', '#']) {
        Some(at) => (&target[..at], target.as_bytes()[at] == b'?'),
        None => (target, false),
    }
}

const OPAQUE_TAIL_HEX_DIGITS: usize = 16;

fn hash_route(target: &str, hasher: &mut AHasher) {
    hash_named_route(target, 0, hasher);
}

fn hash_named_route(target: &str, named: u64, hasher: &mut AHasher) {
    let (path, has_query) = route_path(target);
    for (i, segment) in path.split('/').enumerate() {
        if is_named_segment(named, i) {
            "<name>".hash(hasher);
        } else {
            match classify_route_segment(segment) {
                RouteSegment::Slash => "/".hash(hasher),
                RouteSegment::Id => "<id>".hash(hasher),
                RouteSegment::Skeleton(s) => s.hash(hasher),
            }
        }
        "|".hash(hasher);
    }
    has_query.hash(hasher);
}

fn render_route(target: &str) -> String {
    render_named_route(target, 0)
}

fn render_named_route(target: &str, named: u64) -> String {
    let (path, has_query) = route_path(target);
    let mut out = String::with_capacity(path.len() + 8);
    for (i, segment) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if is_named_segment(named, i) {
            out.push_str("<NAME>");
            continue;
        }
        match classify_route_segment(segment) {
            RouteSegment::Slash => {}
            RouteSegment::Id => out.push_str("<ID>"),
            RouteSegment::Skeleton(s) => out.push_str(&s),
        }
    }
    if has_query {
        out.push_str("?<QUERY>");
    }
    out
}

fn pod_prefix_parts<'a>(caps: &regex::Captures<'a>) -> (&'a str, &'a str) {
    (
        caps.get(1).map_or("", |m| m.as_str()),
        caps.get(2).map_or("", |m| m.as_str()),
    )
}

fn render_pod_prefix(pod: &str, container: &str) -> String {
    let skeleton = pod_skeleton(pod);
    if skeleton.len() == pod.len() {
        format!("[pod/{skeleton}/{container}]")
    } else {
        format!("[pod/{skeleton}-<SUFFIX>/{container}]")
    }
}

enum AnchorRender<'a> {
    Route,
    ProseTarget { named: u64 },
    PodPrefix { pod: &'a str, container: &'a str },
    HttpStatus,
    StatusField,
    Exact,
    KlogCallSite,
    PciAddress,
    SystemdUnit,
}

impl AnchorRender<'_> {
    fn render(&self, text: &str) -> String {
        match self {
            Self::Route => render_route(text),
            Self::ProseTarget { named } => render_prose_target(text, *named),
            Self::PodPrefix { pod, container } => render_pod_prefix(pod, container),
            Self::HttpStatus => format!("<HTTP_STATUS_{}XX>", &text[..1]),
            Self::StatusField => format!("<STATUS_{}XX>", &text[..1]),
            Self::SystemdUnit => render_systemd_unit(text),
            Self::Exact | Self::KlogCallSite | Self::PciAddress => text.to_string(),
        }
    }

    fn sentinel(&self) -> AnchorSentinel {
        match self {
            Self::KlogCallSite => AnchorSentinel::KlogCallSiteVisibleToPid,
            _ => AnchorSentinel::OpaqueToDetectors,
        }
    }

    fn shows_text_verbatim(&self) -> bool {
        matches!(self, Self::Exact | Self::KlogCallSite | Self::PciAddress)
    }

    fn when_nested(&self, cover_shows_text_verbatim: bool) -> NestedIdentity {
        match self {
            Self::Route | Self::ProseTarget { .. } | Self::PodPrefix { .. } => {
                NestedIdentity::Hidden
            }
            Self::HttpStatus | Self::StatusField => NestedIdentity::EveryOccurrence,
            Self::PciAddress if !cover_shows_text_verbatim => NestedIdentity::EveryOccurrence,
            Self::PciAddress | Self::Exact | Self::KlogCallSite | Self::SystemdUnit => {
                NestedIdentity::OnceUnlessShown
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NestedIdentity {
    Hidden,
    EveryOccurrence,
    OnceUnlessShown,
}

struct ProtectedAnchors<'a> {
    text: String,
    renders: Vec<(String, String)>,
    statuses: Vec<ProtectedStatus>,
    name_facts: Vec<String>,
    path_facts: Vec<String>,
    identities: Vec<(AnchorClass, AnchorIdentity<'a>)>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AnchorClass {
    RequestRoute,
    RequestStatus,
    ProseRequest,
    PciAddress,
    CliOption,
    KlogCallSite,
    SystemdUnit,
    AuditType,
    AuditOutcome,
    Caller,
    MessageCallSite,
    TracebackFrame,
    Method,
    MethodPath,
    FieldRoute,
    StatusField,
    Program,
    PodPrefix,
}

#[derive(Clone, Copy)]
enum AnchorIdentity<'a> {
    Route(&'a str),
    Text(&'a str),
    ProseTarget(&'a str, u64),
    Unit(&'a str),
    Pod(&'a str, &'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusSource {
    RequestLine,
    StatusField,
}

struct ProtectedStatus {
    code: String,
    source: StatusSource,
}

impl ProtectedStatus {
    fn fact_of_the_detector_it_was_hidden_from(self, config: &Config) -> Option<Token> {
        if self.source == StatusSource::RequestLine && config.normalize_http_status {
            Some(Token::HttpStatusClass(format!("{}xx", &self.code[..1])))
        } else if config.normalize_durations {
            Some(Token::Number(self.code))
        } else {
            None
        }
    }
}

type AnchoredSpan<'a> = (usize, usize, AnchorRender<'a>);
fn protect_anchored_spans<'a>(
    original: &'a str,
    pci: &[regex::Match<'a>],
    options: &[regex::Match<'a>],
    requests: &[ProseRequest],
) -> ProtectedAnchors<'a> {
    let mut spans: Vec<AnchoredSpan<'a>> = Vec::new();
    let mut statuses = Vec::new();
    let mut name_facts = Vec::new();
    let mut identities = Vec::new();
    let mut path_facts = Vec::new();

    for request in requests {
        spans.push((
            request.method.start,
            request.method.end,
            AnchorRender::Exact,
        ));
        spans.push((
            request.target.start,
            request.target.end,
            AnchorRender::ProseTarget { named: 0 },
        ));
        identities.push((
            AnchorClass::ProseRequest,
            AnchorIdentity::Text(&original[request.method.clone()]),
        ));
        identities.push((
            AnchorClass::ProseRequest,
            AnchorIdentity::ProseTarget(&original[request.target.clone()], 0),
        ));
    }

    if gate(original.contains("HTTP/"), "request line", original, || {
        REQUEST_TARGET.is_match(original)
            || http_status_anchors(original, &REQUEST_STATUS_CLASS)
                .next()
                .is_some()
    }) {
        for caps in REQUEST_TARGET.captures_iter(original) {
            if let Some(m) = caps.get(1) {
                spans.push((m.start(), m.end(), AnchorRender::Route));
                identities.push((AnchorClass::RequestRoute, AnchorIdentity::Route(m.as_str())));
            }
        }
        for (span, class) in http_status_anchors(original, &REQUEST_STATUS_CLASS) {
            statuses.push(ProtectedStatus {
                code: original[span.clone()].to_string(),
                source: StatusSource::RequestLine,
            });
            spans.push((span.start, span.end, AnchorRender::HttpStatus));
            identities.push((AnchorClass::RequestStatus, AnchorIdentity::Text(class)));
        }
    }

    let mut has_method = false;
    if gate(
        original.contains("ethod") || original.contains("ETHOD"),
        "method field",
        original,
        || FIELD_METHOD.is_match(original),
    ) {
        for caps in FIELD_METHOD.captures_iter(original) {
            let method = caps.get(1).map_or("", |m| m.as_str());
            identities.push((AnchorClass::Method, AnchorIdentity::Text(method)));
            has_method |= matches!(
                method.to_ascii_uppercase().as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            );
        }
        if has_method {
            for caps in FIELD_PATH.captures_iter(original) {
                if let Some(m) = caps.get(1) {
                    spans.push((m.start(), m.end(), AnchorRender::Route));
                    identities.push((AnchorClass::MethodPath, AnchorIdentity::Route(m.as_str())));
                }
            }
        }
    }

    if gate(
        may_hold_route_field(original),
        "field route",
        original,
        || field_routes(original, has_method).next().is_some(),
    ) {
        let mut record: Option<RecordIdentity<'_>> = None;
        for (start, value) in field_routes(original, has_method) {
            let end = start + value.len();
            let named = record
                .get_or_insert_with(|| RecordIdentity::of(original))
                .named_segments(value);
            spans.push((start, end, AnchorRender::ProseTarget { named }));
            identities.push((
                AnchorClass::FieldRoute,
                AnchorIdentity::ProseTarget(value, named),
            ));
            path_facts.push(value.to_string());
            name_facts.extend(named_segment_values(value, named).map(str::to_string));
        }
    }

    if gate(
        original.contains("tatus") || original.contains("TATUS"),
        "status field",
        original,
        || {
            http_status_anchors(original, &FIELD_STATUS)
                .next()
                .is_some()
                || status_object_codes(original).next().is_some()
        },
    ) {
        for (span, class) in
            http_status_anchors(original, &FIELD_STATUS).chain(status_object_codes(original))
        {
            statuses.push(ProtectedStatus {
                code: original[span.clone()].to_string(),
                source: StatusSource::StatusField,
            });
            spans.push((span.start, span.end, AnchorRender::StatusField));
            identities.push((AnchorClass::StatusField, AnchorIdentity::Text(class)));
        }
    }

    for address in pci {
        spans.push((address.start(), address.end(), AnchorRender::PciAddress));
        identities.push((
            AnchorClass::PciAddress,
            AnchorIdentity::Text(address.as_str()),
        ));
    }
    for option in options {
        spans.push((option.start(), option.end(), AnchorRender::Exact));
        identities.push((
            AnchorClass::CliOption,
            AnchorIdentity::Text(option.as_str()),
        ));
    }
    for unit in systemd_units(original) {
        spans.push((unit.start(), unit.end(), AnchorRender::SystemdUnit));
        identities.push((
            AnchorClass::SystemdUnit,
            AnchorIdentity::Unit(unit.as_str()),
        ));
        if render_systemd_unit(unit.as_str()) != unit.as_str() {
            name_facts.push(unit.as_str().to_string());
        }
    }

    if gate(
        original.contains(".go:"),
        "klog call site",
        original,
        || {
            exact_anchor_fields(original, &KLOG_CALL_SITE)
                .next()
                .is_some()
        },
    ) {
        for field in exact_anchor_fields(original, &KLOG_CALL_SITE) {
            spans.push((field.start(), field.end(), AnchorRender::KlogCallSite));
            identities.push((
                AnchorClass::KlogCallSite,
                AnchorIdentity::Text(field.as_str()),
            ));
        }
    }
    if gate(
        original.starts_with("type="),
        "audit type",
        original,
        || AUDIT_RECORD_TYPE.is_match(original),
    ) {
        for caps in AUDIT_RECORD_TYPE.captures_iter(original) {
            let record = caps.get(1).map_or("", |m| m.as_str());
            identities.push((AnchorClass::AuditType, AnchorIdentity::Text(record)));
        }
    }
    for (class, open, pattern) in [
        (
            AnchorClass::AuditOutcome,
            original.starts_with("type=SYSCALL "),
            &*AUDIT_SYSCALL_OUTCOME,
        ),
        (
            AnchorClass::Caller,
            original.contains("caller"),
            &*STRUCTURED_CALLER,
        ),
        (
            AnchorClass::MessageCallSite,
            original.contains(".go:"),
            &*MESSAGE_CALL_SITE,
        ),
        (
            AnchorClass::TracebackFrame,
            original.contains("File \""),
            &*TRACEBACK_FRAME,
        ),
        (
            AnchorClass::Program,
            original.contains("exe=")
                || original.contains("comm=")
                || original.contains("\"binary\""),
            &*PROGRAM_FIELD,
        ),
    ] {
        if !gate(open, "exact field", original, || {
            exact_anchor_fields(original, pattern).next().is_some()
        }) {
            continue;
        }
        for field in exact_anchor_fields(original, pattern) {
            spans.push((field.start(), field.end(), AnchorRender::Exact));
            identities.push((class, AnchorIdentity::Text(field.as_str())));
        }
    }

    if gate(
        original.starts_with("[pod/"),
        "pod prefix",
        original,
        || KUBECTL_PREFIX.is_match(original),
    ) {
        for caps in KUBECTL_PREFIX.captures_iter(original) {
            let (pod, container) = pod_prefix_parts(&caps);
            if let Some(m) = caps.get(0) {
                spans.push((
                    m.start(),
                    m.end(),
                    AnchorRender::PodPrefix { pod, container },
                ));
            }
            identities.push((AnchorClass::PodPrefix, AnchorIdentity::Pod(pod, container)));
        }
    }

    if spans.is_empty() {
        return ProtectedAnchors {
            text: original.to_string(),
            renders: Vec::new(),
            statuses,
            name_facts,
            path_facts,
            identities,
        };
    }

    spans.sort_unstable_by_key(|&(start, end, _)| (start, end));
    let mut result = String::with_capacity(original.len());
    let mut renders: Vec<(String, String)> = Vec::with_capacity(spans.len());
    let mut cursor = 0;
    let mut cover_shows_text_verbatim = false;
    for (i, (start, end, render)) in spans.into_iter().enumerate() {
        if start < cursor {
            let showing = render.when_nested(cover_shows_text_verbatim);
            if showing != NestedIdentity::Hidden
                && let Some((_, rendered)) = renders.last_mut()
            {
                let identity = render.render(&original[start..end]);
                if showing == NestedIdentity::EveryOccurrence || !rendered.contains(&identity) {
                    rendered.push(' ');
                    rendered.push_str(&identity);
                }
            }
            continue;
        }
        result.push_str(&original[cursor..start]);
        let sentinel = render.sentinel().text(i);
        cover_shows_text_verbatim = render.shows_text_verbatim();
        renders.push((sentinel.clone(), render.render(&original[start..end])));
        result.push_str(&sentinel);
        cursor = end;
    }
    result.push_str(&original[cursor..]);
    ProtectedAnchors {
        text: result,
        renders,
        statuses,
        name_facts,
        path_facts,
        identities,
    }
}

impl Normalizer {
    pub fn new(config: Config) -> Self {
        debug_assert_eq!(
            order_complaints(&DETECTOR_ORDER.iter().collect::<Vec<_>>()),
            Vec::<String>::new(),
            "DETECTOR_ORDER breaks an entry's `tier` or `after`"
        );
        Self {
            config,
            email_detector: EmailPatternDetector::new().unwrap(),
        }
    }

    pub fn normalize_line(&self, original: String) -> Result<LogLine> {
        self.normalize_in_order(original, DETECTOR_ORDER.iter())
    }

    fn normalize_in_order<'a>(
        &self,
        original: String,
        order: impl Iterator<Item = &'a DetectorEntry>,
    ) -> Result<LogLine> {
        let pci: Vec<_> = pci_addresses(&original).collect();
        let options: Vec<_> = cli_option_names(&original).collect();
        let requests: Vec<_> = prose_requests(&original).collect();
        let mut protected = protect_anchored_spans(&original, &pci, &options, &requests);
        let mut normalized = std::mem::take(&mut protected.text);
        let mut tokens = Vec::with_capacity(8);

        for entry in order {
            if !(entry.enabled)(&self.config) {
                continue;
            }
            if let Some(only_when) = entry.only_when
                && !only_when(&self.config, &original, &normalized)
            {
                continue;
            }
            if let Some(prefilter) = entry.prefilter
                && !prefilter(&self.config, &original, &normalized)
            {
                #[cfg(debug_assertions)]
                {
                    let (skipped_text, skipped_tokens) = (entry.run)(self, &normalized);
                    debug_assert!(
                        skipped_text == normalized && skipped_tokens.is_empty(),
                        "the prefilter of the `{}` detector turned away a line its detector changes:\n  line:   {normalized}\n  result: {skipped_text}",
                        entry.name
                    );
                }
                continue;
            }
            let (new_normalized, mut new_tokens) = (entry.run)(self, &normalized);
            normalized = new_normalized;
            tokens.append(&mut new_tokens);
        }

        for (sentinel, rendered) in &protected.renders {
            if normalized.contains(sentinel.as_str()) {
                normalized = normalized.replace(sentinel.as_str(), rendered);
            }
        }
        tokens.extend(
            std::mem::take(&mut protected.statuses)
                .into_iter()
                .filter_map(|status| status.fact_of_the_detector_it_was_hidden_from(&self.config)),
        );
        tokens.extend(
            std::mem::take(&mut protected.name_facts)
                .into_iter()
                .map(Token::Name),
        );
        tokens.extend(
            std::mem::take(&mut protected.path_facts)
                .into_iter()
                .map(Token::Path),
        );

        tokens.extend(
            requests
                .iter()
                .map(|request| Token::Path(original[request.target.clone()].to_string())),
        );
        let anchor = anchor_hash(&mut protected.identities);

        let hash = mix_anchor_hash(self.calculate_hash(&normalized), anchor);

        Ok(LogLine::new(original, normalized, tokens, hash).anchored(anchor))
    }

    fn calculate_hash(&self, normalized: &str) -> u64 {
        let mut hasher = AHasher::default();
        normalized.hash(&mut hasher);
        hasher.finish()
    }

    pub fn similarity_score(&self, line1: &LogLine, line2: &LogLine) -> f64 {
        let s1 = &line1.normalized;
        let s2 = &line2.normalized;

        if s1 == s2 {
            return 100.0;
        }

        let len1 = s1.len();
        let len2 = s2.len();
        let max_len = len1.max(len2);
        let min_len = len1.min(len2);

        if max_len == 0 {
            return 100.0;
        }

        let length_ratio = min_len as f64 / max_len as f64;
        if length_ratio < 0.7 {
            return length_ratio * 100.0;
        }

        if let (SimTokens::Lcs { toks: a, .. }, SimTokens::Lcs { toks: b, .. }) =
            (line1.sim(), line2.sim())
            && !a.is_empty()
            && !b.is_empty()
        {
            let lcs = Self::token_lcs(s1, a, s2, b, None);
            return (2.0 * lcs as f64 / (a.len() + b.len()) as f64) * 100.0;
        }

        if let Some(ratio) = Self::multiset_ratio(line1, line2) {
            return ratio;
        }

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

    #[inline]
    fn tok_eq(s1: &str, t1: SimTok, s2: &str, t2: SimTok) -> bool {
        if t1.hash != t2.hash {
            return false;
        }
        let (a, b) = (
            &s1[t1.start as usize..t1.end as usize],
            &s2[t2.start as usize..t2.end as usize],
        );
        a == b
            || (is_small_int(a) && is_small_int(b))
            || small_int_tail(a).is_some_and(|t| small_int_tail(b) == Some(t))
    }

    fn multiset_ratio(line1: &LogLine, line2: &LogLine) -> Option<f64> {
        let (sim1, sim2) = (line1.sim(), line2.sim());
        let (a, b) = (sim1.sorted_hashes(), sim2.sorted_hashes());
        if a.is_empty() || b.is_empty() {
            return None;
        }
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

    fn token_lcs(s1: &str, a: &[SimTok], s2: &str, b: &[SimTok], needed: Option<usize>) -> usize {
        let min_n = a.len().min(b.len());

        let mut p = 0;
        while p < min_n && Self::tok_eq(s1, a[p], s2, b[p]) {
            p += 1;
        }
        if p == min_n {
            return min_n;
        }

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

    pub fn are_similar(&self, line1: &LogLine, line2: &LogLine) -> bool {
        if line1.hash == line2.hash {
            return true;
        }

        if line1.anchor != line2.anchor {
            return false;
        }

        let threshold = f64::from(self.config.threshold);

        if let (
            SimTokens::Lcs {
                toks: a,
                sorted_hashes: ha,
            },
            SimTokens::Lcs {
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
            if (2.0 * Self::multiset_intersection(ha, hb) as f64 / total) * 100.0 < threshold {
                return false;
            }

            let mut need = ((threshold * total) / 200.0).ceil() as usize;
            while (2.0 * need as f64 / total) * 100.0 < threshold {
                need += 1;
            }

            return Self::token_lcs(s1, a, s2, b, Some(need)) >= need;
        }

        if let Some(ratio) = Self::multiset_ratio(line1, line2) {
            return ratio >= threshold;
        }

        self.similarity_score(line1, line2) >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_quantities_survive_the_full_detector_pipeline() {
        let n = Normalizer::new(Config::default());
        for text in [
            "limits cpu 750m memory 512Mi waited 20m",
            r#"{"cpu":"750m","memory":"512Mi","wait":"20m"}"#,
            r#"{"msg":"resources {\"cpu\":\"750m\",\"memory\":\"512Mi\"} waited 20m"}"#,
            r#"{"msg":"resources {\\cpu\\:\\750m\\,\\memory\\:\\512Mi\\} waited 20m"}"#,
        ] {
            let line = n.normalize_line(text.to_string()).unwrap();
            assert!(
                line.normalized.contains("<CPU_QUANTITY>"),
                "{}",
                line.normalized
            );
            assert_eq!(
                line.tokens
                    .iter()
                    .filter(|t| matches!(t, Token::CpuQuantity(_)))
                    .count(),
                1
            );
            assert!(
                line.tokens
                    .iter()
                    .any(|t| matches!(t, Token::CpuQuantity(v) if v == "750m"))
            );
            assert!(
                !line
                    .tokens
                    .iter()
                    .any(|t| matches!(t, Token::Duration(v) if v.contains("750m")))
            );
            assert!(
                line.normalized.contains("<DURATION>"),
                "{}",
                line.normalized
            );
        }
    }

    #[test]
    fn decimal_measurements_keep_their_whole_value() {
        let n = Normalizer::new(Config::default());
        for value in [
            "3.1789551111111",
            "3.1789551111111111",
            "3.1789551111111111111",
            "1789551111111.25",
        ] {
            let line = n
                .normalize_line(format!(r#"{{"elapsed_ms":{value}}}"#))
                .unwrap();
            assert_eq!(line.normalized, r#"{"elapsed_ms":<DECIMAL>}"#);
            assert!(
                line.tokens
                    .iter()
                    .any(|t| matches!(t, Token::Duration(v) if v == value))
            );
            assert!(!line.tokens.iter().any(|t| matches!(t, Token::Timestamp(_))));
        }
    }

    #[test]
    fn prose_request_identity_preserves_method_and_route() {
        let n = Normalizer::new(Config::default());
        let norm = |text: &str| n.normalize_line(text.to_string()).unwrap();
        let first = norm("making GET http request: http://10.2.3.4:8080/items/42?view=one");
        let same = norm("making GET http request: http://worker.example:9000/items/71?view=two");
        assert_eq!(first.anchor, same.anchor);
        assert_eq!(
            first.normalized,
            "making GET http request: http://<HOST>/items/<N>?<QUERY>"
        );
        assert_eq!(first.normalized, same.normalized);
        assert!(
            first.tokens.iter().any(
                |t| matches!(t, Token::Path(p) if p == "http://10.2.3.4:8080/items/42?view=one")
            )
        );
        for text in [
            "making POST http request: http://10.2.3.4:8080/items/42",
            "making GET http request: http://10.2.3.4:8080/health/42",
            "making GET http request: https://10.2.3.4:8080/items/42",
        ] {
            assert_ne!(first.anchor, norm(text).anchor, "{text}");
        }
        for (text, shown) in [
            (
                "sent PATCH https://worker.example/items/92?x=y.",
                "PATCH https://<HOST>/items/<N>?<QUERY>.",
            ),
            (
                "making DELETE HTTP request: /items/42",
                "DELETE HTTP request: /items/<N>",
            ),
            ("GET http request: /", "GET http request: /"),
            (
                "GET http://worker.example?ready=yes",
                "GET http://<HOST>?<QUERY>",
            ),
        ] {
            let line = norm(text);
            assert!(line.normalized.contains(shown), "{}", line.normalized);
            assert_ne!(line.anchor, 0);
        }
        for text in [
            "GET the http manual",
            "TARGET http://worker.example/items",
            "read http://worker.example/items",
            "DELETE /tmp/items",
        ] {
            assert_eq!(norm(text).anchor, 0, "{text}");
        }
        for target in ["/items", "http://localhost/items"] {
            let get = norm(&format!("\"GET {target} HTTP/1.1\" 200 5"));
            let post = norm(&format!("\"POST {target} HTTP/1.1\" 200 5"));
            assert_eq!(get.anchor, post.anchor);
            assert!(get.normalized.contains(target));
        }
    }

    #[test]
    fn systemd_unit_rendering_matches_its_anchor_identity() {
        let units = [
            ("modprobe@loop.service", "modprobe@loop.service"),
            ("modprobe@fuse.service", "modprobe@fuse.service"),
            ("session-482.scope", "session-<N>.scope"),
            ("session-629.scope", "session-<N>.scope"),
            (
                "dbus-:1.4-org.example.Viewer@31.service",
                "dbus-:<N>.<N>-org.example.Viewer@<N>.service",
            ),
            (
                "dbus-:1.8-org.example.Viewer@43.service",
                "dbus-:<N>.<N>-org.example.Viewer@<N>.service",
            ),
            (
                "dbus-:1.8-org.example.Editor@43.service",
                "dbus-:<N>.<N>-org.example.Editor@<N>.service",
            ),
            (
                r"run-worker-12345678\x2dabcd\x2d4abc\x2d8abc\x2d123456789abc.scope",
                "run-worker<ID>.scope",
            ),
            (
                "run-worker-23456789-bbcd-4bbc-8bbc-23456789abcd.scope",
                "run-worker<ID>.scope",
            ),
        ];
        let mut lines = Vec::new();
        for (unit, shown) in units {
            assert_eq!(render_systemd_unit(unit), shown);
            let line = normalize(&format!("systemd[1]: {unit}: Deactivated successfully."));
            assert!(line.normalized.contains(shown), "{}", line.normalized);
            assert_ne!(line.anchor, 0);
            if shown != unit {
                assert!(
                    line.tokens
                        .iter()
                        .any(|t| matches!(t, Token::Name(name) if name == unit)),
                    "{}",
                    line.normalized
                );
            }
            lines.push((line, shown));
        }
        for (a, shown_a) in &lines {
            for (b, shown_b) in &lines {
                assert_eq!(a.anchor == b.anchor, shown_a == shown_b);
            }
        }
    }

    #[test]
    fn systemd_unit_protection_only_matches_anchored_subjects() {
        for line in [
            "systemd[1]: Starting worker.service - background worker...",
            "systemd[1]: tmp-cache.mount: Deactivated successfully.",
            "systemd[1]: dev-cache.device: Deactivated successfully.",
            "worker[1]: modprobe@loop.service: Deactivated successfully.",
        ] {
            assert!(systemd_units(line).next().is_none(), "{line}");
            assert_eq!(normalize(line).anchor, 0, "{line}");
        }
    }

    #[test]
    fn pci_identity_is_visible_in_messages_and_paths() {
        let normalizer = Normalizer::new(Config::default());
        for shape in [
            "[    0.125000] pci ADDRESS: enabling device (0000 -> 0002)",
            "[    0.125000] iommu: Using direct mapping for device ADDRESS",
            "warning device path=/sys/bus/pci/devices/ADDRESS/driver failed",
        ] {
            let a = normalizer
                .normalize_line(shape.replace("ADDRESS", "0000:3a:00.0"))
                .unwrap();
            let b = normalizer
                .normalize_line(shape.replace("ADDRESS", "0000:3a:00.1"))
                .unwrap();
            assert_ne!(a.anchor, b.anchor);
            assert_ne!(a.normalized, b.normalized);
            assert!(a.normalized.contains("0000:3a:00.0"), "{}", a.normalized);
            assert!(!a.normalized.contains('\0'));
        }
    }

    #[test]
    fn nested_pci_identities_keep_their_order_and_multiplicity() {
        let normalizer = Normalizer::new(Config::default());
        let one = normalizer
            .normalize_line(r#"method=GET path="/devices/0000:21:00.0""#.into())
            .unwrap();
        let two = normalizer
            .normalize_line(r#"method=GET path="/devices/0000:21:00.0?peer=0000:21:00.0""#.into())
            .unwrap();
        assert_ne!(one.anchor, two.anchor);
        assert_ne!(one.normalized, two.normalized);
        assert_eq!(one.normalized.matches("0000:21:00.0").count(), 1);
        assert_eq!(two.normalized.matches("0000:21:00.0").count(), 2);
        let literal = normalizer
            .normalize_line(r#"exe="/devices/0000:21:00.0/tool""#.into())
            .unwrap();
        assert_eq!(literal.normalized.matches("0000:21:00.0").count(), 1);
        let ordered = normalizer
            .normalize_line(
                r#"method=GET path="/devices?first=0000:21:00.0&second=0000:04:00.0""#.into(),
            )
            .unwrap();
        assert!(
            ordered.normalized.find("0000:21:00.0").unwrap()
                < ordered.normalized.find("0000:04:00.0").unwrap()
        );
    }

    #[test]
    fn pci_near_misses_do_not_gain_device_identity() {
        let normalizer = Normalizer::new(Config::default());
        for address in ["0000:21:00.8", "000:21:00.0", "0000:2g:00.0", "10.23.4.5"] {
            let line = normalizer
                .normalize_line(format!("device {address} enabled"))
                .unwrap();
            assert_eq!(line.anchor, 0, "{address}");
        }
    }

    #[test]
    fn nested_status_identities_keep_their_multiplicity() {
        let normalizer = Normalizer::new(Config::default());
        let one = normalizer
            .normalize_line(r#"method=GET path="/health?status=200""#.into())
            .unwrap();
        let two = normalizer
            .normalize_line(r#"method=GET path="/health?status=200&status=204""#.into())
            .unwrap();
        assert_ne!(one.anchor, two.anchor);
        assert_ne!(one.normalized, two.normalized);
        assert_eq!(two.normalized.matches("<STATUS_2XX>").count(), 2);
    }

    #[test]
    fn exact_anchor_identity_survives_path_and_number_detection() {
        let normalizer = Normalizer::new(Config::default());
        for (shape, identity) in [
            (
                r#"E0916 09:12:35.123456       8 controller.go:137] "Unhandled Error" err="context deadline exceeded""#,
                "controller.go:137",
            ),
            (
                r#"{"caller":"worker/task.go:137","msg":"operation completed"}"#,
                "worker/task.go:137",
            ),
            (
                r#"caller=/opt/src/worker.go:137 msg="operation completed""#,
                "/opt/src/worker.go:137",
            ),
            (
                "I0916 09:12:35.123456       8 reflector.go:137] local.dev/worker/task.go:241: forcing resync",
                "local.dev/worker/task.go:241",
            ),
            (
                r#"  File "/opt/app/worker.py", line 137, in stream"#,
                r#"File "/opt/app/worker.py", line 137, in stream"#,
            ),
            (
                r#"{"binary":"/usr/local/bin/worker","pid":123,"event":"exec"}"#,
                "/usr/local/bin/worker",
            ),
            (
                r#"exe="/usr/local/bin/worker" uid=1000 event=exec"#,
                "/usr/local/bin/worker",
            ),
        ] {
            let line = normalizer.normalize_line(shape.into()).unwrap();
            assert_ne!(line.anchor, 0, "{shape}");
            assert!(
                line.normalized.contains(identity),
                "{} must show {identity}",
                line.normalized
            );
            assert!(!line.normalized.contains('\0'), "{}", line.normalized);
        }
    }

    #[test]
    fn a_protected_klog_site_keeps_its_pid_column_and_respects_detector_flags() {
        let raw = "E0916 09:12:35.123456       8 controller.go:137] request complete";
        let line = Normalizer::new(Config::default())
            .normalize_line(raw.into())
            .unwrap();
        assert!(
            line.normalized.contains("<PID> controller.go:137]"),
            "{}",
            line.normalized
        );
        assert!(line.tokens.iter().any(|t| matches!(t, Token::Pid(8))));
        let config = Config {
            normalize_pids: false,
            ..Config::default()
        };
        let off = Normalizer::new(config).normalize_line(raw.into()).unwrap();
        assert!(!off.tokens.iter().any(|t| matches!(t, Token::Pid(_))));
        assert!(off.normalized.contains("controller.go:137]"));
    }

    #[test]
    fn frame_line_and_function_are_visible_even_with_the_same_file() {
        let normalizer = Normalizer::new(Config::default());
        let lines: Vec<_> = [
            r#"  File "/opt/app/worker.py", line 137, in stream"#,
            r#"  File "/opt/app/worker.py", line 241, in stream"#,
            r#"  File "/opt/app/worker.py", line 137, in poll"#,
        ]
        .into_iter()
        .map(|s| normalizer.normalize_line(s.into()).unwrap())
        .collect();
        for pair in lines.windows(2) {
            assert_ne!(pair[0].anchor, pair[1].anchor);
            assert_ne!(pair[0].normalized, pair[1].normalized);
        }
    }

    #[test]
    fn http_status_anchor_classes_remain_visible_and_codes_within_a_class_agree() {
        let normalizer = Normalizer::new(Config::default());
        for (shape, marker) in [
            (
                r#"method=GET path="/health" status=CODE bytes=120"#,
                "STATUS",
            ),
            (
                r#"{"RequestMethod":"GET","RequestPath":"/health","DownstreamStatus":CODE,"msg":"served"}"#,
                "STATUS",
            ),
            (
                r#"10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET /health HTTP/1.1" CODE 120 "-""#,
                "HTTP_STATUS",
            ),
            (r#"method=GET path="/health?status=CODE""#, "STATUS"),
        ] {
            let run = |code| {
                normalizer
                    .normalize_line(shape.replace("CODE", code))
                    .unwrap()
            };
            let a = run("200");
            let b = run("204");
            let c = run("503");
            assert_eq!(a.anchor, b.anchor, "{shape}");
            assert_ne!(a.anchor, c.anchor, "{shape}");
            assert_eq!(a.normalized, b.normalized, "{shape}");
            assert_ne!(a.normalized, c.normalized, "{shape}");
            assert!(
                a.normalized.contains(&format!("<{marker}_2XX>")),
                "{}",
                a.normalized
            );
            assert!(
                c.normalized.contains(&format!("<{marker}_5XX>")),
                "{}",
                c.normalized
            );
            if marker == "STATUS" {
                assert!(
                    a.tokens
                        .iter()
                        .any(|t| matches!(t, Token::Number(n) if n == "200"))
                );
                assert!(
                    b.tokens
                        .iter()
                        .any(|t| matches!(t, Token::Number(n) if n == "204"))
                );
            } else {
                assert!(
                    a.tokens
                        .iter()
                        .any(|t| matches!(t, Token::HttpStatusClass(c) if c == "2xx"))
                );
            }
        }
    }

    #[test]
    fn process_status_class_is_visible_without_claiming_it_is_http() {
        let line = Normalizer::new(Config::default())
            .normalize_line(
                "systemd[1]: worker.service: Main process exited, code=exited, status=127/NOTFOUND"
                    .into(),
            )
            .unwrap();
        assert!(
            line.normalized.contains("status=<STATUS_1XX>"),
            "{}",
            line.normalized
        );
        assert!(!line.normalized.contains("<HTTP_STATUS_"));
        assert!(
            line.tokens
                .iter()
                .any(|t| matches!(t, Token::Number(n) if n == "127"))
        );
        assert!(
            !line
                .tokens
                .iter()
                .any(|t| matches!(t, Token::HttpStatusClass(_)))
        );
    }

    #[test]
    fn a_protected_status_code_gives_the_fact_of_the_detector_it_was_hidden_from() {
        let fact = |source, http, durations| {
            let config = Config {
                normalize_http_status: http,
                normalize_durations: durations,
                ..Config::default()
            };
            ProtectedStatus {
                code: "204".to_string(),
                source,
            }
            .fact_of_the_detector_it_was_hidden_from(&config)
        };
        let class = Some(Token::HttpStatusClass("2xx".to_string()));
        let number = Some(Token::Number("204".to_string()));
        for durations in [false, true] {
            assert_eq!(fact(StatusSource::RequestLine, true, durations), class);
        }
        assert_eq!(fact(StatusSource::RequestLine, false, true), number);
        assert_eq!(fact(StatusSource::RequestLine, false, false), None);
        for http in [false, true] {
            assert_eq!(
                fact(StatusSource::StatusField, http, true),
                number,
                "a status field is a number, the duration detector's fact, whatever the HTTP flag"
            );
            assert_eq!(fact(StatusSource::StatusField, http, false), None);
        }
    }

    #[test]
    fn non_status_numbers_do_not_gain_http_anchor_markers() {
        let normalizer = Normalizer::new(Config::default());
        for text in [
            "status=600",
            "status=20",
            "status=2000",
            "request_count=200",
        ] {
            let line = normalizer.normalize_line(text.into()).unwrap();
            assert_eq!(line.anchor, 0, "{text}");
            assert!(!line.normalized.contains("<HTTP_STATUS_"), "{text}");
        }
    }

    #[test]
    fn route_ids_hash_and_render_alike() {
        let mut h1 = AHasher::default();
        let mut h2 = AHasher::default();
        hash_route("/api/devices/42/", &mut h1);
        hash_route("/api/devices/99/", &mut h2);
        assert_eq!(h1.finish(), h2.finish());
        assert_eq!(
            render_route("/api/devices/42/"),
            render_route("/api/devices/99/")
        );
        assert_eq!(render_route("/api/devices/42/"), "/api/devices/<N>/");
    }

    #[test]
    fn route_different_endpoints_hash_and_render_differently() {
        let mut h1 = AHasher::default();
        let mut h2 = AHasher::default();
        hash_route("/login/", &mut h1);
        hash_route("/metrics", &mut h2);
        assert_ne!(h1.finish(), h2.finish());
        assert_ne!(render_route("/login/"), render_route("/metrics"));
    }

    #[test]
    fn route_opaque_ids_render_as_id() {
        assert_eq!(
            render_route(
                "/blobs/sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
            ),
            "/blobs/<ID>"
        );
        assert_eq!(
            render_route("/objects/550e8400-e29b-41d4-a716-446655440000"),
            "/objects/<ID>"
        );
    }

    #[test]
    fn an_opaque_file_name_keeps_its_extension() {
        assert_eq!(
            render_route("/snap/000000000000000b-00000000000bee12.snap"),
            render_route("/snap/000000000000000b-00000000000bf0c3.snap"),
        );
        assert_eq!(
            render_route("/wal/0000000000000d4f-00000000c012fd.wal"),
            "/wal/<ID>.wal"
        );
        assert_ne!(
            render_route("/wal/0000000000000d4f-00000000c012fd.wal"),
            render_route("/wal/0000000000000d4f-00000000c012fd.snap")
        );
        assert_eq!(render_route("/pkg/1.25.3"), "/pkg/<N>.<N>.<N>");
    }

    #[test]
    fn a_route_in_a_field_value_is_visible_and_anchored() {
        let n = Normalizer::new(Config::default());
        let line = |s: &str| n.normalize_line(s.to_string()).unwrap();

        let login = line("GET ok url=https://shop.example/login?u=1 user=a1");
        let logout = line("GET ok url=https://shop.example/logout?u=1 user=a1");
        assert_eq!(
            login.normalized,
            "GET ok url=https://<HOST>/login?<QUERY> user=a1"
        );
        assert_ne!(login.hash, logout.hash);
        assert!(
            login
                .tokens
                .iter()
                .any(|t| matches!(t, Token::Path(p) if p == "https://shop.example/login?u=1"))
        );

        let a = line(r#"x url="https://a.example/item/1001?ref=a" y"#);
        let b = line(r#"x url="https://b.example/item/1002?ref=b" y"#);
        assert_eq!(a.normalized, r#"x url="https://<HOST>/item/<N>?<QUERY>" y"#);
        assert_eq!(a.normalized, b.normalized);
        assert_eq!(a.hash, b.hash);

        let users = line("x path=/api/v1/users/42 y");
        let users2 = line("x path=/api/v1/users/43 y");
        let orders = line("x path=/api/v1/orders/42 y");
        assert_eq!(users.normalized, "x path=/api/v<N>/users/<N> y");
        assert_eq!(users.hash, users2.hash);
        assert_ne!(users.hash, orders.hash);

        let listed = line("contact failed, url=http://10.0.0.7:8080/inform, rc=1");
        assert_eq!(
            listed.normalized.split(", ").nth(1),
            Some("url=http://<HOST>/inform")
        );

        assert_eq!(line("x path=relative/dir/file y").anchor, 0);
        assert_eq!(line("x MountPath:/var/run/x y").anchor, 0);
    }

    #[test]
    fn a_digit_between_letters_is_part_of_the_word() {
        assert_eq!(
            render_route("/k8s/apis/authorization.k8s.io/v1beta1/pods/42"),
            "/k8s/apis/authorization.k8s.io/v1beta<N>/pods/<N>"
        );
        let mut a = AHasher::default();
        let mut b = AHasher::default();
        hash_route("/k8s/pods/42", &mut a);
        hash_route("/k9s/pods/99", &mut b);
        assert_ne!(a.finish(), b.finish(), "k8s and k9s are different routes");
        let mut c = AHasher::default();
        let mut d = AHasher::default();
        hash_route("/k8s/pods/42", &mut c);
        hash_route("/k8s/pods/99", &mut d);
        assert_eq!(c.finish(), d.finish(), "the object id still folds");
    }

    fn route_hash(target: &str) -> u64 {
        let mut h = AHasher::default();
        hash_route(target, &mut h);
        h.finish()
    }

    #[test]
    fn a_generated_pod_name_in_a_route_segment_is_an_id() {
        assert_eq!(
            render_route("/api/v1/namespaces/shop/pods/web-7d9c5b8f4-x2kqz"),
            "/api/v<N>/namespaces/shop/pods/web-<SUFFIX>"
        );
        assert_eq!(
            route_hash("/api/v1/namespaces/shop/pods/web-7d9c5b8f4-x2kqz"),
            route_hash("/api/v1/namespaces/shop/pods/web-5f6b8c9d7-m4wzt")
        );
        assert_eq!(render_route("/pods/web-x2kqz"), "/pods/web-<SUFFIX>");
        assert_ne!(
            route_hash("/pods/web-7d9c5b8f4-x2kqz"),
            route_hash("/pods/api-7d9c5b8f4-x2kqz"),
            "the workload name is part of the route"
        );
    }

    fn audit_record(uri: &str, object_ref: &str, code: &str) -> String {
        format!(
            r#"{{"kind":"Event","stage":"ResponseComplete","requestURI":"{uri}","verb":"get","objectRef":{{{object_ref}}},"responseStatus":{{"metadata":{{}},"code":{code}}}}}"#
        )
    }

    #[test]
    fn a_code_inside_a_status_object_is_an_http_status_class() {
        let n = Normalizer::new(Config::default());
        let line = |code: &str| {
            n.normalize_line(audit_record("/readyz", r#""resource":"x""#, code))
                .unwrap()
        };
        let (failed, ok, created) = (line("500"), line("200"), line("201"));
        assert_ne!(failed.anchor, ok.anchor);
        assert_ne!(failed.normalized, ok.normalized);
        assert!(
            failed.normalized.contains(r#""code":<STATUS_5XX>"#),
            "{}",
            failed.normalized
        );
        assert_eq!(ok.anchor, created.anchor, "one class, one anchor");
        assert_eq!(ok.normalized, created.normalized);
        assert!(
            failed
                .tokens
                .iter()
                .any(|t| matches!(t, Token::Number(c) if c == "500"))
        );
    }

    #[test]
    fn a_status_object_code_is_three_digits_from_100_to_599() {
        let class = |code: &str| {
            let text = format!(r#"{{"responseStatus":{{"code":{code}}}}}"#);
            status_object_codes(&text)
                .next()
                .map(|(span, class)| (text[span].to_string(), class.to_string()))
        };
        assert_eq!(class("99"), None);
        assert_eq!(class("100"), Some(("100".into(), "1".into())));
        assert_eq!(class("599"), Some(("599".into(), "5".into())));
        assert_eq!(class("600"), None);
        assert_eq!(class("2000"), None);
        assert_eq!(class("200.5"), None);
        assert_eq!(class(r#""200""#), None);
    }

    #[test]
    fn only_the_code_member_of_the_status_object_itself_counts() {
        let found = |text: &str| status_object_codes(text).next().map(|(_, c)| c.to_string());
        assert_eq!(found(r#"{"error":{"code":500}}"#), None);
        assert_eq!(
            found(r#"{"responseStatus":{"details":{"code":500},"reason":"x"}}"#),
            None
        );
        assert_eq!(
            found(r#"{"responseStatus":{"message":"say \"code\":200","code":404}}"#),
            Some("4".into())
        );
        assert_eq!(
            found(r#"{"responseStatus":{"reason":"code","code" : 503}}"#),
            Some("5".into())
        );
        assert_eq!(
            found(r#"{"responseStatus":{"metadata":{}}},"code":500"#),
            None
        );
    }

    #[test]
    fn a_route_segment_the_record_names_is_a_name_placeholder() {
        let n = Normalizer::new(Config::default());
        let line = |uri: &str, object_ref: &str| {
            n.normalize_line(audit_record(uri, object_ref, "404"))
                .unwrap()
        };
        let orbit = line(
            "/apis/rbac.example.io/v1/clusterroles/orbit-reader",
            r#""resource":"clusterroles","name":"orbit-reader""#,
        );
        let lantern = line(
            "/apis/rbac.example.io/v1/clusterroles/lantern-editor",
            r#""resource":"clusterroles","name":"lantern-editor""#,
        );
        assert!(
            orbit
                .normalized
                .contains(r#""requestURI":"/apis/rbac.example.io/v<N>/clusterroles/<NAME>""#),
            "{}",
            orbit.normalized
        );
        assert_eq!(orbit.anchor, lantern.anchor);
        assert!(
            orbit
                .tokens
                .iter()
                .any(|t| matches!(t, Token::Name(v) if v == "orbit-reader"))
        );

        let orchard = line(
            "/api/v1/namespaces/orchard/limitranges",
            r#""resource":"limitranges","namespace":"orchard""#,
        );
        let tundra = line(
            "/api/v1/namespaces/tundra/limitranges",
            r#""resource":"limitranges","namespace":"tundra""#,
        );
        assert!(
            orchard
                .normalized
                .contains("/namespaces/<NAME>/limitranges"),
            "{}",
            orchard.normalized
        );
        assert_eq!(orchard.anchor, tundra.anchor);
    }

    #[test]
    fn a_segment_counts_as_named_only_when_its_own_line_names_it() {
        let n = Normalizer::new(Config::default());
        let line = |uri: &str, name: &str| {
            n.normalize_line(audit_record(
                uri,
                &format!(r#""resource":"clusterroles","name":"{name}""#),
                "404",
            ))
            .unwrap()
        };
        let named = line("/clusterroles/orbit-reader", "orbit-reader");
        let other_lines_name = line("/clusterroles/lantern-editor", "orbit-reader");
        assert!(
            other_lines_name
                .normalized
                .contains("/clusterroles/lantern-editor"),
            "{}",
            other_lines_name.normalized
        );
        assert_ne!(named.anchor, other_lines_name.anchor);
    }

    #[test]
    fn the_resource_segment_and_the_scope_stay_part_of_the_route() {
        let named = |line: &str, route: &str| RecordIdentity::of(line).named_segments(route);
        assert_eq!(
            named(r#""resource":"pods","name":"pods""#, "/api/v1/pods"),
            0,
            "a name equal to the resource type leaves the resource segment literal"
        );
        assert_eq!(
            named(
                r#""resource":"configmaps","name":"api""#,
                "/api/v1/configmaps/api"
            ),
            1 << 4,
            "only the last segment equal to a name, after a collection, is the name"
        );
        assert_eq!(
            named(
                r#""resource":"pods","namespace":"alpha","name":"kiosk-q7zrt""#,
                "/api/v1/namespaces/alpha/pods/kiosk-q7zrt"
            ),
            (1 << 4) | (1 << 6)
        );
        assert_eq!(named(r#""username":"orbit""#, "/users/orbit"), 0);

        let n = Normalizer::new(Config::default());
        let cluster = n
            .normalize_line(audit_record("/api/v1/pods", r#""resource":"pods""#, "200"))
            .unwrap();
        let namespaced = n
            .normalize_line(audit_record(
                "/api/v1/namespaces/alpha/pods",
                r#""resource":"pods","namespace":"alpha""#,
                "200",
            ))
            .unwrap();
        assert_ne!(cluster.anchor, namespaced.anchor);
    }

    #[test]
    fn a_long_hex_tail_after_a_dot_is_an_opaque_id() {
        assert_eq!(
            render_route("/events/kiosk.1a2f3e4d5c6b7a89"),
            "/events/kiosk.<ID>"
        );
        assert_ne!(
            render_route("/events/kiosk.1a2f3e4d5c6b7a8"),
            "/events/kiosk.<ID>",
            "fifteen hex digits are not yet an opaque id"
        );
        assert_eq!(
            render_route("/events/kiosk-5d8f9c7b6-q7zrt.1a2f3e4d5c6b7a89"),
            "/events/kiosk-<SUFFIX>.<ID>"
        );
        assert_eq!(
            route_hash("/events/kiosk.1a2f3e4d5c6b7a89"),
            route_hash("/events/kiosk.17f3a9c2d4e5b6a7")
        );
        assert_ne!(
            route_hash("/events/kiosk.1a2f3e4d5c6b7a89"),
            route_hash("/events/ledger.1a2f3e4d5c6b7a89")
        );
    }

    #[test]
    fn a_route_segment_without_a_generated_suffix_is_classified_as_before() {
        assert_eq!(
            render_route("/leases/kube-scheduler"),
            "/leases/kube-scheduler"
        );
        assert_eq!(
            render_route("/configmaps/app-config"),
            "/configmaps/app-config"
        );
        assert_eq!(render_route("/items/item-42"), "/items/item-<N>");
        assert_eq!(render_route("/docs/start-en"), "/docs/start-en");
        assert_ne!(
            route_hash("/docs/start-en"),
            route_hash("/docs/start-de"),
            "a short word after a dash is not a generated suffix"
        );
        assert_eq!(render_route("/builds/run-20241105"), "/builds/run-<N>");
    }

    #[test]
    fn a_route_with_a_query_hashes_apart_from_one_without() {
        assert_ne!(
            route_hash("/leases/kube-scheduler?timeout=5s"),
            route_hash("/leases/kube-scheduler")
        );
        assert_eq!(
            route_hash("/leases/kube-scheduler?timeout=5s"),
            route_hash("/leases/kube-scheduler?timeout=10s&watch=1"),
            "the query's content is not part of the route"
        );
        assert_eq!(
            route_hash("/leases/kube-scheduler#top"),
            route_hash("/leases/kube-scheduler"),
            "a fragment is not a query"
        );
    }

    #[test]
    fn a_route_query_renders_as_a_placeholder() {
        assert_eq!(
            render_route(
                "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/kube-scheduler?timeout=5s"
            ),
            "/apis/coordination.k8s.io/v<N>/namespaces/kube-system/leases/kube-scheduler?<QUERY>"
        );
        assert_eq!(render_route("/search?"), "/search?<QUERY>");
        assert_eq!(render_route("/search#q=1"), "/search");
        assert_eq!(render_route("/search"), "/search");
    }

    #[test]
    fn ordinary_file_paths_stay_paths_but_program_identity_is_visible() {
        let normalizer = Normalizer::new(Config::default());
        let line = normalizer
            .normalize_line(r#"exe="/usr/bin/sudo""#.to_string())
            .unwrap();
        assert_eq!(line.normalized, r#"exe="/usr/bin/sudo""#);

        let line = normalizer
            .normalize_line("workerEnv.init() ok /var/log/app/42/status".to_string())
            .unwrap();
        assert_eq!(line.normalized, "workerEnv.init() ok <PATH>");

        let line = normalizer
            .normalize_line("saw pod/x/y earlier".to_string())
            .unwrap();
        assert_eq!(line.normalized, "saw <PATH> earlier");
    }

    fn rendered_prefix(line: &str) -> String {
        let caps = KUBECTL_PREFIX
            .captures(line)
            .expect("test line opens with a kubectl prefix");
        let (pod, container) = pod_prefix_parts(&caps);
        render_pod_prefix(pod, container)
    }

    #[test]
    fn a_pod_prefix_renders_its_workload() {
        assert_eq!(
            rendered_prefix("[pod/rook-ceph-rgw-s3-a-b69d45f98-dwxsc/rgw]"),
            "[pod/rook-ceph-rgw-s3-<SUFFIX>/rgw]"
        );
        assert_eq!(rendered_prefix("[pod/etcd/etcd]"), "[pod/etcd/etcd]");
    }

    #[test]
    fn the_pod_prefix_hash_and_render_agree() {
        let cases = [
            "[pod/llm-d-sim-67cb674c47-d6ms5/vllm-render]",
            "[pod/llm-d-sim-67cb674c47-f86lm/vllm-render]",
            "[pod/render-twin-5c9c5df548-dxqmk/vllm-render]",
            "[pod/gitaly-0/gitaly]",
            "[pod/gitaly-1/gitaly]",
        ];
        for case in cases {
            let caps = KUBECTL_PREFIX.captures(case).expect("test case matches");
            let pod = caps.get(1).map_or("", |m| m.as_str());
            let skeleton = pod_skeleton(pod);
            let rendered = rendered_prefix(case);
            assert!(
                rendered.contains(skeleton),
                "{rendered} must contain the hashed skeleton {skeleton}"
            );
        }

        assert_eq!(
            rendered_prefix("[pod/llm-d-sim-67cb674c47-d6ms5/vllm-render]"),
            rendered_prefix("[pod/llm-d-sim-67cb674c47-f86lm/vllm-render]")
        );
        assert_ne!(
            rendered_prefix("[pod/llm-d-sim-67cb674c47-d6ms5/vllm-render]"),
            rendered_prefix("[pod/render-twin-5c9c5df548-dxqmk/vllm-render]")
        );
        assert_ne!(
            rendered_prefix("[pod/llm-d-sim-67cb674c47-d6ms5/vllm-render]"),
            rendered_prefix("[pod/llm-d-sim-67cb674c47-d6ms5/other]")
        );
    }

    #[test]
    fn the_kubectl_prefix_is_on_the_line() {
        let normalizer = Normalizer::new(Config::default());
        let normalize = |s: &str| normalizer.normalize_line(s.to_string()).unwrap().normalized;

        let first = normalize("[pod/llm-d-sim-67cb674c47-d6ms5/vllm-render] GET /health");
        let second = normalize("[pod/llm-d-sim-67cb674c47-f86lm/vllm-render] GET /health");
        assert_eq!(first, second, "two replicas of one workload");
        assert!(first.contains("[pod/llm-d-sim-<SUFFIX>/vllm-render]"));
        assert!(
            !first.contains("<PATH>"),
            "no <PATH> in the prefix: {first}"
        );

        let third = normalize("[pod/render-twin-5c9c5df548-dxqmk/vllm-render] GET /health");
        assert_ne!(first, third, "another workload");

        let fourth = normalize("[pod/llm-d-sim-67cb674c47-d6ms5/other] GET /health");
        assert_ne!(first, fourth, "same pod, different container");
    }

    #[test]
    fn a_kubernetes_word_does_not_switch_detectors_off() {
        let normalizer = Normalizer::new(Config::default());
        let norm = |s: &str| normalizer.normalize_line(s.to_string()).unwrap();
        let plain = norm("[proxy] [upstream] probe failed");
        let k8s = norm("[proxy] [upstream] probe failed for pod/web-0 on kubelet");
        assert!(
            plain
                .normalized
                .starts_with("<BRACKET_CONTEXT> probe failed")
        );
        assert!(
            k8s.normalized.starts_with("<BRACKET_CONTEXT> probe failed"),
            "{}",
            k8s.normalized
        );
        let json = norm(
            r#"{"level":"info","ts":"2024-01-01T10:00:00.000Z","component":"kubelet","msg":"Starting container"}"#,
        );
        assert!(
            json.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "{:?}",
            json.tokens
        );
    }

    #[test]
    fn table_structured_matches_non_k8s() {
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

        assert_eq!(
            line.normalized,
            "2025-01-20 10:15:30 Connection to <NUMBER>.<NUMBER>.1.<NUMBER> failed"
        );
    }

    #[test]
    fn test_port_detection_vs_timestamps() {
        let config = Config::default();
        let normalizer = Normalizer::new(config);

        let line1 = normalizer
            .normalize_line("2025-01-20 10:15:30 Connection failed".to_string())
            .unwrap();

        assert_eq!(line1.normalized, "<TIMESTAMP> Connection failed");
        assert!(
            line1
                .tokens
                .iter()
                .any(|t| matches!(t, Token::Timestamp(_)))
        );
        assert!(!line1.tokens.iter().any(|t| matches!(t, Token::Port(_))));

        let line2 = normalizer
            .normalize_line("Connection to localhost:8080 failed".to_string())
            .unwrap();

        assert_eq!(line2.normalized, "Connection to localhost:<PORT> failed");
        assert!(line2.tokens.iter().any(|t| matches!(t, Token::Port(8080))));

        let line3 = normalizer
            .normalize_line("Connection to 192.168.1.1:3000 failed".to_string())
            .unwrap();

        assert_eq!(line3.normalized, "Connection to <IP>:<PORT> failed");
        assert!(line3.tokens.iter().any(|t| matches!(t, Token::IPv4(_))));
        assert!(line3.tokens.iter().any(|t| matches!(t, Token::Port(3000))));

        let line4 = normalizer
            .normalize_line("Connection to [2001:db8::1]:8080 failed".to_string())
            .unwrap();

        assert_eq!(line4.normalized, "Connection to [<IP>]:<PORT> failed");
        assert!(line4.tokens.iter().any(|t| matches!(t, Token::IPv6(_))));
        assert!(line4.tokens.iter().any(|t| matches!(t, Token::Port(8080))));
    }

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
        assert!(
            (score - 200.0 / 3.0).abs() < 1e-9,
            "Expected 66.7, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_tolerates_token_insertion() {
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("ERROR: conn refused to backend xyz".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("node1 ERROR: conn refused to backend xyz".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
        assert!(
            score > 90.0,
            "insertion-shifted line should score high, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_common_prefix_not_enough() {
        let normalizer = Normalizer::new(Config::default());
        let a = normalizer
            .normalize_line("svc api gateway east db conn pool exhausted".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("svc api gateway east tls handshake err peer".to_string())
            .unwrap();
        let score = normalizer.similarity_score(&a, &b);
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

        let seven_match = normalizer.normalize_line("abcdefg".to_string()).unwrap();
        let score = normalizer.similarity_score(&seven_match, &ten_chars);
        assert!(
            score.abs() < f64::EPSILON,
            "At boundary (0.7), token comparison applies. Got {score}"
        );

        let six_match = normalizer.normalize_line("abcdef".to_string()).unwrap();
        let score_below = normalizer.similarity_score(&six_match, &ten_chars);
        assert!(
            (score_below - 60.0).abs() < f64::EPSILON,
            "Below boundary, should return ratio*100=60.0. Got {score_below}"
        );

        let seven_mismatch = normalizer.normalize_line("abcdefz".to_string()).unwrap();
        let score_mismatch = normalizer.similarity_score(&seven_mismatch, &ten_chars);
        assert!(
            score_mismatch.abs() < f64::EPSILON,
            "At boundary with mismatch, token comparison gives 0.0. Got {score_mismatch}"
        );

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
        assert!(
            (score - 90.0).abs() < f64::EPSILON,
            "Expected 90.0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_empty_vs_nonempty() {
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
        let normalizer = Normalizer::new(Config::default());
        let short = LogLine::new("abc".into(), "abc".into(), vec![], 0);
        let long = LogLine::new("abcdefghij".into(), "abcdefghij".into(), vec![], 1);
        let score = normalizer.similarity_score(&short, &long);
        assert!(
            (score - 30.0).abs() < f64::EPSILON,
            "3/10 ratio should give 30.0, got {score}"
        );
    }

    const BYTE_FALLBACK_TOKENS: usize = crate::patterns::MAX_HASHED_TOKENS + 1;

    #[test]
    fn test_similarity_score_byte_fallback_division_direction() {
        let normalizer = Normalizer::new(Config::default());
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
        let normalizer = Normalizer::new(Config::default());
        let score =
            normalizer.similarity_score(&raw_line("   ".into(), 0), &raw_line("    ".into(), 1));
        assert!(
            (score - 75.0).abs() < f64::EPSILON,
            "whitespace-only lines should byte-compare to 75.0, got {score}"
        );
    }

    #[test]
    fn test_similarity_score_one_side_whitespace_only() {
        let normalizer = Normalizer::new(Config::default());
        let blank = || raw_line("    ".into(), 0);
        let lead = || raw_line("a   ".into(), 1);
        for (x, y) in [(blank(), lead()), (lead(), blank())] {
            let score = normalizer.similarity_score(&x, &y);
            assert!(
                (score - 75.0).abs() < f64::EPSILON,
                "tokenless side should byte-compare to 75.0, got {score}"
            );
        }
    }

    #[test]
    fn test_similarity_score_token_reorder_partial() {
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
        let mk = |last: &str| {
            let mut s: String = std::iter::repeat_n("tok ", 63).collect();
            s.push_str(last);
            s
        };
        let normalizer = Normalizer::new(Config::default());
        let score = normalizer.similarity_score(&raw_line(mk("aaa"), 0), &raw_line(mk("bbb"), 1));
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

    #[test]
    fn normalize_line_json_disabled_no_detection() {
        let config = Config {
            normalize_json: false,
            ..Config::default()
        };
        let n = Normalizer::new(config);
        let line = n.normalize_line(r"&Event{Type: Warning}".into()).unwrap();
        assert!(
            !line
                .tokens
                .iter()
                .any(|t| matches!(t, Token::EmbeddedJson(_))),
            "JSON detection should be disabled"
        );
    }

    #[test]
    fn structured_detection_brace_only() {
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
        let n = Normalizer::new(Config::default());
        let line = n
            .normalize_line("level=error component=web msg=fail".into())
            .unwrap();
        assert!(
            line.tokens.iter().any(|t| matches!(
                t,
                Token::StructuredMessage { .. } | Token::KeyValuePair { .. }
            )),
            "Equals-only input should trigger structured or KV detection: {:?}",
            line.tokens
        );
    }

    #[test]
    fn normalize_timestamps_disabled_with_colon_input() {
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

    #[test]
    fn quoted_detection_single_quote_only() {
        let n = Normalizer::new(Config::default());
        let line = n
            .normalize_line("mount 'very-long-volume-name-that-exceeds-threshold-ok' done".into())
            .unwrap();
        let _ = line;
    }

    #[test]
    fn json_detector_folds_an_event_metadata_block() {
        let (_, direct_tokens) = crate::patterns::json::JsonDetector::detect_and_replace(
            "&Event{ObjectMeta:{web-a.17f3  default    0 map[] []},Reason:Pulled}",
        );
        assert!(
            direct_tokens
                .iter()
                .any(|t| matches!(t, Token::EmbeddedJson(_))),
            "JsonDetector should detect Event objects: {direct_tokens:?}"
        );
    }

    #[test]
    fn the_json_flag_decides_an_event_block_once_the_path_detector_is_off() {
        let input = "&Event{ObjectMeta:{web-a.17f3  default    0 map[] []},Reason:Pulled}";
        let json_on = run(|c| c.normalize_paths = false, input);
        let json_off = run(
            |c| {
                c.normalize_paths = false;
                c.normalize_json = false;
            },
            input,
        );
        assert_eq!(json_on.normalized, "<EVENT_OBJECT>,Reason:Pulled}");
        assert!(
            json_on
                .tokens
                .iter()
                .any(|t| matches!(t, Token::EmbeddedJson(_)))
        );
        assert_eq!(json_off.normalized, input);
        assert!(
            !json_off
                .tokens
                .iter()
                .any(|t| matches!(t, Token::EmbeddedJson(_)))
        );
    }

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
        let input = "level=info component=api-gateway msg=ready";
        let (_, direct) =
            crate::patterns::structured::StructuredMessageDetector::detect_and_replace(input);
        assert!(
            direct
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "detector itself must fire on {input:?}, got {direct:?}"
        );
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
    fn each_structured_half_answers_only_to_its_own_flag() {
        let json = r#"{"level":"info","component":"api","msg":"set a=b"}"#;
        let logfmt = "level=info component=api-gateway msg=ready";
        let has_record = |line: LogLine| {
            line.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. }))
        };
        assert!(has_record(run(|_| {}, json)));
        assert!(has_record(run(|_| {}, logfmt)));
        assert!(!has_record(run(|c| c.normalize_json = false, json)));
        assert!(has_record(run(|c| c.normalize_json = false, logfmt)));
        assert!(has_record(run(|c| c.normalize_key_value = false, json)));
        assert!(!has_record(run(|c| c.normalize_key_value = false, logfmt)));
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
        let input = "service api-deploy-7d9f8b6c5-x1y2z started";
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
        assert!(off.normalized.contains("<HTTP_STATUS_4XX>"));
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

    #[test]
    fn similarity_score_division_not_multiplication() {
        let normalizer = Normalizer::new(Config::default());
        let short = LogLine::new("xyz".into(), "xyz".into(), vec![], 0);
        let long = LogLine::new("abcdefghij".into(), "abcdefghij".into(), vec![], 1);
        let score = normalizer.similarity_score(&short, &long);
        assert!(
            score > 20.0,
            "3/10 ratio should give 30.0, got {score} (if 0.0, division was mutated to *)"
        );
    }

    #[test]
    fn test_multiset_intersection_counts_multiplicity() {
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
        assert_eq!(Normalizer::multiset_intersection(&[1, 2, 3, 4], &[4]), 1);
        assert_eq!(Normalizer::multiset_intersection(&[4], &[1, 2, 3, 4]), 1);
    }

    #[test]
    fn test_multiset_intersection_asymmetric_duplicates() {
        assert_eq!(Normalizer::multiset_intersection(&[5, 5], &[5, 9]), 1);
        assert_eq!(Normalizer::multiset_intersection(&[5, 9], &[5, 5]), 1);
    }

    #[test]
    fn test_are_similar_float_boundary_58_of_100() {
        let words = |prefix: char, from: usize, to: usize| -> Vec<String> {
            (from..to)
                .map(|i| {
                    let hi = char::from(b'a' + (i / 26) as u8);
                    let lo = char::from(b'a' + (i % 26) as u8);
                    format!("{prefix}{hi}{lo}")
                })
                .collect()
        };
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
        let normalizer = Normalizer::new(Config::default());
        let a = raw_line("ccc ccc ccc         ".to_string(), 1);
        let b = raw_line("ccc ccc xxx ccc ccc ccc".to_string(), 2);
        let score = normalizer.similarity_score(&a, &b);
        assert!(
            (score - 200.0 / 3.0).abs() < 1e-9,
            "expected 66.67, got {score}"
        );
    }

    #[test]
    fn test_are_similar_agrees_with_score_exhaustively() {
        let vocab = [
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
            "lambda", "mu",
        ];
        let mut lines: Vec<String> = Vec::new();
        for n in 1..=12usize {
            lines.push(vocab[..n].join(" "));
            let mut mid = vocab[..n].to_vec();
            mid[n / 2] = "XXXXX";
            lines.push(mid.join(" "));
            let mut rev = vocab[..n].to_vec();
            rev.reverse();
            lines.push(rev.join(" "));
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

    fn normalize(line: &str) -> LogLine {
        Normalizer::new(Config::default())
            .normalize_line(line.to_string())
            .unwrap()
    }

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
        assert!(
            normalizer.similarity_score(&login, &admin) >= f64::from(Config::default().threshold),
            "the point of the anchor is that similarity alone does not separate these"
        );
    }

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

    #[test]
    fn anchor_ignores_messages_about_units() {
        let line = normalize(
            "Sep 14 06:38:27 oryx systemd[1]: Starting containerd.service - containerd container runtime...",
        );
        assert_eq!(line.anchor, 0);
    }

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
        let prose = normalize("event type=CRED_ACQ msg=audit(1.0:1): done");
        assert_eq!(prose.anchor, 0);
    }

    #[test]
    fn audit_syscall_outcomes_are_visible_identities() {
        let header = "type=SYSCALL msg=audit(1789430400.123:801): arch=c000003e syscall=42";
        let yes = normalize(&format!("{header} success=yes exit=0"));
        let no = normalize(&format!("{header} success=no exit=-2"));
        assert_ne!(yes.anchor, no.anchor);
        assert!(yes.normalized.contains("success=yes"));
        assert!(no.normalized.contains("success=no"));
        let another = normalize(
            "type=SYSCALL msg=audit(1789430999.456:912): arch=c000003e syscall=42 success=yes exit=4",
        );
        assert_eq!(yes.anchor, another.anchor);
        assert_eq!(
            no.anchor,
            normalize(&format!("{header} success=no exit=-13")).anchor
        );
    }

    #[test]
    fn audit_outcome_needs_the_syscall_header_position() {
        for line in [
            "event success=yes exit=0",
            "event type=SYSCALL msg=audit(1789430400.123:801): arch=c000003e syscall=42 success=yes exit=0",
            "type=EXECVE msg=audit(1789430400.123:801): argc=1 a0=\"success=yes\"",
            "type=SYSCALL msg=audit(1789430400.123:801): note=\"arch=c000003e syscall=42 success=yes\"",
            "type=SYSCALL msg=audit(1789430400.123:801): arch=c000003e syscall=42 success=yesplease",
            "type=SYSCALL msg=audit(1789430400.123:801): arch=c000003e syscall=42 success=yes,no",
        ] {
            assert!(
                !AUDIT_SYSCALL_OUTCOME.is_match(line),
                "false outcome identity: {line}"
            );
            assert_eq!(
                normalize(line).anchor,
                normalize(&line.replace("success=yes", "success=no")).anchor,
                "outcome-like prose must not change identity: {line}"
            );
        }
    }

    #[test]
    fn cli_option_names_are_identity_but_values_are_not() {
        let first = normalize(r#"{"msg":"worker --mode alpha -t 120"}"#);
        let second = normalize(r#"{"msg":"worker --mode beta -t 240"}"#);
        let other = normalize(r#"{"msg":"worker --scope alpha -t 120"}"#);
        assert_eq!(first.anchor, second.anchor);
        assert_ne!(first.anchor, other.anchor);
        assert!(first.normalized.contains("--mode"));
        assert!(first.normalized.contains("-t"));
        assert_eq!(normalize("event -sdown master example").anchor, 0);
        assert_eq!(normalize("event -namespace example").anchor, 0);
        let numeric_name = normalize("worker --http1234-port=4567");
        assert!(numeric_name.normalized.contains("--http1234-port="));
    }

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

    #[test]
    fn anchor_is_folded_into_the_line_hash() {
        let login = normalize(
            r#"[2026-08-16 14:08:34 +0200] ::ffff - "GET /login/ HTTP/1.1" 200 17450.949"#,
        );
        let admin = normalize(
            r#"[2026-08-16 14:08:34 +0200] ::ffff - "GET /admin/ HTTP/1.1" 200 17450.949"#,
        );
        assert_ne!(
            login.normalized, admin.normalized,
            "an anchored route renders as its skeleton, so a split it forces is visible on the line"
        );
        assert_ne!(
            login.hash, admin.hash,
            "the hash must still tell them apart"
        );
    }

    fn wide_line(state: &str, n: usize) -> String {
        let tail: Vec<String> = (0..n).map(|i| format!("f{i}=v{i}")).collect();
        format!("evt one two {state} {}", tail.join(" "))
    }

    #[test]
    fn overflow_lines_fold_like_short_ones() {
        let normalizer = Normalizer::new(Config::default());
        let short = |s: &str| normalizer.normalize_line(wide_line(s, 10)).unwrap();
        let long = |s: &str| normalizer.normalize_line(wide_line(s, 200)).unwrap();

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
        let huge = crate::patterns::MAX_HASHED_TOKENS + 10;
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
        assert_eq!(first.normalized, second.normalized);
        assert!(
            first
                .normalized
                .contains("[pod/llm-d-sim-<SUFFIX>/vllm-render]")
        );
        assert_ne!(first.normalized, third.normalized);
        assert_ne!(first.normalized, fourth.normalized);
        assert!(
            !first.normalized.contains("<PATH>"),
            "no <PATH> in the kubectl prefix: {}",
            first.normalized
        );
        let ord0 = normalize("[pod/gitaly-0/gitaly] x");
        let ord1 = normalize("[pod/gitaly-1/gitaly] x");
        assert_eq!(ord0.anchor, ord1.anchor, "statefulset ordinals");
        assert_eq!(ord0.normalized, ord1.normalized);
        assert_eq!(
            ord0.normalized, "[pod/gitaly-<SUFFIX>/gitaly] x",
            "the ordinal strips"
        );
        let osd0 = normalize("[pod/rook-ceph-osd-0-56d5fdf8f8-ltzv5/osd] x");
        let osd1 = normalize("[pod/rook-ceph-osd-1-6bb486f64d-njdks/osd] x");
        let mon_bp = normalize("[pod/rook-ceph-mon-bp-74f99bc8b4-v8d9g/mon] x");
        let mon_cc = normalize("[pod/rook-ceph-mon-cc-69db7dc6fc-72pbb/mon] x");
        assert_eq!(
            osd0.anchor, osd1.anchor,
            "the same daemon on another instance"
        );
        assert_eq!(osd0.normalized, osd1.normalized);
        assert_eq!(mon_bp.anchor, mon_cc.anchor, "instance letters");
        assert_eq!(mon_bp.normalized, mon_cc.normalized);
        assert_ne!(osd0.anchor, mon_bp.anchor, "osd is not mon");
        assert_ne!(osd0.normalized, mon_bp.normalized);
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

#[cfg(test)]
mod key_value_gate_2026_08_29 {
    use super::*;

    #[test]
    fn key_value_folding_needs_an_unquoted_equals_sign() {
        assert!(KeyValueDetector::has_pair_outside_quotes(
            "time=x level=info"
        ));
        assert!(!KeyValueDetector::has_pair_outside_quotes(
            r#"{"exec_id":"Z2Y2M2I6MjI3MDk3MjQ5MzY5NDM3ODoyMTYwMDUz=", "pid":2160053}"#
        ));
        assert!(!KeyValueDetector::has_pair_outside_quotes(
            r#"{"msg":"a=b inside"}"#
        ));
        assert!(KeyValueDetector::has_pair_outside_quotes(
            r#"msg="quoted" key=value"#
        ));
    }

    #[test]
    fn a_json_record_whose_only_equals_sign_is_quoted_keeps_its_values() {
        let line = r#"{"exec_id":"Z2Y2M2I6MjI3MDk3MjQ5=","retries":3}"#;
        assert!(
            KeyValueDetector::detect_and_replace(line)
                .0
                .contains("<KEY_VALUE>"),
            "the detector folds JSON values on its own, so the table must keep it off this line"
        );
        let normalized = Normalizer::new(Config::default())
            .normalize_line(line.to_string())
            .unwrap()
            .normalized;
        assert!(!normalized.contains("<KEY_VALUE>"), "{normalized}");
    }
}

#[cfg(test)]
mod program_anchor_2026_08_29 {
    use super::*;

    fn normalize(line: &str) -> LogLine {
        Normalizer::new(Config::default())
            .normalize_line(line.to_string())
            .unwrap()
    }

    #[test]
    fn the_program_a_record_names_is_its_identity() {
        let sudo = normalize(
            r#"type=SYSCALL msg=audit(1481077232.471:485): arch=c000003e syscall=59 success=yes exit=0 comm="sudo" exe="/usr/bin/sudo" key=(null)"#,
        );
        let sshd = normalize(
            r#"type=SYSCALL msg=audit(1481077232.471:486): arch=c000003e syscall=59 success=yes exit=0 comm="sshd" exe="/usr/sbin/sshd" key=(null)"#,
        );
        let sudo2 = normalize(
            r#"type=SYSCALL msg=audit(1481077299.100:490): arch=c000003e syscall=59 success=yes exit=0 comm="sudo" exe="/usr/bin/sudo" key=(null)"#,
        );
        assert_ne!(sudo.anchor, sshd.anchor);
        assert_eq!(sudo.anchor, sudo2.anchor);
        let runc = normalize(
            r#"[pod/tetragon-fbkw6/export-stdout] {"process_exec":{"process":{"exec_id":"Z2Y2M2I6MjI3MDk3MjQ5MzY5NDM3ODoyMTYwMDUz", "pid":2160053, "binary":"/var/lib/rancher/rke2/bin/runc", "arguments":"exec"}}}"#,
        );
        let redis = normalize(
            r#"[pod/tetragon-fbkw6/export-stdout] {"process_exec":{"process":{"exec_id":"Z2Y2M2I6MjI3MDk3MjcwNTgxMDUzNzoyMTYwMDkx", "pid":2160091, "binary":"/usr/bin/redis-cli", "arguments":"ping"}}}"#,
        );
        assert_ne!(runc.anchor, redis.anchor);
        assert!(
            runc.normalized.contains(r#""exec_id":"<UUID>""#),
            "{}",
            runc.normalized
        );
    }
}

#[cfg(test)]
mod syslog_host_tests_2026_08_29 {
    use super::*;

    fn normalize(line: &str) -> LogLine {
        Normalizer::new(Config::default())
            .normalize_line(line.to_string())
            .unwrap()
    }

    #[test]
    fn a_positional_host_folds_across_devices_and_tag_shapes() {
        let bracket_pid = normalize("Aug 29 08:40:15 usw-core-1 dnsmasq[123]: query[A] x");
        let bare_tag = normalize("Aug 29 08:40:15 usw-core-2 kernel: link up");
        let facility_level = normalize("Aug 29 08:40:15 ap-hall-3 daemon.err syslogd: restart");
        assert_eq!(
            bracket_pid.normalized,
            "<TIMESTAMP> <HOST> dnsmasq[<PID>]: query[A] x"
        );
        assert_eq!(bare_tag.normalized, "<TIMESTAMP> <HOST> kernel: link up");
        assert_eq!(
            facility_level.normalized,
            "<TIMESTAMP> <HOST> daemon.err syslogd: restart"
        );
        assert!(
            bracket_pid
                .tokens
                .iter()
                .any(|t| matches!(t, Token::SyslogHost(h) if h == "usw-core-1"))
        );
    }

    #[test]
    fn rfc5424_timestamp_hosts_fold_too() {
        let line = normalize("2026-08-29T08:40:15Z node7 sshd[1]: accepted");
        assert!(
            line.normalized
                .starts_with("<TIMESTAMP> <HOST> sshd[<PID>]:")
        );
    }

    #[test]
    fn a_severity_word_in_the_host_slot_is_left_alone() {
        let line = normalize("Aug 29 08:40:15 INFO main: starting up");
        assert!(!line.normalized.contains("<HOST>"), "{}", line.normalized);
        assert_eq!(line.normalized, "<TIMESTAMP> INFO main: starting up");
    }

    #[test]
    fn a_second_word_with_no_tag_is_left_alone() {
        let line = normalize("Aug 29 08:40:15 gw-core rebooted after power loss");
        assert!(!line.normalized.contains("<HOST>"), "{}", line.normalized);
    }

    #[test]
    fn an_already_tokenised_host_is_left_as_is() {
        let line = normalize("Aug 29 08:40:15 gw-core.example.com kernel: link up");
        assert!(
            !line.normalized.contains("<HOST>"),
            "an FQDN host stays <FQDN>: {}",
            line.normalized
        );
        assert!(line.normalized.contains("<FQDN>"), "{}", line.normalized);
    }
}

#[cfg(test)]
mod threshold_zero_2026_09_17 {
    use super::*;

    #[test]
    #[allow(clippy::float_cmp)]
    fn at_threshold_zero_disjoint_unanchored_lines_are_similar() {
        let normalizer = Normalizer::new(Config {
            threshold: 0,
            ..Config::default()
        });
        let a = normalizer
            .normalize_line("alpha bravo charlie delta".to_string())
            .unwrap();
        let b = normalizer
            .normalize_line("echo foxtrot golf hotel".to_string())
            .unwrap();
        assert_ne!(a.hash, b.hash);
        assert_eq!(a.anchor, b.anchor, "plain words carry no anchor");
        assert_eq!(normalizer.similarity_score(&a, &b), 0.0);
        assert!(
            normalizer.are_similar(&a, &b),
            "threshold 0 must accept a pair with nothing in common"
        );
        let strict = Normalizer::new(Config::default());
        assert!(!strict.are_similar(&a, &b));
    }
}

#[cfg(test)]
mod e8v_normalize_2026_09_17 {
    use super::*;

    fn normalize_with(config: Config, line: &str) -> LogLine {
        Normalizer::new(config)
            .normalize_line(line.to_string())
            .unwrap()
    }

    fn normalize(line: &str) -> LogLine {
        normalize_with(Config::default(), line)
    }

    #[test]
    fn a_lowercase_cpu_field_reaches_the_cpu_quantity_pass() {
        let line = normalize("resources cpu=500m memory=256Mi");
        assert!(
            line.normalized.contains("<CPU_QUANTITY>"),
            "{}",
            line.normalized
        );
        assert!(
            !line.normalized.contains("cpu=<KEY_VALUE>"),
            "{}",
            line.normalized
        );
    }

    #[test]
    fn a_json_record_is_still_structured_with_key_value_disabled() {
        let cfg = Config {
            normalize_key_value: false,
            ..Config::default()
        };
        let line = normalize_with(
            cfg,
            r#"{"level":"info","component":"core","msg":"started"}"#,
        );
        assert!(
            line.tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "{:?}",
            line.tokens
        );
    }

    #[test]
    fn a_disabled_structured_half_does_not_run_on_its_shape() {
        let no_json = Config {
            normalize_json: false,
            ..Config::default()
        };
        let json = normalize_with(
            no_json,
            r#"{"level":"info","component":"core","msg":"started"}"#,
        );
        assert!(
            !json
                .tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "{:?}",
            json.tokens
        );
        let no_kv = Config {
            normalize_key_value: false,
            ..Config::default()
        };
        let logfmt = normalize_with(no_kv, r#"level=info component=core msg="started""#);
        assert!(
            !logfmt
                .tokens
                .iter()
                .any(|t| matches!(t, Token::StructuredMessage { .. })),
            "{:?}",
            logfmt.tokens
        );
    }

    #[test]
    fn a_kernel_uptime_line_has_no_syslog_host() {
        let line = normalize("[    5.450000] usb usb1: New USB bus registered");
        assert!(!line.normalized.contains("<HOST>"), "{}", line.normalized);
    }

    #[test]
    fn a_bracket_free_module_shape_is_left_alone() {
        for line in [
            "daemon.err sshd: ERROR bad key from peer",
            "daemon.info mod_agent: ready",
        ] {
            let l = normalize(line);
            assert!(
                !l.tokens
                    .iter()
                    .any(|t| matches!(t, Token::LogWithModule { .. })),
                "{line}: {:?}",
                l.tokens
            );
            assert!(
                !l.normalized.contains("<LOG_WITH_MODULE>"),
                "{line}: {}",
                l.normalized
            );
        }
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_quoted_value() {
        assert!(!KeyValueDetector::has_pair_outside_quotes(r#""a \"b c=d""#));
        assert!(KeyValueDetector::has_pair_outside_quotes(r#""a b" c=d"#));
    }

    #[test]
    fn a_leading_dot_with_a_colon_does_not_panic_the_pci_prefilter() {
        let line = normalize(".5 a:b done");
        assert!(!line.normalized.is_empty());
    }

    #[test]
    fn a_facility_level_word_is_not_a_host_but_lookalikes_are() {
        let shape = normalize("Aug 29 08:40:15 daemon.info syslogd: started");
        assert!(!shape.normalized.contains("<HOST>"), "{}", shape.normalized);
        assert!(!shape.normalized.contains("<FQDN>"), "{}", shape.normalized);
        let bare = normalize("Aug 29 08:40:15 daemon. syslogd: started");
        assert!(bare.normalized.contains("<HOST>"), "{}", bare.normalized);

        assert!(is_facility_level_shape("daemon.info"));
        assert!(is_facility_level_shape("authpriv.notice"));
        for lookalike in [
            "Daemon.info",
            "daemon.Info",
            "daemon.a.b",
            "daemon.",
            ".info",
            "daemon",
        ] {
            assert!(!is_facility_level_shape(lookalike), "{lookalike}");
        }
    }

    #[test]
    fn a_colon_word_is_not_a_host_and_a_trailing_bracket_does_not_disqualify() {
        let colon = normalize("Aug 29 08:40:15 gw:1 kernel: link up");
        assert!(!colon.normalized.contains("<HOST>"), "{}", colon.normalized);
        let angle = normalize("Aug 29 08:40:15 gw> kernel: link up");
        assert!(angle.normalized.contains("<HOST>"), "{}", angle.normalized);
    }

    #[test]
    fn human_words_of_generated_lengths_stay_in_the_pod_skeleton() {
        assert_eq!(pod_skeleton("web-nginx-x7k2q"), "web-nginx");
        assert_eq!(pod_skeleton("web-frontend-x7k2q"), "web-frontend");
        assert_eq!(pod_skeleton("web-x7k2q-x7k2q"), "web");
    }

    #[test]
    fn a_lowercase_method_field_alone_reaches_the_method_anchor() {
        let line = normalize(r#"method=GET path="/api/v1/items" status=200"#);
        assert!(!line.normalized.contains("<PATH>"), "{}", line.normalized);
        assert!(line.normalized.contains("/api/"), "{}", line.normalized);
    }

    #[test]
    fn a_field_value_is_a_route_only_when_written_as_one() {
        assert!(is_route_shaped("/srv/data"));
        assert!(is_route_shaped("https://a.example/x"));
        assert!(!is_route_shaped("relative/dir"));
        assert!(!is_route_shaped("://a.example/x"));
        assert!(!is_route_shaped("h2c-1://a.example/x"));
        assert_eq!(normalize("x path=relative/dir/file to=/srv y").anchor, 0);
    }

    fn either_side(line: &str, later: &str, earlier: &str) -> (String, String) {
        let mut order: Vec<&DetectorEntry> = DETECTOR_ORDER.iter().collect();
        let from = order.iter().position(|e| e.name == later).unwrap();
        let moved = order.remove(from);
        let at = order.iter().position(|e| e.name == earlier).unwrap();
        let n = Normalizer::new(Config::default());
        let run = |to: usize| {
            let mut order = order.clone();
            order.insert(to, moved);
            n.normalize_in_order(line.to_string(), order.into_iter())
                .unwrap()
                .normalized
        };
        (run(at + 1), run(at))
    }

    #[test]
    fn every_declared_order_rule_changes_its_line() {
        for entry in DETECTOR_ORDER {
            for (earlier, line) in entry.after {
                let (after, before) = either_side(line, entry.name, earlier);
                assert_ne!(
                    after, before,
                    "`{}` after `{earlier}` is declared, but its line reads the same either way: {line}",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn every_order_dependence_on_a_corpus_line_is_declared() {
        let mut lines: Vec<String> = Vec::new();
        let corpora = std::fs::read_dir("examples/distilled")
            .expect("examples/distilled must exist: this test reads every corpus");
        for entry in corpora {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "log") {
                let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
                lines.extend(text.lines().filter(|l| l.len() <= 2000).map(str::to_string));
            }
        }
        assert!(lines.len() > 1000, "only {} corpus lines", lines.len());
        let n = Normalizer::new(Config::default());
        let run = |line: &str, order: &[&DetectorEntry]| {
            n.normalize_in_order(line.to_string(), order.iter().copied())
                .unwrap()
                .normalized
        };
        let table: Vec<&DetectorEntry> = DETECTOR_ORDER.iter().collect();
        let mut undeclared = Vec::new();
        for later in 1..table.len() {
            let mut prev: Vec<String> = lines.iter().map(|l| run(l, &table)).collect();
            for k in (0..later).rev() {
                let mut order = table.clone();
                let moved = order.remove(later);
                order.insert(k, moved);
                let now: Vec<String> = lines.iter().map(|l| run(l, &order)).collect();
                let changed: Vec<usize> =
                    (0..lines.len()).filter(|&at| now[at] != prev[at]).collect();
                let declared = table[later].after.iter().any(|(e, _)| *e == table[k].name);
                if let (false, Some(&shortest)) =
                    (declared, changed.iter().min_by_key(|&&at| lines[at].len()))
                {
                    undeclared.push(format!(
                        "`{}` after `{}`: {} corpus lines, the shortest:\n  {}\n  after:  {}\n  before: {}",
                        table[later].name,
                        table[k].name,
                        changed.len(),
                        lines[shortest],
                        prev[shortest],
                        now[shortest]
                    ));
                }
                prev = now;
            }
        }
        assert!(
            undeclared.is_empty(),
            "{} undeclared order rule(s):\n{}",
            undeclared.len(),
            undeclared.join("\n")
        );
    }

    #[test]
    fn detector_order_keeps_what_each_entry_declares() {
        let order: Vec<&DetectorEntry> = DETECTOR_ORDER.iter().collect();
        assert_eq!(order_complaints(&order), Vec::<String>::new());
        assert_eq!(order.len(), 20);
    }

    #[test]
    fn a_reorder_that_breaks_a_declared_constraint_is_named() {
        let at = |name: &str| DETECTOR_ORDER.iter().position(|e| e.name == name).unwrap();
        let swapped = |a: &str, b: &str| {
            let mut order: Vec<&DetectorEntry> = DETECTOR_ORDER.iter().collect();
            order.swap(at(a), at(b));
            order_complaints(&order)
        };
        assert_eq!(
            swapped("uuid", "hash"),
            vec![
                "`hash` must come after `uuid`",
                "`hash` must come after `network`"
            ]
        );
        assert_eq!(
            swapped("name", "quoted"),
            vec![
                "`quoted` must come after `name`",
                "`name` (Generic) comes after `quoted` (Last)"
            ]
        );
        let mut twice: Vec<&DetectorEntry> = DETECTOR_ORDER.iter().collect();
        twice.push(&DETECTOR_ORDER[at("quoted")]);
        assert_eq!(
            order_complaints(&twice),
            vec!["`quoted` is in the table twice"]
        );
        let lone = [&DETECTOR_ORDER[at("uuid")]];
        assert_eq!(
            order_complaints(&lone),
            vec![
                "`uuid` must come after `timestamp`",
                "`uuid` must come after `path`"
            ]
        );
    }

    #[test]
    fn the_same_identity_in_two_anchor_classes_is_two_anchors() {
        let one = |class| anchor_hash(&mut [(class, AnchorIdentity::Text("GET"))]);
        assert_ne!(one(AnchorClass::Method), one(AnchorClass::Program));
        let split = |first, second| {
            anchor_hash(&mut [
                (first, AnchorIdentity::Text("x")),
                (second, AnchorIdentity::Text("y")),
            ])
        };
        assert_ne!(
            split(AnchorClass::Caller, AnchorClass::Program),
            split(AnchorClass::Method, AnchorClass::Program),
            "x as a caller and x as a method are different anchors beside the same program"
        );
    }

    #[test]
    fn a_nested_identity_shows_by_its_own_kind_and_by_what_covers_it() {
        use NestedIdentity::{EveryOccurrence, Hidden, OnceUnlessShown};
        for cover_verbatim in [false, true] {
            for (render, expected) in [
                (AnchorRender::Route, Hidden),
                (AnchorRender::ProseTarget { named: 0 }, Hidden),
                (
                    AnchorRender::PodPrefix {
                        pod: "web-0",
                        container: "app",
                    },
                    Hidden,
                ),
                (AnchorRender::HttpStatus, EveryOccurrence),
                (AnchorRender::StatusField, EveryOccurrence),
                (AnchorRender::Exact, OnceUnlessShown),
                (AnchorRender::KlogCallSite, OnceUnlessShown),
                (AnchorRender::SystemdUnit, OnceUnlessShown),
            ] {
                assert_eq!(render.when_nested(cover_verbatim), expected);
            }
        }
        assert_eq!(
            AnchorRender::PciAddress.when_nested(false),
            EveryOccurrence,
            "a route skeleton drops its query, so each PCI address in it is appended"
        );
        assert_eq!(
            AnchorRender::PciAddress.when_nested(true),
            OnceUnlessShown,
            "a verbatim cover already shows the PCI address inside it"
        );
    }

    #[test]
    fn an_open_gate_or_a_scan_that_finds_nothing_passes() {
        assert!(gate(true, "t", "line", || true));
        assert!(gate(true, "t", "line", || false));
        assert!(!gate(false, "t", "line", || false));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "turned away a line its pattern matches")]
    fn a_gate_narrower_than_its_pattern_stops_a_test_build() {
        gate(false, "t", "line", || true);
    }

    #[test]
    fn field_routes_are_the_route_shaped_values_without_closing_punctuation() {
        let line = r#"x path=/api/a; dir=relative url="https://a.example/b" uri="/c""#;
        let found: Vec<_> = field_routes(line, false).collect();
        assert_eq!(
            found,
            vec![(7, "/api/a"), (33, "https://a.example/b"), (59, "/c")]
        );
        let found: Vec<_> = field_routes(line, true).collect();
        assert_eq!(found, vec![(7, "/api/a")]);
    }

    #[test]
    fn a_line_with_no_route_field_shape_stops_at_the_byte_gate() {
        assert!(!may_hold_route_field(r#"opened "/srv/data" for path"#));
        assert!(!may_hold_route_field(r#"path, "/srv/data""#));
        assert!(!may_hold_route_field("path = relative"));
    }

    #[test]
    fn a_quoted_route_keeps_its_anchor_with_spaces_around_the_separator() {
        let a = normalize(r#"x path = "/api/a" y"#).anchor;
        let b = normalize(r#"x path = "/api/b" y"#).anchor;
        assert_ne!(a, 0);
        assert_ne!(a, b);
        assert_eq!(a, normalize(r#"x path="/api/a" y"#).anchor);
    }

    #[test]
    fn each_written_form_of_a_route_field_passes_the_byte_gate() {
        for s in [
            "x url=https://a.example/b y",
            "x path=/api/a y",
            r#"x path="/api/a" y"#,
            r#"x "path":"/api/a" y"#,
            r#"x "path": "/api/a" y"#,
            r#"x path = "/api/a" y"#,
            r#"x path= "/api/a" y"#,
            "x \"path\":\t \"/api/a\" y",
        ] {
            assert!(may_hold_route_field(s), "{s}");
            assert_ne!(normalize(s).anchor, 0, "{s}");
        }
    }

    #[test]
    fn a_file_named_by_an_id_keeps_only_an_extension_written_as_one() {
        assert_eq!(render_route("/files/0011aabb.snap"), "/files/<ID>.snap");
        assert_eq!(render_route("/files/0011aabb.7z"), "/files/<N>aabb.<N>z");
        assert_eq!(
            render_route("/files/0011aabb.tar-gz"),
            "/files/<N>aabb.tar-gz"
        );
    }

    #[test]
    fn an_http_method_field_makes_any_quoted_path_field_a_route() {
        let items = normalize(r#"method=GET path="items/42" y"#);
        let orders = normalize(r#"method=GET path="orders/42" y"#);
        assert_ne!(items.anchor, orders.anchor);
    }

    #[test]
    fn a_path_the_method_rule_anchored_is_not_also_a_field_route() {
        let line = normalize(r#"method=GET path="/api/v1/items" status=200"#);
        assert!(
            !line.tokens.iter().any(|t| matches!(t, Token::Path(_))),
            "{:?}",
            line.tokens
        );
    }

    #[test]
    fn tokens_with_the_same_small_int_tail_shape_are_equal() {
        let normalizer = Normalizer::new(Config::default());
        let first = normalizer
            .normalize_line("job worker1 done ok".into())
            .unwrap();
        let second = normalizer
            .normalize_line("job worker2 done ok".into())
            .unwrap();
        assert!(normalizer.are_similar(&first, &second));
        let third = normalizer
            .normalize_line("job worker1 done ok".into())
            .unwrap();
        let fourth = normalizer
            .normalize_line("job slot1 done ok".into())
            .unwrap();
        assert!(!normalizer.are_similar(&third, &fourth));
    }
}

#[cfg(test)]
mod e8v_multiset_2026_09_18 {
    use super::*;

    #[test]
    fn cpu_quantities_are_recognized_before_a_path_consumes_the_cpu_label() {
        let n = Normalizer::new(Config::default());
        let line = n.normalize_line("/sys/fs/cgroup/cpu 500m".into()).unwrap();
        assert_eq!(line.normalized, "<PATH> <CPU_QUANTITY>");
        assert!(
            line.tokens
                .iter()
                .any(|t| matches!(t, Token::CpuQuantity(_)))
        );
    }

    #[test]
    fn a_long_line_with_one_widened_value_is_similar_by_token_bag() {
        let n = Normalizer::new(Config::default());
        let tail = (0..crate::patterns::MAX_SIMILARITY_TOKENS + 36)
            .map(|i| format!("word{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let short = n
            .normalize_line(format!("job started for tenant x {tail}"))
            .unwrap();
        let long = n
            .normalize_line(format!(
                "job started for tenant xxxxxxxxxxxxxxxxxxxxxxxx {tail}"
            ))
            .unwrap();
        assert!(short.sim().sorted_hashes().len() > crate::patterns::MAX_SIMILARITY_TOKENS);
        assert!(n.are_similar(&short, &long));
    }
}

fn mix_anchor_hash(base_hash: u64, anchor: u64) -> u64 {
    base_hash ^ anchor.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

#[cfg(test)]
mod anchor_hash_mixing_tests {
    use super::mix_anchor_hash;

    #[test]
    fn distinct_anchors_remain_distinct_for_a_fixed_base_hash() {
        for base_hash in [0, u64::MAX] {
            let keys = [0, 1, 2].map(|anchor| mix_anchor_hash(base_hash, anchor));
            for i in 0..keys.len() {
                for j in i + 1..keys.len() {
                    assert_ne!(keys[i], keys[j], "base {base_hash}, anchors {i} and {j}");
                }
            }
        }
    }
}
