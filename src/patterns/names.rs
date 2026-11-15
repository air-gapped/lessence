use regex::Regex;
use std::sync::LazyLock;

use super::Token;

static SYSTEMD_TEMPLATE_UNIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\b(?P<template>[a-z][a-z0-9-]*)@[a-z0-9][a-z0-9._:-]*\.(?P<unit_type>{})\b",
        super::SYSTEMD_UNIT_TYPES.join("|")
    ))
    .expect("Failed to compile template unit regex")
});

const WORD_OR_DIGIT_SEGMENT: &str = "[a-z0-9]+";
const PLACEHOLDER_SEGMENT: &str = "<[A-Z_]+>";

static HYPHENATED_NAMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\b(?P<prefix>[a-z][a-z0-9]*(?:-(?:{WORD_OR_DIGIT_SEGMENT}|{PLACEHOLDER_SEGMENT}))*)-(?P<suffix>[a-z0-9]{{{MIN_SUFFIX_LEN},}})\b"
    ))
    .expect("Failed to compile hyphenated names regex")
});

pub(crate) const K8S_RAND_ALPHABET: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";

const MIN_SUFFIX_LEN: usize = 5;
const K8S_RAND_SUFFIX_LEN: usize = 5;
const POD_TEMPLATE_HASH_LEN: std::ops::RangeInclusive<usize> = 8..=10;

static ALWAYS_GENERATED_FAMILIES: &[&str] = &[
    "kube-api-access",
    "kube-proxy",
    "kube-controller",
    "kube-scheduler",
    "nvidia-device-plugin",
    "nvidia-container-toolkit",
    "node-feature-discovery",
    "container-runtime",
    "csi-rbdplugin",
    "virt-handler",
    "cilium-envoy",
];

static WORD_SUFFIXES: &[&str] = &[
    "stable", "latest", "master", "worker", "server", "client", "proxy", "cache", "store", "admin",
    "config", "service",
];

pub struct NameDetector;

impl NameDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        if !Self::may_hold_name(text) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        if result.contains('@') {
            result = SYSTEMD_TEMPLATE_UNIT
                .replace_all(&result, |caps: &regex::Captures| {
                    tokens.push(Token::Name(caps[0].to_string()));
                    format!("{}@<INSTANCE>.{}", &caps["template"], &caps["unit_type"])
                })
                .to_string();
        }

        result = HYPHENATED_NAMES
            .replace_all(&result, |caps: &regex::Captures| {
                let prefix = &caps["prefix"];
                let suffix = &caps["suffix"];
                let full_name = &caps[0];
                let preceding_segment = prefix.rsplit('-').next().unwrap_or("");

                let generated = Self::is_variable_suffix(preceding_segment, suffix)
                    || Self::is_always_generated_family_suffix(prefix, suffix);
                if generated {
                    tokens.push(Token::Name(full_name.to_string()));
                    format!("{}-<SUFFIX>", Self::strip_generated_segments(prefix))
                } else {
                    full_name.to_string()
                }
            })
            .to_string();

        (result, tokens)
    }

    fn may_hold_name(text: &str) -> bool {
        text.contains('-') || text.contains('@')
    }

    fn is_always_generated_family_suffix(prefix: &str, suffix: &str) -> bool {
        Self::is_k8s_rand_suffix(suffix)
            && ALWAYS_GENERATED_FAMILIES
                .iter()
                .any(|family| Self::ends_with_segment(prefix, family))
    }

    fn is_variable_suffix(preceding_segment: &str, suffix: &str) -> bool {
        if suffix.len() < MIN_SUFFIX_LEN {
            return false;
        }

        if WORD_SUFFIXES.contains(&suffix) {
            return false;
        }

        if Self::is_rand_chunk_after_variable_segment(preceding_segment, suffix) {
            return true;
        }

        if super::is_designator(suffix) && !Self::is_k8s_rand(suffix) {
            return false;
        }

        Self::is_hash_like(suffix)
    }

    fn is_k8s_rand_suffix(suffix: &str) -> bool {
        suffix.len() == K8S_RAND_SUFFIX_LEN && Self::is_k8s_rand(suffix)
    }

    fn is_rand_chunk_after_variable_segment(preceding_segment: &str, suffix: &str) -> bool {
        Self::is_k8s_rand_suffix(suffix)
            && (preceding_segment.starts_with('<') || Self::is_pod_template_hash(preceding_segment))
    }

    fn is_pod_template_hash(segment: &str) -> bool {
        POD_TEMPLATE_HASH_LEN.contains(&segment.len()) && Self::is_k8s_rand(segment)
    }

    fn is_hash_like(suffix: &str) -> bool {
        let has_letters = suffix.chars().any(char::is_alphabetic);
        let has_numbers = suffix.chars().any(char::is_numeric);
        let all_lowercase = suffix.chars().all(|c| c.is_lowercase() || c.is_numeric());
        has_letters && has_numbers && all_lowercase
    }

    fn is_k8s_rand(s: &str) -> bool {
        s.bytes().all(|b| K8S_RAND_ALPHABET.contains(&b))
    }

    fn ends_with_segment(prefix: &str, family: &str) -> bool {
        prefix
            .strip_suffix(family)
            .is_some_and(|head| head.is_empty() || head.ends_with('-'))
    }

    fn strip_generated_segments(prefix: &str) -> &str {
        let mut base = prefix;
        while let Some((head, last)) = base.rsplit_once('-') {
            let generated = last.starts_with('<') || Self::is_pod_template_hash(last);
            if !generated {
                break;
            }
            base = head;
        }
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hyphenated_name_detection() {
        for (input, expected, reason) in [
            (
                "pod pushprox-kube-proxy-client-9djm4",
                "pod pushprox-kube-proxy-client-<SUFFIX>",
                "hash-like suffix",
            ),
            (
                "volume kube-api-access-52r58",
                "volume kube-api-access-<SUFFIX>",
                "hash-like suffix",
            ),
            (
                "container cilium-kh8lj",
                "container cilium-<SUFFIX>",
                "hash-like suffix",
            ),
            (
                "service nginx-stable",
                "service nginx-stable",
                "stable is a word suffix",
            ),
            (
                "app my-service",
                "app my-service",
                "service is a word suffix",
            ),
        ] {
            let (result, _tokens) = NameDetector::detect_and_replace(input);
            assert_eq!(result, expected, "{reason}: {input}");
        }
    }

    #[test]
    fn generated_pod_name_after_placeholder_is_one_name() {
        let cases = [
            (
                "pod web-v2-<HASH>-hcwqj ready",
                "pod web-v2-<SUFFIX> ready",
                "hex template hash already <HASH>, digit-free suffix",
            ),
            (
                "Pod/ledger-all-in-1-v2-<HASH>-x4q7c",
                "Pod/ledger-all-in-1-v2-<SUFFIX>",
                "digit-led segment inside the base name",
            ),
            (
                "pod backup-db-<NUMBER>-tvszq",
                "pod backup-db-<SUFFIX>",
                "CronJob minute already <NUMBER>",
            ),
            (
                "pod portal-5b8dfd9ck-bdwdp",
                "pod portal-<SUFFIX>",
                "non-hex template hash left by the hash detector",
            ),
            (
                "Pulled Pod/web-<HASH>-hcwqj image",
                "Pulled Pod/web-<SUFFIX> image",
                "the whole name is one token, not just its tail",
            ),
        ];
        for (input, expected, reason) in cases {
            let (result, tokens) = NameDetector::detect_and_replace(input);
            assert_eq!(result, expected, "{reason}: {input}");
            assert!(
                tokens.iter().any(|t| matches!(t, Token::Name(_))),
                "no Name token ({reason}): {input}"
            );
        }
    }

    #[test]
    fn a_generated_name_keeps_its_component() {
        let (a, _) =
            NameDetector::detect_and_replace("restarted container nginx-a1b2c3 after probe");
        let (b, _) =
            NameDetector::detect_and_replace("restarted container redis-d4e5f6 after probe");
        assert_eq!(a, "restarted container nginx-<SUFFIX> after probe");
        assert_eq!(b, "restarted container redis-<SUFFIX> after probe");
        assert_eq!(
            NameDetector::strip_generated_segments("web-v2-<HASH>"),
            "web-v2"
        );
        assert_eq!(
            NameDetector::strip_generated_segments("portal-5b8dfd9ck"),
            "portal"
        );
        assert_eq!(NameDetector::strip_generated_segments("<HASH>"), "<HASH>");
        assert_eq!(
            NameDetector::strip_generated_segments("backup-db-<NUMBER>"),
            "backup-db"
        );
    }

    #[test]
    fn systemd_template_unit_instance_is_the_variable() {
        let (r, t) = NameDetector::detect_and_replace(
            "Starting modprobe@configfs.service - Load Kernel Module configfs; user@1000.service up",
        );
        assert_eq!(
            r,
            "Starting modprobe@<INSTANCE>.service - Load Kernel Module configfs; user@<INSTANCE>.service up"
        );
        assert_eq!(t.len(), 2);
        let (r, _) = NameDetector::detect_and_replace("mail root@example.com sent");
        assert_eq!(r, "mail root@example.com sent");
    }

    #[test]
    fn generated_family_takes_an_all_letter_suffix() {
        let (r, _) = NameDetector::detect_and_replace(
            "volume kube-api-access-jwjsk in projected/<UUID>-kube-api-access-hcwqj pod cilium-envoy-vmvkk not osd-prepare-nztxp",
        );
        assert_eq!(
            r,
            "volume kube-api-access-<SUFFIX> in projected/<UUID>-kube-api-access-<SUFFIX> pod cilium-envoy-<SUFFIX> not osd-prepare-nztxp"
        );
        assert!(!NameDetector::ends_with_segment(
            "mykube-api-access",
            "kube-api-access"
        ));
        assert!(NameDetector::ends_with_segment(
            "x-kube-api-access",
            "kube-api-access"
        ));
    }

    #[test]
    fn lone_all_letter_suffix_stays_literal() {
        for input in [
            "port proxy-https open",
            "db main-pgsql up",
            "pod osd-prepare-g8-nztxp done",
        ] {
            let (result, tokens) = NameDetector::detect_and_replace(input);
            assert_eq!(
                result, input,
                "a rand-alphabet word with no variable segment before it is a word"
            );
            assert!(tokens.is_empty(), "{input}");
        }
    }

    #[test]
    fn a_hash_like_suffix_needs_letters_and_digits() {
        for suffix in ["9djm4", "52r58", "kh8lj"] {
            assert!(NameDetector::is_variable_suffix("", suffix), "{suffix}");
        }
        for (suffix, reason) in [
            ("abcde", "no digit"),
            ("abc", "under 5 chars"),
            ("stable", "a word suffix"),
            ("123", "under 5 chars"),
        ] {
            assert!(
                !NameDetector::is_variable_suffix("", suffix),
                "{reason}: {suffix}"
            );
        }
    }

    #[test]
    fn k8s_rand_suffix_needs_a_variable_segment_before_it() {
        assert!(NameDetector::is_variable_suffix("<HASH>", "hcwqj"));
        assert!(NameDetector::is_variable_suffix("<NUMBER>", "tvszq"));
        assert!(
            NameDetector::is_variable_suffix("5b8dfd9ck", "bdwdp"),
            "a 9-char template hash"
        );
        for (preceding, suffix, reason) in [
            ("proxy", "https", "a word before it"),
            ("<HASH>", "hcwqa", "`a` is not in the alphabet"),
            ("<HASH>", "hcwqjx", "6 chars is no rand suffix"),
            ("abcdefgh", "hcwqj", "vowels: no template hash"),
            ("bcdfghj", "hcwqj", "7 chars: too short for a template hash"),
            (
                "bcdfghjklmn",
                "hcwqj",
                "11 chars: too long for a template hash",
            ),
        ] {
            assert!(
                !NameDetector::is_variable_suffix(preceding, suffix),
                "{reason}: {preceding}-{suffix}"
            );
        }
    }

    #[test]
    fn k8s_rand_alphabet_has_no_vowels_y_or_0_1_3() {
        let mut expected: Vec<u8> = (b'a'..=b'z')
            .chain(b'0'..=b'9')
            .filter(|b| !b"aeiouy013".contains(b))
            .collect();
        expected.sort_unstable();
        let mut alphabet = K8S_RAND_ALPHABET.to_vec();
        alphabet.sort_unstable();
        assert_eq!(alphabet, expected);
    }

    #[test]
    fn every_systemd_unit_type_takes_an_instance() {
        for unit in super::super::SYSTEMD_UNIT_TYPES {
            let (out, tokens) =
                NameDetector::detect_and_replace(&format!("Starting getty@tty1.{unit} now"));
            assert_eq!(
                out,
                format!("Starting getty@<INSTANCE>.{unit} now"),
                "{unit}"
            );
            assert_eq!(tokens.len(), 1, "{unit}");
        }
        let (out, _) = NameDetector::detect_and_replace("Set up automount boot@efi.automount");
        assert_eq!(out, "Set up automount boot@<INSTANCE>.automount");
    }

    #[test]
    fn variable_suffix_boundary_4_chars() {
        assert!(!NameDetector::is_variable_suffix("", "ab1c"));
    }

    #[test]
    fn variable_suffix_boundary_5_chars() {
        assert!(NameDetector::is_variable_suffix("", "ab1c2"));
    }
}

#[cfg(test)]
mod shapes_2026_08_29 {
    use super::*;

    #[test]
    fn letters_then_digits_is_a_designator_not_a_suffix() {
        for line in [
            "with ssh-ed25519 key",
            "cipher aes-sha256 x",
            "proto tcp-ipv6 y",
        ] {
            let (r, _) = NameDetector::detect_and_replace(line);
            assert_eq!(r, line, "{line}");
        }
        let (r, _) = NameDetector::detect_and_replace("pod api-deploy-7d9f8b6c5 x");
        assert!(r.contains("<SUFFIX>"), "{r}");
    }
}

#[cfg(test)]
mod hyphen_or_at_fast_path {
    use super::*;

    #[test]
    fn a_hyphenated_name_without_an_at_sign_is_still_detected() {
        let line = "pod cebo-model-cache-x7k2q ready";
        let (out, tokens) = NameDetector::detect_and_replace(line);
        assert_ne!(out, line, "{tokens:?}");
        assert!(out.contains("<SUFFIX>"), "{out}");
    }

    #[test]
    fn a_template_unit_without_a_hyphen_is_still_detected() {
        let (out, _) = NameDetector::detect_and_replace("Starting getty@tty1.service now");
        assert_eq!(out, "Starting getty@<INSTANCE>.service now");
    }
}
