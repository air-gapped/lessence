use regex::Regex;
use std::sync::LazyLock;

use super::Token;

// Generic hyphenated names with variable suffixes:
// component-name-suffix, kube-api-access-suffix. A prefix segment may be a
// word, a digit-led chunk (`v2`, `1`, a pod-template hash) or a placeholder
// an earlier detector left behind (`<HASH>`, `<NUMBER>`), so a generated
// Kubernetes name such as `web-v2-<HASH>-7j5z7` is seen as one name.
// A systemd template unit instance: `modprobe@configfs.service`,
// `user@1000.service`, `getty@tty1.service`. The template is the name, the
// instance is the variable.
static TEMPLATE_UNIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([a-z][a-z0-9-]*)@([a-z0-9][a-z0-9._:-]*)\.(service|socket|timer|mount|target|slice|scope|path|device|swap)\b")
        .expect("Failed to compile template unit regex")
});

static HYPHENATED_NAMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([a-z][a-z0-9]*(?:-(?:[a-z0-9]+|<[A-Z_]+>))*)-([a-z0-9]{5,})\b")
        .expect("Failed to compile hyphenated names regex")
});

// The alphabet Kubernetes draws generated-name suffixes and pod-template
// hashes from (k8s.io/apimachinery rand.String): no vowels, no y, no 0/1/3.
pub(crate) const K8S_RAND_ALPHABET: &[u8] = b"bcdfghjklmnpqrstvwxz2456789";

// Common prefixes that should be preserved (not treated as variable)
static COMMON_PREFIXES: &[&str] = &[
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

pub struct NameDetector;

impl NameDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // FAST PATH: Skip if no hyphens (most lines won't have hyphenated names)
        if !text.contains('-') && !text.contains('@') {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        if result.contains('@') {
            result = TEMPLATE_UNIT
                .replace_all(&result, |caps: &regex::Captures| {
                    tokens.push(Token::Name(caps[0].to_string()));
                    format!("{}@<INSTANCE>.{}", &caps[1], &caps[3])
                })
                .to_string();
        }

        // Replace hyphenated names with variable suffixes
        result = HYPHENATED_NAMES
            .replace_all(&result, |caps: &regex::Captures| {
                let prefix = caps.get(1).unwrap().as_str();
                let suffix = caps.get(2).unwrap().as_str();
                let full_name = caps.get(0).unwrap().as_str();
                let prev = prefix.rsplit('-').next().unwrap_or("");

                // A variable suffix: hash-like, or a rand chunk after another
                // variable segment, or a rand chunk on a family whose names
                // are always generated (`kube-api-access-jwjsk`).
                let generated = Self::is_variable_suffix(prev, suffix)
                    || (suffix.len() == 5
                        && Self::is_k8s_rand(suffix)
                        && COMMON_PREFIXES
                            .iter()
                            .any(|p| Self::ends_with_segment(prefix, p)));
                if generated {
                    // Check if the prefix is a known common pattern
                    if Self::is_common_prefix(prefix) {
                        tokens.push(Token::Name(full_name.to_string()));
                        format!("{prefix}-<SUFFIX>")
                    } else {
                        // Generic component name
                        tokens.push(Token::Name(full_name.to_string()));
                        "<COMPONENT>-<SUFFIX>".to_string()
                    }
                } else {
                    // Keep original if suffix doesn't look variable
                    full_name.to_string()
                }
            })
            .to_string();

        (result, tokens)
    }

    /// `prev` is the prefix segment right before the suffix.
    fn is_variable_suffix(prev: &str, suffix: &str) -> bool {
        // Variable suffixes are typically:
        // - 5+ characters mixed alphanumeric (hash-like)
        // - Contains both letters and numbers
        // - Exclude common English words

        if suffix.len() < 5 {
            return false;
        }

        // Exclude common English words that aren't variable
        let common_words = &[
            "stable", "latest", "master", "worker", "server", "client", "proxy", "cache", "store",
            "admin", "config", "service",
        ];
        if common_words.contains(&suffix) {
            return false;
        }

        // A Kubernetes generated name: a 5-char rand.String chunk right after
        // another variable segment — `<HASH>`, `<NUMBER>` (a CronJob's minute
        // number) or a pod-template hash that was not hex. Two variable
        // segments in a row cannot be a word, so this holds for `hcwqj` as
        // much as for `7j5z7`. A lone all-letter chunk is not enough:
        // `https`, `pgsql`, `smtps`, `nfsv4` all fit the alphabet.
        if suffix.len() == 5
            && Self::is_k8s_rand(suffix)
            && (prev.starts_with('<')
                || ((8..=10).contains(&prev.len()) && Self::is_k8s_rand(prev)))
        {
            return true;
        }

        // Letters then digits and nothing else — `ed25519`, `sha256`,
        // `ipv6` — is a designator, a word with a number in it, not a
        // generated suffix (the hash detector draws the same line). A
        // designator has a vowel in it; a generated chunk (`tsd92`,
        // `mrgp8`) is drawn from an alphabet without one.
        let letters = suffix.bytes().take_while(u8::is_ascii_alphabetic).count();
        if letters >= 2
            && suffix.bytes().skip(letters).all(|b| b.is_ascii_digit())
            && !Self::is_k8s_rand(suffix)
        {
            return false;
        }

        let has_letters = suffix.chars().any(char::is_alphabetic);
        let has_numbers = suffix.chars().any(char::is_numeric);
        let all_lowercase = suffix.chars().all(|c| c.is_lowercase() || c.is_numeric());

        // Only accept if it has both letters and numbers (hash-like)
        has_letters && has_numbers && all_lowercase
    }

    fn is_k8s_rand(s: &str) -> bool {
        s.bytes().all(|b| K8S_RAND_ALPHABET.contains(&b))
    }

    /// `prefix` is `family` or ends with `-family`.
    fn ends_with_segment(prefix: &str, family: &str) -> bool {
        prefix
            .strip_suffix(family)
            .is_some_and(|head| head.is_empty() || head.ends_with('-'))
    }

    fn is_common_prefix(prefix: &str) -> bool {
        COMMON_PREFIXES.contains(&prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hyphenated_name_detection() {
        let test_cases = vec![
            (
                "pod pushprox-kube-proxy-client-9djm4",
                "pod <COMPONENT>-<SUFFIX>",
            ),
            (
                "volume kube-api-access-52r58",
                "volume kube-api-access-<SUFFIX>",
            ),
            ("container cilium-kh8lj", "container <COMPONENT>-<SUFFIX>"),
            ("service nginx-stable", "service nginx-stable"), // Short suffix, unchanged
            ("app my-service", "app my-service"),             // Too short, unchanged
        ];

        for (input, expected) in test_cases {
            let (result, _tokens) = NameDetector::detect_and_replace(input);
            assert_eq!(result, expected, "Failed for input: {input}");
        }
    }

    /// A generated Kubernetes name is one name even when an earlier detector
    /// already replaced its template hash or job number, and even when the
    /// 5-char suffix happens to contain no digit.
    #[test]
    fn generated_pod_name_after_placeholder_is_one_name() {
        let cases = [
            // Deployment pod, hex template hash already <HASH>, suffix has no digit
            (
                "pod web-v2-<HASH>-hcwqj ready",
                "pod <COMPONENT>-<SUFFIX> ready",
            ),
            // digit-led segment inside the base name (`all-in-1-v2`)
            (
                "Pod/ledger-all-in-1-v2-<HASH>-x4q7c",
                "Pod/<COMPONENT>-<SUFFIX>",
            ),
            // CronJob pod: minute number already <NUMBER>
            ("pod backup-db-<NUMBER>-tvszq", "pod <COMPONENT>-<SUFFIX>"),
            // non-hex template hash survived the hash detector
            ("pod portal-5b8dfd9ck-bdwdp", "pod <COMPONENT>-<SUFFIX>"),
            // the whole name is tokenised, not just its tail
            (
                "Pulled Pod/web-<HASH>-hcwqj image",
                "Pulled Pod/<COMPONENT>-<SUFFIX> image",
            ),
        ];
        for (input, expected) in cases {
            let (result, tokens) = NameDetector::detect_and_replace(input);
            assert_eq!(result, expected, "input: {input}");
            assert!(
                tokens.iter().any(|t| matches!(t, Token::Name(_))),
                "no Name token for {input}"
            );
        }
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

    /// A family whose names are always generated takes an all-letter rand
    /// suffix; a family that is not stays literal.
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

    /// An all-letter 5-char chunk with nothing variable before it is a word
    /// until proven otherwise: `https` and `pgsql` fit the alphabet too.
    #[test]
    fn lone_all_letter_suffix_stays_literal() {
        for input in [
            "port proxy-https open",
            "db main-pgsql up",
            "pod osd-prepare-g8-nztxp done",
        ] {
            let (result, tokens) = NameDetector::detect_and_replace(input);
            assert_eq!(result, input);
            assert!(tokens.is_empty(), "{input}");
        }
    }

    #[test]
    fn test_variable_suffix_detection() {
        assert!(NameDetector::is_variable_suffix("", "9djm4")); // mixed alphanumeric
        assert!(NameDetector::is_variable_suffix("", "52r58")); // mixed alphanumeric
        assert!(NameDetector::is_variable_suffix("", "kh8lj")); // mixed alphanumeric
        // "abcde" is all letters with no numbers — the code requires both letters AND numbers
        assert!(!NameDetector::is_variable_suffix("", "abcde"));

        assert!(!NameDetector::is_variable_suffix("", "abc")); // too short
        assert!(!NameDetector::is_variable_suffix("", "stable")); // common word
        assert!(!NameDetector::is_variable_suffix("", "123")); // too short
    }

    #[test]
    fn k8s_rand_suffix_needs_a_variable_segment_before_it() {
        assert!(NameDetector::is_variable_suffix("<HASH>", "hcwqj"));
        assert!(NameDetector::is_variable_suffix("<NUMBER>", "tvszq"));
        assert!(NameDetector::is_variable_suffix("5b8dfd9ck", "bdwdp")); // 9-char template hash
        assert!(!NameDetector::is_variable_suffix("proxy", "https")); // a word before it
        assert!(!NameDetector::is_variable_suffix("<HASH>", "hcwqa")); // `a` is not in the alphabet
        assert!(!NameDetector::is_variable_suffix("<HASH>", "hcwqjx")); // 6 chars is not a suffix
        assert!(!NameDetector::is_variable_suffix("abcdefgh", "hcwqj")); // vowels: not a template hash
        assert!(!NameDetector::is_variable_suffix("bcdfghj", "hcwqj")); // 7 chars: too short for one
        assert!(!NameDetector::is_variable_suffix("bcdfghjklmn", "hcwqj")); // 11: too long
    }

    #[test]
    fn variable_suffix_boundary_4_chars() {
        assert!(!NameDetector::is_variable_suffix("", "ab1c")); // exactly 4 — too short
    }

    #[test]
    fn variable_suffix_boundary_5_chars() {
        assert!(NameDetector::is_variable_suffix("", "ab1c2")); // exactly 5 — accepted
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
