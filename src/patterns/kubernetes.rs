use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// All regexes are compiled once and reused. The previous shape — calling
// `Regex::new(pattern)` inside each per-line normalize function — recompiled
// the entire NFA/DFA on every invocation, which dominated CPU time on
// kubernetes-heavy logs (≈30–40% of cycles in compiler/Utf8Compiler paths
// per profiling).

// A namespace slot is a shape: whatever sits in it is a namespace. No
// vocabulary of "known" namespaces decides — the position does.
static NS_REGEXES: LazyLock<[Regex; 5]> = LazyLock::new(|| {
    [
        Regex::new(r"Namespace:([a-z0-9][a-z0-9-]*[a-z0-9])").unwrap(),
        Regex::new(r"namespace:([a-z0-9][a-z0-9-]*[a-z0-9])").unwrap(),
        Regex::new(r"pod ([a-z0-9][a-z0-9-]*[a-z0-9])/").unwrap(),
        // klog's structured pod reference: pod="namespace/name"
        Regex::new(r#"pod="([a-z0-9][a-z0-9-]*[a-z0-9])/"#).unwrap(),
        // kubelet's container reference: pod=<name>_<namespace>(<uid>)
        Regex::new(r"pod=[^\s_]+_([a-z0-9][a-z0-9-]*[a-z0-9])\(").unwrap(),
    ]
});

// `kube-api-access-<suffix>` is not here: the name detector folds it, with
// its token, like every other hyphenated name with a generated suffix.
static VOLUME_REGEXES: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    [
        Regex::new(r#"volume "([a-z0-9][a-z0-9-]*[a-z0-9]-secret)""#).unwrap(),
        Regex::new(r#"volume "([a-z0-9][a-z0-9-]*[a-z0-9]-token)""#).unwrap(),
        Regex::new(r"volume (oidc-token)").unwrap(),
    ]
});

static PLUGIN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"plugin type="([^"]+)""#).unwrap());

// A pod slot holds a pod name whatever its kind — Deployment
// (`web-<HASH>-x4q7c`), StatefulSet (`db-0`), static (`etcd-node3`) — so
// the whole name folds. Earlier detectors may already have left placeholders
// in it. The last capture group is the name.
static POD_REGEXES: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    [
        Regex::new(r"Name:([a-z0-9][a-z0-9-]*[a-z0-9]-[a-z0-9]+)").unwrap(),
        Regex::new(r"pod ([a-z0-9][a-z0-9-]*[a-z0-9])/((?:[a-z0-9-]|<[A-Z_]+>)+)").unwrap(),
        Regex::new(r#"pod="([a-z0-9][a-z0-9-]*[a-z0-9])/([^"]+)""#).unwrap(),
    ]
});

// A Kubernetes group/version: `apps/v1`, `management.cattle.io/v3`,
// `cdi.kubevirt.io/v1beta1`, the core group's `/v1`. The version suffix is
// the shape. A `/v1` inside a longer path (`k8s.io/api/apps/v1`) is not one.
static GROUP_VERSION_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\b[a-z0-9]+(?:[.-][a-z0-9]+)*)?/v\d+(?:(?:alpha|beta)\d+)?\b").unwrap()
});

static NAME_FIELD_REGEXES: LazyLock<[Regex; 4]> = LazyLock::new(|| {
    [
        Regex::new(r#"([a-zA-Z]*[Nn]ame): "([^"]+)""#).unwrap(),
        Regex::new(r#"([a-zA-Z]*[Nn]ame)="([^"]+)""#).unwrap(),
        // An unquoted value runs to the next separator, so
        // `volumeName:kubernetes.io/projected/<UUID>-kube-api-access-<SUFFIX>`
        // is one value. A value that is already a placeholder is left alone.
        Regex::new(
            r#"([a-zA-Z]*[Nn]ame):([A-Za-z0-9](?:[^\s,"'()\[\]{};:=]*[^\s,"'()\[\]{};:=.])?)"#,
        )
        .unwrap(),
        Regex::new(
            r#"([a-zA-Z]*[Nn]ame)=([A-Za-z0-9](?:[^\s,"'()\[\]{};:=]*[^\s,"'()\[\]{};:=.])?)"#,
        )
        .unwrap(),
    ]
});

pub struct KubernetesDetector;

impl KubernetesDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        // FAST PATH: Skip if no kubernetes indicators
        if !text.contains("kube")
            && !text.contains("namespace")
            && !text.contains("pod")
            && !text.contains("volume")
            && !text.contains("/v")
        {
            return (text.to_string(), Vec::new());
        }

        let mut tokens = Vec::new();
        let result = Self::normalize_group_versions(text, &mut tokens);

        // Apply all Kubernetes patterns in order (only if kubernetes content detected).
        // Pods first: the namespace regexes then see `pod ns/<POD_NAME>`.
        let (result, pod_tokens) = Self::normalize_pod_names(result);
        tokens.extend(pod_tokens);

        let (result, ns_tokens) = Self::normalize_namespaces(result);
        tokens.extend(ns_tokens);

        let (result, vol_tokens) = Self::normalize_volume_names(result);
        tokens.extend(vol_tokens);

        let (result, plugin_tokens) = Self::normalize_plugin_types(result);
        tokens.extend(plugin_tokens);

        // Re-enabled with fixed regex patterns that avoid backtracking
        let (result, name_field_tokens) = Self::normalize_name_fields(result);
        tokens.extend(name_field_tokens);

        (result, tokens)
    }

    /// `group/version` is one name. Not preceded by a path or name
    /// character: `k8s.io/api/apps/v1` is a Go import path.
    fn normalize_group_versions(text: &str, tokens: &mut Vec<Token>) -> String {
        let mut result = text.to_string();
        if text.contains("/v") {
            super::fold_matches(&mut result, tokens, &GROUP_VERSION_REGEX, |caps| {
                let m = caps.get(0).unwrap();
                let prev = m.start().checked_sub(1).map(|i| text.as_bytes()[i]);
                let continues = prev.is_some_and(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_')
                });
                (!continues).then(|| {
                    (
                        Token::Name(m.as_str().to_string()),
                        "<GROUP_VERSION>".to_string(),
                    )
                })
            });
        }
        result
    }

    /// Normalize Kubernetes namespaces
    fn normalize_namespaces(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        for re in NS_REGEXES.iter() {
            for capture in re.captures_iter(&result) {
                tokens.push(Token::KubernetesNamespace(capture[1].to_string()));
            }
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    Self::replace_group(caps, 1, "<NAMESPACE>")
                })
                .to_string();
        }

        (result, tokens)
    }

    /// Replace one capture group inside the whole match by position, so a
    /// namespace that also appears in the pod name is replaced once.
    fn replace_group(caps: &regex::Captures, idx: usize, placeholder: &str) -> String {
        let whole = caps.get(0).unwrap();
        let group = caps.get(idx).unwrap();
        let text = whole.as_str();
        let (start, end) = (group.start() - whole.start(), group.end() - whole.start());
        format!("{}{placeholder}{}", &text[..start], &text[end..])
    }

    /// Normalize volume names
    fn normalize_volume_names(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        for re in VOLUME_REGEXES.iter() {
            for capture in re.captures_iter(&result) {
                tokens.push(Token::VolumeName(capture[1].to_string()));
            }
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    Self::replace_group(caps, 1, "<VOLUME_NAME>")
                })
                .to_string();
        }

        (result, tokens)
    }

    /// Normalize plugin types
    fn normalize_plugin_types(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        let captures: Vec<_> = PLUGIN_REGEX.captures_iter(&result).collect();
        for capture in captures {
            if let Some(plugin) = capture.get(1) {
                tokens.push(Token::PluginType(plugin.as_str().to_string()));
            }
        }
        result = PLUGIN_REGEX
            .replace_all(&result, r#"plugin type="<PLUGIN>""#)
            .to_string();

        (result, tokens)
    }

    /// Normalize pod names
    fn normalize_pod_names(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        for re in POD_REGEXES.iter() {
            let captures: Vec<_> = re.captures_iter(&result).collect();
            for capture in captures {
                if let Some(pod_name) = capture.get(capture.len() - 1) {
                    tokens.push(Token::PodName(pod_name.as_str().to_string()));
                }
            }
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    Self::replace_group(caps, caps.len() - 1, "<POD_NAME>")
                })
                .to_string();
        }

        (result, tokens)
    }

    /// Normalize any field ending with Name: or name=
    fn normalize_name_fields(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        for re in NAME_FIELD_REGEXES.iter() {
            let captures: Vec<_> = re.captures_iter(&result).collect();
            for capture in captures {
                if let Some(value) = capture.get(2) {
                    tokens.push(Token::KubernetesNamespace(value.as_str().to_string()));
                    // Reuse namespace token for simplicity
                }
            }
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    let field_name = caps.get(1).unwrap().as_str();
                    let full_match = caps.get(0).unwrap().as_str();
                    if full_match.contains('=') {
                        // Handle name= pattern
                        if full_match.contains('"') {
                            format!("{field_name}=\"<K8S_NAME>\"")
                        } else {
                            format!("{field_name}=<K8S_NAME>")
                        }
                    } else {
                        // Handle Name: pattern; the placeholder replaces
                        // the value and nothing else, so no space is added
                        if full_match.contains('"') {
                            format!("{field_name}: \"<K8S_NAME>\"")
                        } else {
                            format!("{field_name}:<K8S_NAME>")
                        }
                    }
                })
                .to_string();
        }

        (result, tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `group/version` folds as one name whichever group it is, including
    /// the core group's bare `/v1`; a version inside a longer path does not.
    #[test]
    fn group_version_is_one_name() {
        let (r, t) = KubernetesDetector::detect_and_replace(
            "Watching management.cattle.io/v3, Kind=Cluster and apps/v1 and cdi.kubevirt.io/v1beta1 and /v1, Kind=Service",
        );
        assert_eq!(
            r,
            "Watching <GROUP_VERSION>, Kind=Cluster and <GROUP_VERSION> and <GROUP_VERSION> and <GROUP_VERSION>, Kind=Service"
        );
        assert_eq!(t.len(), 4);
        for line in [
            "at k8s.io/api/apps/v1 x",
            "in github.com/foo/bar/v2 x",
            "SomeType/v1 x",
            "v1 to ResourceManager",
        ] {
            let (r, _) = KubernetesDetector::detect_and_replace(line);
            assert_eq!(r, line);
        }
    }

    /// A name field's value is the whole token, dots and slashes included,
    /// and the placeholder adds nothing the input did not have.
    #[test]
    fn name_field_value_is_the_whole_token() {
        let (r, _) = KubernetesDetector::detect_and_replace(
            "volumeName:kubernetes.io/projected/<UUID>-kube-api-access-<SUFFIX> podName:<UUID> nodeName:} filename=app.log. hostname=? hostname=<FQDN> port=x:80",
        );
        assert_eq!(
            r,
            "volumeName:<K8S_NAME> podName:<UUID> nodeName:} filename=<K8S_NAME>. hostname=? hostname=<FQDN> port=x:80"
        );
    }

    #[test]
    fn test_namespace_normalization() {
        let text = "Error preparing data for projected volume kube-api-access-abc123 for pod gpu-operator/worker-xyz: failed";
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);

        assert!(result.contains("pod <NAMESPACE>/"));
        assert!(!result.contains("gpu-operator"));
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::KubernetesNamespace(_)))
        );
    }

    #[test]
    fn test_volume_normalization() {
        let text = r#"volume "grafana-token" and volume "db-secret" failed"#;
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        assert_eq!(
            result,
            r#"volume "<VOLUME_NAME>" and volume "<VOLUME_NAME>" failed"#
        );
        assert_eq!(tokens.len(), 2);
    }

    /// `kube-api-access-<suffix>` belongs to the name detector, which folds
    /// the suffix and keeps a token. Inserting a placeholder here used to
    /// leave `kube-api-access-<SUFFIX>abc12` — a template of nothing.
    #[test]
    fn kube_api_access_is_left_to_the_name_detector() {
        let text = r#"volume "kube-api-access-abc12" and volume kube-api-access-def34 failed"#;
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        assert_eq!(result, text);
        assert!(tokens.is_empty(), "{tokens:?}");
    }

    #[test]
    fn test_plugin_normalization() {
        // The fast path requires "kube" || "namespace" || "pod" || "volume" in the text.
        // "cilium-cni" alone doesn't trigger Kubernetes detection.
        let text = r#"plugin type="cilium-cni" failed"#;
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);

        // Fast path returns early — no Kubernetes indicators found
        assert_eq!(result, text);
        assert!(tokens.is_empty());

        // With a kubernetes indicator present, plugin normalization works
        let text_with_kube = r#"kube plugin type="cilium-cni" failed"#;
        let (result2, tokens2) = KubernetesDetector::detect_and_replace(text_with_kube);
        assert!(result2.contains(r#"plugin type="<PLUGIN>""#));
        assert!(tokens2.iter().any(|t| matches!(t, Token::PluginType(_))));
    }

    #[test]
    fn test_pod_name_in_namespace_slash_format() {
        // The existing test uses "pod namespace/name" format which is what the regex matches
        let text = "Error preparing data for pod kube-system/nginx-abc123: failed";
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::KubernetesNamespace(_) | Token::PodName(_))),
            "should detect namespace or pod, got tokens: {tokens:?}"
        );
        assert!(
            result.contains("<NAMESPACE>") || result.contains("<POD>"),
            "should normalize namespace/pod, got: {result}"
        );
    }

    #[test]
    fn test_volume_name_kube_api_access() {
        let text = "volume \"kube-api-access-def456\" (projected) failed to mount for pod kube-system/test-pod";
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        assert!(
            !tokens.is_empty(),
            "should detect k8s patterns, got: {result}"
        );
    }

    #[test]
    fn test_no_detection_without_k8s_indicators() {
        let text = "just a plain log line with nothing kubernetes about it";
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        assert!(tokens.is_empty(), "should detect nothing k8s");
        assert_eq!(result, text);
    }

    // ---- Mutant-killing: normalize_pod_names arithmetic ----

    #[test]
    fn pod_names_capture_last_group() {
        // Kills mutant: `capture.len() - 1` → `capture.len() + 1` or `/ 1`.
        // The `Name:` pattern has one capture group: len() = 2, len()-1 = 1
        // is the pod name; +1 is out of bounds and yields no token.
        let text = "pod Name:nginx-abc123 failed";
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        assert!(
            tokens.iter().any(|t| matches!(t, Token::PodName(_))),
            "Should detect pod name, tokens: {tokens:?}"
        );
        assert!(
            result.contains("<POD_NAME>"),
            "Should replace pod name: {result}"
        );
    }

    /// Whatever sits in a namespace slot is a namespace — there is no list
    /// of "known" namespaces deciding which ones fold.
    #[test]
    fn any_namespace_in_a_namespace_slot_is_normalized() {
        let cases = [
            (
                "Error for pod my-custom-ns/nginx-abc123: failed",
                "Error for pod <NAMESPACE>/<POD_NAME>: failed",
            ),
            (
                r#"volume started" pod="shop/web-7d4b9c2f8e-x4q7c""#,
                r#"volume started" pod="<NAMESPACE>/<POD_NAME>""#,
            ),
            (
                "container=agent pod=web-x4q7c_shop(<UUID>)",
                "container=agent pod=web-x4q7c_<NAMESPACE>(<UUID>)",
            ),
            // the namespace is also the pod name: each replaced once, by position
            (
                "Error for pod shop/shop: failed",
                "Error for pod <NAMESPACE>/<POD_NAME>: failed",
            ),
        ];
        for (input, expected) in cases {
            let (result, tokens) = KubernetesDetector::detect_and_replace(input);
            assert_eq!(result, expected, "input: {input}");
            assert!(
                tokens
                    .iter()
                    .any(|t| matches!(t, Token::KubernetesNamespace(_))),
                "no namespace token for {input}"
            );
        }
    }

    /// A pod slot folds every kind of pod name, including the ones no
    /// suffix rule can see: a StatefulSet ordinal, a static pod, a name that
    /// already carries a placeholder from an earlier detector.
    #[test]
    fn pod_slot_folds_every_pod_kind() {
        let cases = [
            (
                "for pod db/db-0: failed",
                "for pod <NAMESPACE>/<POD_NAME>: failed",
            ),
            (
                "for pod sys/etcd-node3 ok",
                "for pod <NAMESPACE>/<POD_NAME> ok",
            ),
            (
                r#"ok" pod="web/web-<HASH>-hcwqj""#,
                r#"ok" pod="<NAMESPACE>/<POD_NAME>""#,
            ),
            (
                "for pod web/web-<NUMBER>-deploy-<HASH>-x4q7c: failed",
                "for pod <NAMESPACE>/<POD_NAME>: failed",
            ),
        ];
        for (input, expected) in cases {
            let (result, tokens) = KubernetesDetector::detect_and_replace(input);
            assert_eq!(result, expected, "input: {input}");
            assert!(
                tokens.iter().any(|t| matches!(t, Token::PodName(_))),
                "no pod token for {input}"
            );
        }
    }

    /// `_word(` alone is not a namespace slot: `jk2_init()` and `pam_unix(`
    /// are function names.
    #[test]
    fn underscore_call_is_not_a_namespace() {
        let text = "kubelet jk2_init() Found child; pam_unix(cron:session): opened";
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        assert_eq!(result, text);
        assert!(tokens.is_empty(), "{tokens:?}");
    }
}
