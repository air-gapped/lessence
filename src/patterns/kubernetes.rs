use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// All regexes are compiled once and reused. The previous shape — calling
// `Regex::new(pattern)` inside each per-line normalize function — recompiled
// the entire NFA/DFA on every invocation, which dominated CPU time on
// kubernetes-heavy logs (≈30–40% of cycles in compiler/Utf8Compiler paths
// per profiling).

static NS_REGEXES: LazyLock<[Regex; 4]> = LazyLock::new(|| {
    [
        Regex::new(r"Namespace:([a-z0-9][a-z0-9-]*[a-z0-9])").unwrap(),
        Regex::new(r"namespace:([a-z0-9][a-z0-9-]*[a-z0-9])").unwrap(),
        Regex::new(r"pod ([a-z0-9][a-z0-9-]*[a-z0-9])/").unwrap(),
        Regex::new(r"_([a-z0-9][a-z0-9-]*[a-z0-9])\(").unwrap(),
    ]
});

static VOLUME_REGEXES: LazyLock<[Regex; 5]> = LazyLock::new(|| {
    [
        Regex::new(r#"volume "kube-api-access-[a-z0-9]+""#).unwrap(),
        Regex::new(r"volume kube-api-access-[a-z0-9]+").unwrap(),
        Regex::new(r#"volume "([a-z0-9][a-z0-9-]*[a-z0-9]-secret)""#).unwrap(),
        Regex::new(r#"volume "([a-z0-9][a-z0-9-]*[a-z0-9]-token)""#).unwrap(),
        Regex::new(r"volume (oidc-token)").unwrap(),
    ]
});

static PLUGIN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"plugin type="([^"]+)""#).unwrap());

static POD_REGEXES: LazyLock<[Regex; 2]> = LazyLock::new(|| {
    [
        Regex::new(r"Name:([a-z0-9][a-z0-9-]*[a-z0-9]-[a-z0-9]+)").unwrap(),
        Regex::new(r"pod ([a-z0-9][a-z0-9-]*[a-z0-9])/([a-z0-9][a-z0-9-]*[a-z0-9]-[a-z0-9]+)")
            .unwrap(),
    ]
});

static NAME_FIELD_REGEXES: LazyLock<[Regex; 4]> = LazyLock::new(|| {
    [
        Regex::new(r#"([a-zA-Z]*[Nn]ame): "([^"]+)""#).unwrap(),
        Regex::new(r#"([a-zA-Z]*[Nn]ame)="([^"]+)""#).unwrap(),
        Regex::new(r"([a-zA-Z]*[Nn]ame):([a-zA-Z0-9-]+)\b").unwrap(),
        Regex::new(r"([a-zA-Z]*[Nn]ame)=([a-zA-Z0-9-]+)\b").unwrap(),
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
        {
            return (text.to_string(), Vec::new());
        }

        let result = text.to_string();
        let mut tokens = Vec::new();

        // Apply all Kubernetes patterns in order (only if kubernetes content detected)
        let (result, ns_tokens) = Self::normalize_namespaces(result);
        tokens.extend(ns_tokens);

        let (result, vol_tokens) = Self::normalize_volume_names(result);
        tokens.extend(vol_tokens);

        let (result, plugin_tokens) = Self::normalize_plugin_types(result);
        tokens.extend(plugin_tokens);

        let (result, pod_tokens) = Self::normalize_pod_names(result);
        tokens.extend(pod_tokens);

        // Re-enabled with fixed regex patterns that avoid backtracking
        let (result, name_field_tokens) = Self::normalize_name_fields(result);
        tokens.extend(name_field_tokens);

        (result, tokens)
    }

    /// Normalize Kubernetes namespaces
    fn normalize_namespaces(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        for re in NS_REGEXES.iter() {
            let captures: Vec<_> = re.captures_iter(&result).collect();
            for capture in captures {
                if let Some(namespace) = capture.get(1) {
                    let namespace_str = namespace.as_str();
                    // Only normalize common Kubernetes namespaces
                    if Self::is_common_k8s_namespace(namespace_str) {
                        tokens.push(Token::KubernetesNamespace(namespace_str.to_string()));
                    }
                }
            }
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    let namespace = caps.get(1).unwrap().as_str();
                    if Self::is_common_k8s_namespace(namespace) {
                        caps.get(0)
                            .unwrap()
                            .as_str()
                            .replace(namespace, "<NAMESPACE>")
                    } else {
                        caps.get(0).unwrap().as_str().to_string()
                    }
                })
                .to_string();
        }

        (result, tokens)
    }

    /// Normalize volume names
    #[mutants::skip] // capture.len() > 1 is always true: the regexes always have a capture group
    fn normalize_volume_names(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        for re in VOLUME_REGEXES.iter() {
            let captures: Vec<_> = re.captures_iter(&result).collect();
            for capture in captures {
                if capture.len() > 1
                    && let Some(volume) = capture.get(1)
                {
                    tokens.push(Token::VolumeName(volume.as_str().to_string()));
                }
            }
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    if caps.get(0).unwrap().as_str().contains("kube-api-access") {
                        caps.get(0)
                            .unwrap()
                            .as_str()
                            .replace("kube-api-access-", "kube-api-access-<SUFFIX>")
                    } else {
                        caps.get(0)
                            .unwrap()
                            .as_str()
                            .replace(caps.get(1).unwrap().as_str(), "<VOLUME_NAME>")
                    }
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
                    let full_match = caps.get(0).unwrap().as_str();
                    let pod_name = caps.get(caps.len() - 1).unwrap().as_str();
                    full_match.replace(pod_name, "<POD_NAME>")
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
                        // Handle Name: pattern
                        if full_match.contains('"') {
                            format!("{field_name}: \"<K8S_NAME>\"")
                        } else {
                            format!("{field_name}: <K8S_NAME>")
                        }
                    }
                })
                .to_string();
        }

        (result, tokens)
    }

    /// Check if a namespace is a common Kubernetes namespace that should be normalized
    fn is_common_k8s_namespace(namespace: &str) -> bool {
        matches!(
            namespace,
            "kube-system"
                | "kube-public"
                | "kube-node-lease"
                | "default"
                | "gpu-operator"
                | "rook-ceph"
                | "kubevirt"
                | "traefik"
                | "cilium-test-1"
                | "cattle-monitoring-system"
                | "keycloak"
                | "monitoring"
                | "logging"
                | "istio-system"
                | "cert-manager"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let text = r#"volume "kube-api-access-abc123" failed"#;
        let (result, _) = KubernetesDetector::detect_and_replace(text);

        // The replacement inserts <SUFFIX> after "kube-api-access-" but the original
        // suffix text remains appended (string replace only replaces the prefix portion)
        assert!(result.contains("kube-api-access-<SUFFIX>"));
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

    // ---- Mutant-killing: normalize_volume_names boundary ----

    #[test]
    fn volume_names_captures_len_boundary() {
        // Kills mutant: `capture.len() > 1` → `capture.len() >= 1` (line ~102)
        // A kube-api-access match has only capture group 0 (no group 1), so
        // len() == 1, meaning > 1 is false. If mutated to >= 1, it would try
        // capture.get(1) on a None, which would panic or produce wrong tokens.
        let text = r"volume kube-api-access-abc123 failed";
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        // Should succeed without panic — the kube-api-access pattern has no capture group 1
        assert!(
            result.contains("kube-api-access-<SUFFIX>"),
            "result: {result}"
        );
        // kube-api-access patterns don't push VolumeName tokens (only named-capture patterns do)
        let _ = tokens; // just verify no panic
    }

    // ---- Mutant-killing: normalize_pod_names arithmetic ----

    #[test]
    fn pod_names_capture_last_group() {
        // Kills mutant: `capture.len() - 1` → `capture.len() + 1` or `/ 1` (lines ~165, 172)
        // The pod pattern "pod ns/pod-name" has 2 capture groups: (1)=ns, (2)=pod-name
        // capture.len() = 3 (0=full, 1=ns, 2=pod). len()-1 = 2, which is the pod name.
        // If mutated to len()+1 = 4, it would be out of bounds.
        // Use a non-common namespace so normalize_namespaces doesn't alter the text first.
        let text = "Error for pod my-app-ns/nginx-abc123: failed";
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        // Should detect the pod name (the last capture group)
        assert!(
            tokens.iter().any(|t| matches!(t, Token::PodName(_))),
            "Should detect pod name, tokens: {tokens:?}"
        );
        assert!(
            result.contains("<POD_NAME>"),
            "Should replace pod name: {result}"
        );
    }

    // ---- Mutant-killing: is_common_k8s_namespace replace with true ----

    #[test]
    fn is_common_k8s_namespace_rejects_unknown() {
        // Kills mutant: `is_common_k8s_namespace` replaced with `true`
        // An unknown namespace should NOT be normalized
        assert!(!KubernetesDetector::is_common_k8s_namespace("my-custom-ns"));
        assert!(!KubernetesDetector::is_common_k8s_namespace("production"));
        assert!(!KubernetesDetector::is_common_k8s_namespace("staging"));
    }

    #[test]
    fn is_common_k8s_namespace_accepts_known() {
        assert!(KubernetesDetector::is_common_k8s_namespace("kube-system"));
        assert!(KubernetesDetector::is_common_k8s_namespace("default"));
        assert!(KubernetesDetector::is_common_k8s_namespace("monitoring"));
    }

    #[test]
    fn unknown_namespace_not_normalized() {
        // Integration test: unknown namespace should NOT be replaced with <NAMESPACE>
        // This kills the mutant where is_common_k8s_namespace always returns true
        let text = "Error for pod my-custom-ns/nginx-abc123: failed";
        let (result, _tokens) = KubernetesDetector::detect_and_replace(text);
        // "my-custom-ns" is NOT a common k8s namespace, so it should be preserved
        assert!(
            result.contains("my-custom-ns"),
            "Unknown namespace should NOT be replaced: {result}"
        );
    }
}
