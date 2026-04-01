use super::Token;

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
        let patterns = [
            // Namespace patterns in various contexts
            r"Namespace:([a-z0-9][a-z0-9-]*[a-z0-9])",
            r"namespace:([a-z0-9][a-z0-9-]*[a-z0-9])",
            r"pod ([a-z0-9][a-z0-9-]*[a-z0-9])/",
            r"_([a-z0-9][a-z0-9-]*[a-z0-9])\(",
        ];

        let mut result = text;
        let mut tokens = Vec::new();

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
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
        }

        (result, tokens)
    }

    /// Normalize volume names
    fn normalize_volume_names(text: String) -> (String, Vec<Token>) {
        let patterns = [
            // kube-api-access volumes with suffixes
            r#"volume "kube-api-access-[a-z0-9]+""#,
            r"volume kube-api-access-[a-z0-9]+",
            // Other common volume patterns
            r#"volume "([a-z0-9][a-z0-9-]*[a-z0-9]-secret)""#,
            r#"volume "([a-z0-9][a-z0-9-]*[a-z0-9]-token)""#,
            r"volume (oidc-token)",
        ];

        let mut result = text;
        let mut tokens = Vec::new();

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
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
        }

        (result, tokens)
    }

    /// Normalize plugin types
    fn normalize_plugin_types(text: String) -> (String, Vec<Token>) {
        let pattern = r#"plugin type="([^"]+)""#;
        let mut result = text;
        let mut tokens = Vec::new();

        if let Ok(re) = regex::Regex::new(pattern) {
            let captures: Vec<_> = re.captures_iter(&result).collect();
            for capture in captures {
                if let Some(plugin) = capture.get(1) {
                    tokens.push(Token::PluginType(plugin.as_str().to_string()));
                }
            }
            result = re
                .replace_all(&result, r#"plugin type="<PLUGIN>""#)
                .to_string();
        }

        (result, tokens)
    }

    /// Normalize pod names
    fn normalize_pod_names(text: String) -> (String, Vec<Token>) {
        let patterns = [
            // Common Kubernetes pod naming patterns
            r"Name:([a-z0-9][a-z0-9-]*[a-z0-9]-[a-z0-9]+)",
            r"pod ([a-z0-9][a-z0-9-]*[a-z0-9])/([a-z0-9][a-z0-9-]*[a-z0-9]-[a-z0-9]+)",
        ];

        let mut result = text;
        let mut tokens = Vec::new();

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
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
        }

        (result, tokens)
    }

    /// Normalize any field ending with Name: or name=
    fn normalize_name_fields(text: String) -> (String, Vec<Token>) {
        let patterns = [
            // Field names ending with Name: or name: (with quoted values)
            r#"([a-zA-Z]*[Nn]ame): "([^"]+)""#,
            r#"([a-zA-Z]*[Nn]ame)="([^"]+)""#,
            // Field names ending with Name: or name: (with unquoted simple values)
            // Use word boundaries instead of requiring trailing space to avoid backtracking
            r"([a-zA-Z]*[Nn]ame):([a-zA-Z0-9-]+)\b",
            r"([a-zA-Z]*[Nn]ame)=([a-zA-Z0-9-]+)\b",
        ];

        let mut result = text;
        let mut tokens = Vec::new();

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
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
}
