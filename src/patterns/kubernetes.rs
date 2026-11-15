use super::Token;
use regex::Regex;
use std::sync::LazyLock;

const DNS_LABEL: &str = "[a-z0-9][a-z0-9-]*[a-z0-9]";

static NS_REGEXES: LazyLock<[Regex; 5]> = LazyLock::new(|| {
    let namespace_field_upper = format!("Namespace:({DNS_LABEL})");
    let namespace_field = format!("namespace:({DNS_LABEL})");
    let pod_slash_ref = format!("pod ({DNS_LABEL})/");
    let klog_pod_ref = format!(r#"pod="({DNS_LABEL})/"#);
    let kubelet_container_ref = format!(r"pod=[^\s_]+_({DNS_LABEL})\(");
    [
        namespace_field_upper,
        namespace_field,
        pod_slash_ref,
        klog_pod_ref,
        kubelet_container_ref,
    ]
    .map(|pattern| Regex::new(&pattern).unwrap())
});

static VOLUME_REGEXES: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    [
        Regex::new(&format!(r#"volume "({DNS_LABEL}-secret)""#)).unwrap(),
        Regex::new(&format!(r#"volume "({DNS_LABEL}-token)""#)).unwrap(),
        Regex::new(r"volume (oidc-token)").unwrap(),
    ]
});

static PLUGIN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"plugin type="([^"]+)""#).unwrap());

static POD_REGEXES: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    let name_field = format!("Name:(?P<pod>{DNS_LABEL}-[a-z0-9]+)");
    let pod_slash_ref = format!("pod ({DNS_LABEL})/(?P<pod>(?:[a-z0-9-]|<[A-Z_]+>)+)");
    let klog_pod_ref = format!(r#"pod="({DNS_LABEL})/(?P<pod>[^"]+)""#);
    [name_field, pod_slash_ref, klog_pod_ref].map(|pattern| Regex::new(&pattern).unwrap())
});

static GROUP_VERSION_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\b[a-z0-9]+(?:[.-][a-z0-9]+)*)?/v\d+(?:(?:alpha|beta)\d+)?\b").unwrap()
});

const NOT_A_PLACEHOLDER_START: &str = "[A-Za-z0-9]";
const UNQUOTED_VALUE_BODY: &str = r#"(?:[^\s,"'()\[\]{};:=]*[^\s,"'()\[\]{};:=.])?"#;

static NAME_FIELD_REGEXES: LazyLock<[Regex; 4]> = LazyLock::new(|| {
    let unquoted_value = format!("{NOT_A_PLACEHOLDER_START}{UNQUOTED_VALUE_BODY}");
    [
        r#"([a-zA-Z]*[Nn]ame): "([^"]+)""#.to_string(),
        r#"([a-zA-Z]*[Nn]ame)="([^"]+)""#.to_string(),
        format!("([a-zA-Z]*[Nn]ame):({unquoted_value})"),
        format!("([a-zA-Z]*[Nn]ame)=({unquoted_value})"),
    ]
    .map(|pattern| Regex::new(&pattern).unwrap())
});

pub struct KubernetesDetector;

impl KubernetesDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        if !Self::has_kubernetes_indicators(text) {
            return (text.to_string(), Vec::new());
        }

        let mut tokens = Vec::new();
        let result = Self::normalize_group_versions(text, &mut tokens);

        let (result, pod_tokens) = Self::normalize_pod_names(result);
        tokens.extend(pod_tokens);

        let (result, ns_tokens) = Self::normalize_namespaces(result);
        tokens.extend(ns_tokens);

        let (result, vol_tokens) = Self::normalize_volume_names(result);
        tokens.extend(vol_tokens);

        let (result, plugin_tokens) = Self::normalize_plugin_types(result);
        tokens.extend(plugin_tokens);

        let (result, name_field_tokens) = Self::normalize_name_fields(result);
        tokens.extend(name_field_tokens);

        (result, tokens)
    }

    fn has_kubernetes_indicators(text: &str) -> bool {
        ["kube", "namespace", "pod", "volume", "/v"]
            .iter()
            .any(|indicator| text.contains(indicator))
    }

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

    fn normalize_namespaces(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        for re in NS_REGEXES.iter() {
            for capture in re.captures_iter(&result) {
                tokens.push(Token::KubernetesNamespace(capture[1].to_string()));
            }
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    Self::replace_capture_by_position(caps, caps.get(1), "<NAMESPACE>")
                })
                .to_string();
        }

        (result, tokens)
    }

    fn replace_capture_by_position(
        caps: &regex::Captures,
        group: Option<regex::Match>,
        placeholder: &str,
    ) -> String {
        let whole = caps.get(0).unwrap();
        let group = group.unwrap();
        let text = whole.as_str();
        let (start, end) = (group.start() - whole.start(), group.end() - whole.start());
        format!("{}{placeholder}{}", &text[..start], &text[end..])
    }

    fn normalize_volume_names(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        for re in VOLUME_REGEXES.iter() {
            for capture in re.captures_iter(&result) {
                tokens.push(Token::VolumeName(capture[1].to_string()));
            }
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    Self::replace_capture_by_position(caps, caps.get(1), "<VOLUME_NAME>")
                })
                .to_string();
        }

        (result, tokens)
    }

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

    fn normalize_pod_names(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        for re in POD_REGEXES.iter() {
            for capture in re.captures_iter(&result) {
                tokens.push(Token::PodName(capture["pod"].to_string()));
            }
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    Self::replace_capture_by_position(caps, caps.name("pod"), "<POD_NAME>")
                })
                .to_string();
        }

        (result, tokens)
    }

    fn normalize_name_fields(text: String) -> (String, Vec<Token>) {
        let mut result = text;
        let mut tokens = Vec::new();

        for re in NAME_FIELD_REGEXES.iter() {
            let captures: Vec<_> = re.captures_iter(&result).collect();
            for capture in captures {
                if let Some(value) = capture.get(2) {
                    tokens.push(Token::KubernetesName(value.as_str().to_string()));
                }
            }
            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    let field_name = caps.get(1).unwrap().as_str();
                    let full_match = caps.get(0).unwrap().as_str();
                    if full_match.contains('=') {
                        if full_match.contains('"') {
                            format!("{field_name}=\"<K8S_NAME>\"")
                        } else {
                            format!("{field_name}=<K8S_NAME>")
                        }
                    } else {
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
            assert_eq!(
                r, line,
                "a /vN inside a longer path is a Go import path, not a group/version"
            );
        }
    }

    #[test]
    fn name_field_value_is_the_whole_token() {
        let (r, tokens) = KubernetesDetector::detect_and_replace(
            "volumeName:kubernetes.io/projected/<UUID>-kube-api-access-<SUFFIX> podName:<UUID> nodeName:} filename=app.log. hostname=? hostname=<FQDN> port=x:80",
        );
        assert_eq!(
            r,
            "volumeName:<K8S_NAME> podName:<UUID> nodeName:} filename=<K8S_NAME>. hostname=? hostname=<FQDN> port=x:80",
            "the value is the whole token and the placeholder adds nothing the input did not have"
        );
        assert_eq!(
            tokens,
            vec![
                Token::KubernetesName(
                    "kubernetes.io/projected/<UUID>-kube-api-access-<SUFFIX>".into()
                ),
                Token::KubernetesName("app.log".into()),
            ],
            "a name field is recorded as a name, never as a namespace"
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

    #[test]
    fn kube_api_access_is_left_to_the_name_detector() {
        let text = r#"volume "kube-api-access-abc12" and volume kube-api-access-def34 failed"#;
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        assert_eq!(
            result, text,
            "a placeholder here would leave kube-api-access-<SUFFIX>abc12, a template of nothing"
        );
        assert!(tokens.is_empty(), "{tokens:?}");
    }

    #[test]
    fn plugin_type_folds_only_behind_a_kubernetes_indicator() {
        let text = r#"plugin type="cilium-cni" failed"#;
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);

        assert_eq!(
            result, text,
            "no kube/namespace/pod/volume//v indicator: the line is returned unchanged"
        );
        assert!(tokens.is_empty());

        let text_with_kube = r#"kube plugin type="cilium-cni" failed"#;
        let (result2, tokens2) = KubernetesDetector::detect_and_replace(text_with_kube);
        assert!(result2.contains(r#"plugin type="<PLUGIN>""#));
        assert!(tokens2.iter().any(|t| matches!(t, Token::PluginType(_))));
    }

    #[test]
    fn namespace_slash_pod_folds_both_slots() {
        let text = "Error preparing data for pod kube-system/nginx-abc123: failed";
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        assert_eq!(
            result,
            "Error preparing data for pod <NAMESPACE>/<POD_NAME>: failed"
        );
        assert_eq!(
            tokens,
            vec![
                Token::PodName("nginx-abc123".into()),
                Token::KubernetesNamespace("kube-system".into()),
            ]
        );
    }

    #[test]
    fn pods_fold_before_namespaces() {
        let text = "for pod shop/web-x4q7c: failed".to_string();
        let (pods_first, _) = KubernetesDetector::normalize_namespaces(
            KubernetesDetector::normalize_pod_names(text.clone()).0,
        );
        assert_eq!(pods_first, "for pod <NAMESPACE>/<POD_NAME>: failed");
        let (namespaces_first, _) = KubernetesDetector::normalize_pod_names(
            KubernetesDetector::normalize_namespaces(text.clone()).0,
        );
        assert_eq!(
            namespaces_first, "for pod <NAMESPACE>/web-x4q7c: failed",
            "the pod regex cannot see its slot once the namespace is a placeholder"
        );
        assert_eq!(KubernetesDetector::detect_and_replace(&text).0, pods_first);
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

    #[test]
    fn a_name_field_folds_its_pod_group() {
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
            (
                "Error for pod shop/shop: failed",
                "Error for pod <NAMESPACE>/<POD_NAME>: failed",
            ),
        ];
        for (input, expected) in cases {
            let (result, tokens) = KubernetesDetector::detect_and_replace(input);
            assert_eq!(
                result, expected,
                "each slot is replaced once, by position, even when the namespace is the pod name: {input}"
            );
            assert!(
                tokens
                    .iter()
                    .any(|t| matches!(t, Token::KubernetesNamespace(_))),
                "no namespace token for {input}"
            );
        }
    }

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

    #[test]
    fn underscore_call_is_not_a_namespace() {
        let text = "kubelet jk2_init() Found child; pam_unix(cron:session): opened";
        let (result, tokens) = KubernetesDetector::detect_and_replace(text);
        assert_eq!(
            result, text,
            "jk2_init() and pam_unix( are function names, not a kubelet pod=name_ns( reference"
        );
        assert!(tokens.is_empty(), "{tokens:?}");
    }
}
