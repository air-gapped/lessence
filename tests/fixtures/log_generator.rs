//! Synthetic log generator for integration tests.
//!
//! Generates deterministic, realistic log output exercising all major token
//! types. Used by constitutional compliance tests so they don't depend on
//! gitignored corpus files.
//!
//! The generator produces kubelet-style logs with 5 repeating patterns.
//! Static text within each pattern is identical — only token values (IPs,
//! UUIDs, timestamps, hashes, pod names) vary between lines. This mirrors
//! how real repetitive logs behave and produces high compression ratios.

/// Generate synthetic log lines exercising all major token types.
///
/// Patterns and their token coverage:
/// - Volume errors: Timestamp, UUID, Path, IP, Port, PID, QuotedString
/// - Transport warnings: Timestamp, IP, PID, Path
/// - Lease errors: Timestamp, PID, Duration
/// - Pod reconciliation: Timestamp, PodName, KubernetesNamespace, PID
/// - Configmap syncs: Timestamp, Hash, KubernetesNamespace, PID
///
/// Compression ratios: ~93% at 500 lines, ~96% at 2000 lines.
pub fn generate_log(line_count: usize) -> String {
    let mut lines = Vec::with_capacity(line_count);

    for i in 0..line_count {
        let sec = i % 60;
        let min = (i / 60) % 60;
        let ms = (i * 137) % 1_000_000;
        let pid = 12345 + (i % 20);

        let line = match i % 5 {
            0 => {
                // Volume mount failure: UUID, Path, IP, Port, PID
                let uuid = format!("{:08x}-e29b-41d4-a716-{:012x}", i % 256, i % 4096);
                let ip = format!("10.0.{}.{}", (i / 256) % 10, i % 256);
                let port = 8080 + (i % 3);
                format!(
                    "E0909 13:{min:02}:{sec:02}.{ms:06} {pid} nestedpendingoperations.go:348] \
                     Operation for volume \"pvc-{uuid}\" failed with: mount failed for \
                     /var/lib/kubelet/pods/{uuid}/volumes/kubernetes.io~csi/data \
                     from {ip}:{port}, err: \"connection timed out after 30s\""
                )
            }
            1 => {
                // Transport warning: IP, PID, Path
                let ip = format!("10.0.{}.{}", (i / 256) % 10, i % 256);
                format!(
                    "W0909 13:{min:02}:{sec:02}.{ms:06} {pid} transport.go:356] \
                     Unable to cancel request for \
                     \"https://api.k8s.internal:6443/api/v1/namespaces/kube-system/pods\" \
                     to {ip}"
                )
            }
            2 => {
                // Lease failure: PID, Duration
                format!(
                    "E0909 13:{min:02}:{sec:02}.{ms:06} {pid} controller.go:145] \
                     Failed to ensure lease exists, will retry in 7s, err: \
                     client rate limiter Wait returned an error: context deadline exceeded"
                )
            }
            3 => {
                // Pod reconciliation: PodName, Namespace, PID
                let pods = [
                    "api-server-7b8c9d0e1f",
                    "worker-batch-6a7b8c9d0e",
                    "cache-redis-5f6a7b8c9d",
                    "db-postgres-4e5f6a7b8c",
                    "gateway-envoy-3d4e5f6a7b",
                ];
                let namespaces = ["production", "batch-jobs", "infra", "data", "ingress"];
                let idx = i % pods.len();
                format!(
                    "I0909 13:{min:02}:{sec:02}.{ms:06} {pid} reconciler.go:224] \
                     Reconciling pod \"{}-xx{:02x}\" in namespace \"{}\"",
                    pods[idx],
                    i % 256,
                    namespaces[idx],
                )
            }
            4 => {
                // Configmap sync: Hash (fixed-length SHA256-like), Namespace, PID
                let hash = format!(
                    "{:016x}{:016x}{:016x}{:016x}",
                    (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15),
                    (i as u64).wrapping_mul(0x517c_c1b7_2722_0a95),
                    (i as u64).wrapping_mul(0x6c62_272e_07bb_0142),
                    (i as u64).wrapping_mul(0x1234_5678_9abc_def0),
                );
                format!(
                    "I0909 13:{min:02}:{sec:02}.{ms:06} {pid} sync.go:190] \
                     Successfully synced configmap \"kube-system/coredns\" with hash {hash}"
                )
            }
            _ => unreachable!(),
        };
        lines.push(line);
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_produces_expected_line_count() {
        assert_eq!(generate_log(100).lines().count(), 100);
        assert_eq!(generate_log(1000).lines().count(), 1000);
    }

    #[test]
    fn generator_is_deterministic() {
        assert_eq!(generate_log(50), generate_log(50));
    }

    #[test]
    fn generator_exercises_all_patterns() {
        let log = generate_log(10);
        let lines: Vec<&str> = log.lines().collect();
        assert!(lines[0].contains("pvc-"));
        assert!(lines[1].contains("transport.go"));
        assert!(lines[2].contains("controller.go"));
        assert!(lines[3].contains("Reconciling pod"));
        assert!(lines[4].contains("synced configmap"));
    }
}
