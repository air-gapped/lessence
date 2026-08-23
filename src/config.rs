/// Default similarity threshold in percent. Single origin for the clap
/// default on `--threshold` and `Config::default()` — they diverged once
/// (75 vs 85). 83 comes from the 2026-08 re-sweep under the 0.4.4 LCS
/// matcher (r98.12/vm9): distinct HTTP status classes re-merge at ≤81
/// and the fold cost jumps ~50% at ≥84, so 83 is the measured optimum.
pub const DEFAULT_THRESHOLD: u8 = 83;
/// Default minimum group size before folding (`--min-collapse`).
pub const DEFAULT_MIN_COLLAPSE: usize = 3;
/// Default cap on line length in bytes (`--max-line-length`, 1 MiB).
pub const DEFAULT_MAX_LINE_LENGTH: usize = 1024 * 1024;
/// Default output format (`--format`).
pub const DEFAULT_OUTPUT_FORMAT: &str = "text";

#[derive(Debug, Clone)]
pub struct Config {
    pub threshold: u8,
    pub min_collapse: usize,
    pub normalize_timestamps: bool,
    pub normalize_hashes: bool,
    pub normalize_ports: bool,
    pub normalize_ips: bool,
    pub normalize_fqdns: bool,
    pub normalize_uuids: bool,
    pub normalize_pids: bool,
    pub normalize_emails: bool,
    pub normalize_paths: bool,
    pub normalize_json: bool,
    pub normalize_durations: bool,
    pub normalize_kubernetes: bool,
    pub normalize_http_status: bool,
    pub normalize_brackets: bool,
    pub normalize_key_value: bool,
    pub normalize_quoted: bool,
    pub normalize_names: bool,
    pub output_format: String,
    pub stats: bool,
    pub preserve_color: bool,
    pub compact: bool,
    pub preflight: bool,
    pub summary: bool,
    // Constitutional CLI flags
    pub essence_mode: bool, // --essence: timestamp removal/tokenization for temporal independence
    pub thread_count: Option<usize>, // --threads: number of threads (1=single-threaded, None=auto-detect)

    // Security & ReDoS Protection (Constitutional Principle X)
    pub max_line_length: Option<usize>, // --max-line-length: skip lines exceeding this length (default: 1MB)
    pub max_lines: Option<usize>,       // --max-lines: stop processing after this many lines
    pub sanitize_pii: bool, // --sanitize-pii: mask email addresses in output (default: false)
    pub top_n: Option<usize>, // --top N: show only N most frequent patterns
    pub stats_json: bool,   // --stats-json: emit JSON stats to stderr
    pub fail_pattern: Option<String>, // --fail-on-pattern: exit 1 when regex matches input
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
            min_collapse: DEFAULT_MIN_COLLAPSE,
            normalize_timestamps: true,
            normalize_hashes: true,
            normalize_ports: true,
            normalize_ips: true,
            normalize_fqdns: true,
            normalize_uuids: true,
            normalize_pids: true,
            normalize_emails: true,
            normalize_paths: true,
            normalize_json: true,
            normalize_durations: true,
            normalize_kubernetes: true,
            normalize_http_status: true,
            normalize_brackets: true,
            normalize_key_value: true,
            normalize_quoted: true,
            normalize_names: true,
            output_format: DEFAULT_OUTPUT_FORMAT.to_string(),
            stats: true,
            preserve_color: false,
            compact: true,
            preflight: false,
            summary: false,
            // Constitutional CLI flags defaults
            essence_mode: false, // Essence mode disabled by default
            thread_count: None,  // Auto-detect threads by default (1=single-threaded)

            // Security defaults (Constitutional Principle X)
            max_line_length: Some(DEFAULT_MAX_LINE_LENGTH), // 1MB default line length limit
            max_lines: None,                                // No line count limit by default
            sanitize_pii: false, // Disabled by default (backward compatibility)
            top_n: None,         // No top-N filtering by default
            stats_json: false,   // No JSON stats by default
            fail_pattern: None,  // No fail pattern by default
        }
    }
}

/// One user-facing pattern group: the `--disable-patterns` name and the
/// detector gates it expands to. [`PATTERN_REGISTRY`] is the single source
/// of truth for these names — the CLI name list and help text
/// (`src/cli/mod.rs`) and the flag-to-`Config` mapping (`src/main.rs`)
/// both derive from it.
pub struct PatternEntry {
    /// User-facing name accepted by `--disable-patterns`.
    pub name: &'static str,
    set_enabled: fn(&mut Config, bool),
}

/// Every user-facing pattern group, in documentation order.
pub const PATTERN_REGISTRY: &[PatternEntry] = &[
    PatternEntry {
        name: "timestamp",
        set_enabled: |c, on| c.normalize_timestamps = on,
    },
    PatternEntry {
        name: "hash",
        set_enabled: |c, on| c.normalize_hashes = on,
    },
    PatternEntry {
        name: "network",
        set_enabled: |c, on| {
            c.normalize_ports = on;
            c.normalize_ips = on;
            c.normalize_fqdns = on;
        },
    },
    PatternEntry {
        name: "uuid",
        set_enabled: |c, on| c.normalize_uuids = on,
    },
    PatternEntry {
        name: "email",
        set_enabled: |c, on| c.normalize_emails = on,
    },
    PatternEntry {
        name: "path",
        set_enabled: |c, on| c.normalize_paths = on,
    },
    PatternEntry {
        name: "duration",
        set_enabled: |c, on| c.normalize_durations = on,
    },
    PatternEntry {
        name: "json",
        set_enabled: |c, on| c.normalize_json = on,
    },
    PatternEntry {
        name: "kubernetes",
        set_enabled: |c, on| c.normalize_kubernetes = on,
    },
    PatternEntry {
        name: "http-status",
        set_enabled: |c, on| c.normalize_http_status = on,
    },
    PatternEntry {
        name: "brackets",
        set_enabled: |c, on| c.normalize_brackets = on,
    },
    PatternEntry {
        name: "key-value",
        set_enabled: |c, on| c.normalize_key_value = on,
    },
    PatternEntry {
        name: "process",
        set_enabled: |c, on| c.normalize_pids = on,
    },
    PatternEntry {
        name: "quoted-string",
        set_enabled: |c, on| c.normalize_quoted = on,
    },
    PatternEntry {
        name: "name",
        set_enabled: |c, on| c.normalize_names = on,
    },
];

impl Config {
    /// Enable or disable one user-facing pattern group by name, expanding
    /// it to its detector gates via [`PATTERN_REGISTRY`]. Returns `false`
    /// when the name is not a registered pattern group.
    pub fn set_pattern_enabled(&mut self, name: &str, enabled: bool) -> bool {
        match PATTERN_REGISTRY.iter().find(|entry| entry.name == name) {
            Some(entry) => {
                (entry.set_enabled)(self, enabled);
                true
            }
            None => false,
        }
    }
}

pub fn parse_size_suffix(input: &str) -> Result<usize, String> {
    let input = input.trim();

    if let Some(num_str) = input.strip_suffix('K').or_else(|| input.strip_suffix('k')) {
        num_str
            .parse::<usize>()
            .map(|n| n * 1024)
            .map_err(|_| format!("Invalid number before 'K': {num_str}"))
    } else if let Some(num_str) = input.strip_suffix('M').or_else(|| input.strip_suffix('m')) {
        num_str
            .parse::<usize>()
            .map(|n| n * 1024 * 1024)
            .map_err(|_| format!("Invalid number before 'M': {num_str}"))
    } else if let Some(num_str) = input.strip_suffix('G').or_else(|| input.strip_suffix('g')) {
        num_str
            .parse::<usize>()
            .map(|n| n * 1024 * 1024 * 1024)
            .map_err(|_| format!("Invalid number before 'G': {num_str}"))
    } else {
        input
            .parse::<usize>()
            .map_err(|_| format!("Invalid number: {input}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_thread_count_is_none() {
        let config = Config::default();
        assert!(
            config.thread_count.is_none(),
            "Default thread_count should be None (auto-detect)"
        );
    }

    #[test]
    fn test_single_threaded_mode_detection() {
        let config = Config {
            thread_count: Some(1),
            ..Default::default()
        };
        // Test will fail until single_thread field is removed
        // This validates that thread_count == Some(1) replaces single_thread
        assert_eq!(
            config.thread_count,
            Some(1),
            "Single-threaded mode should be detected via thread_count == Some(1)"
        );
    }

    #[test]
    fn test_auto_detect_mode_detection() {
        let config = Config::default();
        // Auto-detect mode = thread_count is None
        assert!(
            config.thread_count.is_none(),
            "Auto-detect mode when thread_count is None"
        );
    }

    #[test]
    fn test_multi_thread_mode_detection() {
        let config = Config {
            thread_count: Some(4),
            ..Default::default()
        };
        assert_eq!(
            config.thread_count,
            Some(4),
            "Multi-threaded mode with explicit count"
        );
    }

    #[test]
    fn test_thread_count_validation() {
        let config = Config {
            thread_count: Some(0),
            ..Default::default()
        };
        assert_eq!(config.thread_count, Some(0));
    }

    // ---- parse_size_suffix ----

    #[test]
    fn parse_size_plain_number() {
        assert_eq!(parse_size_suffix("1024").unwrap(), 1024);
    }

    #[test]
    fn parse_size_k_suffix() {
        assert_eq!(parse_size_suffix("4K").unwrap(), 4 * 1024);
        assert_eq!(parse_size_suffix("4k").unwrap(), 4 * 1024);
    }

    #[test]
    fn parse_size_m_suffix() {
        assert_eq!(parse_size_suffix("2M").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size_suffix("2m").unwrap(), 2 * 1024 * 1024);
    }

    #[test]
    fn parse_size_g_suffix() {
        assert_eq!(parse_size_suffix("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size_suffix("1g").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_invalid() {
        assert!(parse_size_suffix("abc").is_err());
        assert!(parse_size_suffix("K").is_err()); // no number before K
        assert!(parse_size_suffix("M").is_err());
        assert!(parse_size_suffix("G").is_err());
    }

    #[test]
    fn parse_size_whitespace() {
        assert_eq!(parse_size_suffix("  1024  ").unwrap(), 1024);
    }

    // ---- Config defaults ----

    #[test]
    fn default_config_values() {
        let c = Config::default();
        // 83 is the documented CLI default; Config::default() must match it
        assert_eq!(c.threshold, 83);
        assert_eq!(c.min_collapse, 3);
        assert!(c.normalize_timestamps);
        assert!(c.normalize_hashes);
        assert!(c.normalize_ports);
        assert!(c.normalize_ips);
        assert!(c.normalize_fqdns);
        assert!(c.normalize_uuids);
        assert!(c.normalize_pids);
        assert!(c.normalize_emails);
        assert!(c.normalize_paths);
        assert!(c.normalize_json);
        assert!(c.normalize_durations);
        assert!(c.normalize_kubernetes);
        assert!(c.normalize_http_status);
        assert!(c.normalize_brackets);
        assert!(c.normalize_key_value);
        assert!(c.normalize_quoted);
        assert!(c.normalize_names);
        assert_eq!(c.output_format, "text");
        assert!(c.stats);
        assert!(!c.preserve_color);
        assert!(c.compact);
        assert!(!c.preflight);
        assert!(!c.summary);
        assert!(!c.essence_mode);
        assert_eq!(c.max_line_length, Some(1024 * 1024));
        assert!(c.max_lines.is_none());
        assert!(!c.sanitize_pii);
        assert!(c.top_n.is_none());
        assert!(!c.stats_json);
        assert!(c.fail_pattern.is_none());
    }

    // ---- pattern registry ----

    /// Names of the detector gates that are OFF after disabling `name`,
    /// relative to the all-enabled default.
    fn disabled_gates(name: &str) -> Vec<&'static str> {
        let mut config = Config::default();
        assert!(
            config.set_pattern_enabled(name, false),
            "registry must know pattern name {name}"
        );
        let gates = [
            ("normalize_timestamps", config.normalize_timestamps),
            ("normalize_hashes", config.normalize_hashes),
            ("normalize_ports", config.normalize_ports),
            ("normalize_ips", config.normalize_ips),
            ("normalize_fqdns", config.normalize_fqdns),
            ("normalize_uuids", config.normalize_uuids),
            ("normalize_pids", config.normalize_pids),
            ("normalize_emails", config.normalize_emails),
            ("normalize_paths", config.normalize_paths),
            ("normalize_json", config.normalize_json),
            ("normalize_durations", config.normalize_durations),
            ("normalize_kubernetes", config.normalize_kubernetes),
            ("normalize_http_status", config.normalize_http_status),
            ("normalize_brackets", config.normalize_brackets),
            ("normalize_key_value", config.normalize_key_value),
            ("normalize_quoted", config.normalize_quoted),
            ("normalize_names", config.normalize_names),
        ];
        gates
            .into_iter()
            .filter(|(_, enabled)| !enabled)
            .map(|(field, _)| field)
            .collect()
    }

    #[test]
    fn registry_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for entry in PATTERN_REGISTRY {
            assert!(
                seen.insert(entry.name),
                "duplicate registry name {}",
                entry.name
            );
        }
    }

    #[test]
    fn set_pattern_enabled_rejects_unknown_name() {
        let mut config = Config::default();
        assert!(!config.set_pattern_enabled("no-such-pattern", false));
        // and an unknown name must leave the config untouched
        assert_eq!(
            format!("{config:?}"),
            format!("{:?}", Config::default()),
            "unknown name must not modify the config"
        );
    }

    #[test]
    fn registry_expands_each_name_to_exactly_its_gates() {
        let want: &[(&str, &[&str])] = &[
            ("timestamp", &["normalize_timestamps"]),
            ("hash", &["normalize_hashes"]),
            (
                "network",
                &["normalize_ports", "normalize_ips", "normalize_fqdns"],
            ),
            ("uuid", &["normalize_uuids"]),
            ("email", &["normalize_emails"]),
            ("path", &["normalize_paths"]),
            ("duration", &["normalize_durations"]),
            ("json", &["normalize_json"]),
            ("kubernetes", &["normalize_kubernetes"]),
            ("http-status", &["normalize_http_status"]),
            ("brackets", &["normalize_brackets"]),
            ("key-value", &["normalize_key_value"]),
            ("process", &["normalize_pids"]),
            ("quoted-string", &["normalize_quoted"]),
            ("name", &["normalize_names"]),
        ];
        assert_eq!(
            want.len(),
            PATTERN_REGISTRY.len(),
            "expectation table must cover every registry entry"
        );
        for (name, gates) in want {
            let mut got = disabled_gates(name);
            let mut expected: Vec<&str> = gates.to_vec();
            got.sort_unstable();
            expected.sort_unstable();
            assert_eq!(got, expected, "detector gates disabled by {name}");
        }
    }

    #[test]
    fn set_pattern_enabled_true_restores_the_default() {
        let baseline = format!("{:?}", Config::default());
        for entry in PATTERN_REGISTRY {
            let mut config = Config::default();
            config.set_pattern_enabled(entry.name, false);
            assert_ne!(
                format!("{config:?}"),
                baseline,
                "disabling {} must change the config",
                entry.name
            );
            config.set_pattern_enabled(entry.name, true);
            assert_eq!(
                format!("{config:?}"),
                baseline,
                "re-enabling {} must restore the default",
                entry.name
            );
        }
    }
}
