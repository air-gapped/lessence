pub const DEFAULT_THRESHOLD: u8 = 83;
pub const LINES_A_COLLAPSED_GROUP_SHOWS: usize = 3;
pub const DEFAULT_MIN_COLLAPSE: usize = LINES_A_COLLAPSED_GROUP_SHOWS;
pub const DEFAULT_MAX_LINE_LENGTH: usize = 1024 * 1024;
pub const DEFAULT_OUTPUT_FORMAT: &str = "text";
pub const DEFAULT_SUMMARY_TOP: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Markdown,
    Json,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "text" | "plain" => Some(Self::Text),
            "markdown" | "md" => Some(Self::Markdown),
            "json" | "jsonl" => Some(Self::Json),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupSink {
    #[default]
    Render,
    RecordDistillMembers {
        members_per_group: usize,
    },
}

impl GroupSink {
    pub fn is_distilling(self) -> bool {
        matches!(self, Self::RecordDistillMembers { .. })
    }
}

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
    pub output_format: OutputFormat,
    pub stats: bool,
    pub preserve_color: bool,
    pub preflight: bool,
    pub summary: bool,
    pub essence_mode: bool,
    pub thread_count: Option<usize>,

    pub max_line_length: Option<usize>,
    pub max_lines: Option<usize>,
    pub sanitize: Option<crate::sanitize::Sanitizer>,
    pub top_n: Option<usize>,
    pub stats_json: bool,
    pub fail_pattern: Option<String>,
    pub frame_continuations: bool,
    pub explain: bool,
    pub group_sink: GroupSink,
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
            output_format: OutputFormat::Text,
            stats: true,
            preserve_color: false,
            preflight: false,
            summary: false,
            essence_mode: false,
            thread_count: None,

            max_line_length: Some(DEFAULT_MAX_LINE_LENGTH),
            max_lines: None,
            sanitize: None,
            top_n: None,
            stats_json: false,
            fail_pattern: None,
            frame_continuations: false,
            explain: false,
            group_sink: GroupSink::Render,
        }
    }
}

pub struct PatternEntry {
    pub name: &'static str,
    set_enabled: fn(&mut Config, bool),
}

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
    pub fn sanitizer(&self) -> Option<crate::sanitize::Sanitizer> {
        self.sanitize.clone()
    }

    pub fn keep_sanitized_detectors(&mut self) {
        use crate::sanitize::Entity;
        let Some(z) = self.sanitizer() else {
            return;
        };
        if z.names(Entity::Email) {
            self.normalize_emails = true;
        }
        if z.names(Entity::Ip) {
            self.normalize_ips = true;
        }
        if z.names(Entity::Host) {
            self.normalize_fqdns = true;
            self.keep_the_timestamp_a_syslog_host_follows();
        }
    }

    fn keep_the_timestamp_a_syslog_host_follows(&mut self) {
        self.normalize_timestamps = true;
    }

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

    for (suffix, multiplier) in [('K', 1024), ('M', 1024 * 1024), ('G', 1024 * 1024 * 1024)] {
        let lower = suffix.to_ascii_lowercase();
        if let Some(num_str) = input
            .strip_suffix(suffix)
            .or_else(|| input.strip_suffix(lower))
        {
            let n = num_str
                .parse::<usize>()
                .map_err(|_| format!("Invalid number before '{suffix}': {num_str}"))?;
            return n
                .checked_mul(multiplier)
                .ok_or_else(|| format!("Size too large: {input}"));
        }
    }

    input
        .parse::<usize>()
        .map_err(|_| format!("Invalid number: {input}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sanitized_entity_turns_back_on_exactly_its_detectors_and_nothing_else() {
        let all_off = |sanitize: &[&str], pii: bool| {
            let specs: Vec<String> = sanitize.iter().map(ToString::to_string).collect();
            let mut c = Config {
                sanitize: crate::sanitize::Sanitizer::parse(&specs, pii).unwrap(),
                ..Config::default()
            };
            for entry in PATTERN_REGISTRY {
                c.set_pattern_enabled(entry.name, false);
            }
            c.keep_sanitized_detectors();
            (
                c.normalize_emails,
                c.normalize_ips,
                c.normalize_fqdns,
                c.normalize_timestamps,
                c.normalize_ports || c.normalize_pids || c.normalize_paths,
            )
        };
        assert_eq!(
            all_off(&[], false),
            (false, false, false, false, false),
            "a run that sanitizes nothing keeps every gate as it was set"
        );
        assert_eq!(
            all_off(&["credential"], false),
            (false, false, false, false, false),
            "credentials have no detector to turn back on"
        );
        assert_eq!(all_off(&[], true), (true, false, false, false, false));
        assert_eq!(
            all_off(&["email"], false),
            (true, false, false, false, false)
        );
        assert_eq!(all_off(&["ip"], false), (false, true, false, false, false));
        assert_eq!(
            all_off(&["host"], false),
            (false, false, true, true, false),
            "host keeps the timestamp detector: a syslog host is the word after the timestamp"
        );
    }

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
        assert!(
            parse_size_suffix("K").is_err(),
            "no number before the suffix"
        );
        assert!(parse_size_suffix("M").is_err());
        assert!(parse_size_suffix("G").is_err());
    }

    #[test]
    fn parse_size_whitespace() {
        assert_eq!(parse_size_suffix("  1024  ").unwrap(), 1024);
    }

    #[test]
    fn default_config_values() {
        let c = Config::default();
        assert_eq!(
            c.threshold, DEFAULT_THRESHOLD,
            "Config::default() must use the documented CLI default threshold"
        );
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
        assert_eq!(c.output_format, OutputFormat::Text);
        assert!(c.stats);
        assert!(!c.preserve_color);
        assert!(!c.preflight);
        assert!(!c.summary);
        assert!(!c.essence_mode);
        assert_eq!(c.max_line_length, Some(1024 * 1024));
        assert!(c.max_lines.is_none());
        assert!(c.sanitize.is_none());
        assert!(c.top_n.is_none());
        assert!(!c.stats_json);
        assert!(c.fail_pattern.is_none());
    }

    fn gates_off_after_disabling(name: &str) -> Vec<&'static str> {
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
    fn the_registry_lists_pattern_names_in_documentation_order() {
        let names: Vec<&str> = PATTERN_REGISTRY.iter().map(|entry| entry.name).collect();
        assert_eq!(
            names,
            [
                "timestamp",
                "hash",
                "network",
                "uuid",
                "email",
                "path",
                "duration",
                "json",
                "kubernetes",
                "http-status",
                "brackets",
                "key-value",
                "process",
                "quoted-string",
                "name",
            ],
            "the order is the --disable-patterns help order and the README's"
        );
    }

    #[test]
    fn output_formats_parse_with_their_aliases_in_any_case() {
        for (given, want) in [
            ("text", Some(OutputFormat::Text)),
            ("plain", Some(OutputFormat::Text)),
            ("TEXT", Some(OutputFormat::Text)),
            ("markdown", Some(OutputFormat::Markdown)),
            ("md", Some(OutputFormat::Markdown)),
            ("MARKDOWN", Some(OutputFormat::Markdown)),
            ("json", Some(OutputFormat::Json)),
            ("jsonl", Some(OutputFormat::Json)),
            ("Json", Some(OutputFormat::Json)),
            ("xml", None),
        ] {
            assert_eq!(OutputFormat::parse(given), want, "--format {given}");
        }
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
            let mut got = gates_off_after_disabling(name);
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
