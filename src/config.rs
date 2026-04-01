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
    pub output_format: String,
    pub stats: bool,
    pub preserve_color: bool,
    pub compact: bool,
    pub max_tokens: Option<usize>,
    pub preflight: bool,
    pub summary: bool,
    #[allow(dead_code)]
    pub adaptive_min_group_size: usize,
    #[allow(dead_code)]
    pub adaptive_max_group_size: usize,
    // Constitutional CLI flags
    pub essence_mode: bool,           // --essence: timestamp removal/tokenization for temporal independence
    pub thread_count: Option<usize>,  // --threads: number of threads (1=single-threaded, None=auto-detect)
    
    // Security & ReDoS Protection (Constitutional Principle X)
    pub max_line_length: Option<usize>,  // --max-line-length: skip lines exceeding this length (default: 1MB)
    pub max_lines: Option<usize>,        // --max-lines: stop processing after this many lines
    pub sanitize_pii: bool,              // --sanitize-pii: mask email addresses in output (default: false)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threshold: 85,
            min_collapse: 3,
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
            output_format: "text".to_string(),
            stats: true,
            preserve_color: false,
            compact: true,
            max_tokens: None,
            preflight: false,
            summary: false,
            adaptive_min_group_size: 10,
            adaptive_max_group_size: 1000,
            // Constitutional CLI flags defaults
            essence_mode: false,               // Essence mode disabled by default
            thread_count: None,                // Auto-detect threads by default (1=single-threaded)
            
            // Security defaults (Constitutional Principle X)
            max_line_length: Some(1024 * 1024), // 1MB default line length limit
            max_lines: None,                   // No line count limit by default
            sanitize_pii: false,               // Disabled by default (backward compatibility)
        }
    }
}

pub fn parse_size_suffix(input: &str) -> Result<usize, String> {
    let input = input.trim();
    
    if let Some(num_str) = input.strip_suffix('K').or_else(|| input.strip_suffix('k')) {
        num_str.parse::<usize>()
            .map(|n| n * 1024)
            .map_err(|_| format!("Invalid number before 'K': {}", num_str))
    } else if let Some(num_str) = input.strip_suffix('M').or_else(|| input.strip_suffix('m')) {
        num_str.parse::<usize>()
            .map(|n| n * 1024 * 1024)
            .map_err(|_| format!("Invalid number before 'M': {}", num_str))
    } else if let Some(num_str) = input.strip_suffix('G').or_else(|| input.strip_suffix('g')) {
        num_str.parse::<usize>()
            .map(|n| n * 1024 * 1024 * 1024)
            .map_err(|_| format!("Invalid number before 'G': {}", num_str))
    } else {
        input.parse::<usize>()
            .map_err(|_| format!("Invalid number: {}", input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_thread_count_is_none() {
        let config = Config::default();
        assert!(config.thread_count.is_none(), "Default thread_count should be None (auto-detect)");
    }

    #[test]
    fn test_single_threaded_mode_detection() {
        let mut config = Config::default();
        config.thread_count = Some(1);
        // Test will fail until single_thread field is removed
        // This validates that thread_count == Some(1) replaces single_thread
        assert_eq!(config.thread_count, Some(1), "Single-threaded mode should be detected via thread_count == Some(1)");
    }

    #[test]
    fn test_auto_detect_mode_detection() {
        let config = Config::default();
        // Auto-detect mode = thread_count is None
        assert!(config.thread_count.is_none(), "Auto-detect mode when thread_count is None");
    }

    #[test]
    fn test_multi_thread_mode_detection() {
        let mut config = Config::default();
        config.thread_count = Some(4);
        assert_eq!(config.thread_count, Some(4), "Multi-threaded mode with explicit count");
    }

    #[test]
    fn test_thread_count_validation() {
        // This test documents the validation requirement
        // Actual validation happens at CLI parsing level
        // Zero thread count should be rejected (validated in main.rs)
        let mut config = Config::default();
        config.thread_count = Some(0);
        // This configuration is invalid but Config doesn't enforce it
        // Validation must happen at CLI level
        assert_eq!(config.thread_count, Some(0));
    }
}