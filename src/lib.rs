//! lessence - Intelligent log compression via pattern-based folding

pub mod analyzer;
pub mod cli;
pub mod config;
pub mod folder;
pub mod normalize;
pub mod output;
pub mod patterns;

pub use analyzer::LogAnalyzer;
pub use config::Config;
pub use folder::{PatternFolder, apply_pii_masking};

pub fn should_process_line(line: &str, config: &Config) -> bool {
    if let Some(max_length) = config.max_line_length {
        line.len() <= max_length
    } else {
        true
    }
}

pub fn should_process_line_count(current_line_number: usize, config: &Config) -> bool {
    if let Some(max_lines) = config.max_lines {
        current_line_number < max_lines
    } else {
        true
    }
}

pub fn sanitize_email(email: &str) -> String {
    let at_count = email.matches('@').count();
    if at_count != 1 {
        return email.to_string();
    }

    if let Some((local, domain)) = email.split_once('@') {
        if local.is_empty() || domain.is_empty() {
            return email.to_string();
        }

        let local_first = local.chars().next().unwrap_or(' ');
        let local_masked = format!("{local_first}***");

        let domain_masked = if let Some(last_dot_pos) = domain.rfind('.') {
            let (domain_parts, tld) = domain.split_at(last_dot_pos + 1);
            if domain_parts.is_empty() || tld.is_empty() {
                return email.to_string();
            }
            let domain_first = domain_parts.chars().next().unwrap_or(' ');
            format!("{domain_first}***.{tld}")
        } else {
            let domain_first = domain.chars().next().unwrap_or(' ');
            format!("{domain_first}***")
        };

        format!("{local_masked}@{domain_masked}")
    } else {
        email.to_string()
    }
}

pub fn process_line(line: &str, config: &Config) -> String {
    let normalizer = normalize::Normalizer::new(config.clone());
    if let Ok(log_line) = normalizer.normalize_line(line.to_string()) {
        log_line.normalized
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- should_process_line ----

    #[test]
    fn process_line_no_limit() {
        let config = Config::default();
        assert!(should_process_line("any length line", &config));
    }

    #[test]
    fn process_line_within_limit() {
        let config = Config {
            max_line_length: Some(100),
            ..Config::default()
        };
        assert!(should_process_line("short", &config));
    }

    #[test]
    fn process_line_at_limit() {
        let config = Config {
            max_line_length: Some(5),
            ..Config::default()
        };
        assert!(should_process_line("12345", &config));
    }

    #[test]
    fn process_line_over_limit() {
        let config = Config {
            max_line_length: Some(5),
            ..Config::default()
        };
        assert!(!should_process_line("123456", &config));
    }

    // ---- should_process_line_count ----

    #[test]
    fn line_count_no_limit() {
        let config = Config::default();
        assert!(should_process_line_count(999_999, &config));
    }

    #[test]
    fn line_count_within_limit() {
        let config = Config {
            max_lines: Some(100),
            ..Config::default()
        };
        assert!(should_process_line_count(50, &config));
    }

    #[test]
    fn line_count_at_limit() {
        let config = Config {
            max_lines: Some(100),
            ..Config::default()
        };
        assert!(!should_process_line_count(100, &config));
    }

    // ---- sanitize_email ----

    #[test]
    fn sanitize_valid_email() {
        let result = sanitize_email("user@example.com");
        assert_eq!(result, "u***@e***.com");
    }

    #[test]
    fn sanitize_no_at() {
        assert_eq!(sanitize_email("noemail"), "noemail");
    }

    #[test]
    fn sanitize_multiple_at() {
        assert_eq!(sanitize_email("a@b@c"), "a@b@c");
    }

    #[test]
    fn sanitize_empty_local() {
        assert_eq!(sanitize_email("@domain.com"), "@domain.com");
    }

    #[test]
    fn sanitize_empty_domain() {
        assert_eq!(sanitize_email("user@"), "user@");
    }

    #[test]
    fn sanitize_no_tld_dot() {
        let result = sanitize_email("user@localhost");
        assert_eq!(result, "u***@l***");
    }

    // ---- process_line ----

    #[test]
    fn process_line_normalizes() {
        let config = Config::default();
        let result = process_line("error at 10.0.0.1 port 8080", &config);
        assert!(result.contains("<IP>"), "should normalize IP: {result}");
    }

    #[test]
    fn process_line_plain_text() {
        let config = Config::default();
        let result = process_line("no patterns here", &config);
        assert_eq!(result, "no patterns here");
    }
}
