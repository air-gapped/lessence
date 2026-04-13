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
