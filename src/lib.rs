//! lessence - Intelligent log compression via pattern-based folding

pub mod cli;
pub mod config;
pub mod folder;
pub mod ingest;
pub mod normalize;
pub mod patterns;
pub mod report;

pub use config::Config;
pub use folder::{PatternFolder, apply_pii_masking};

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
