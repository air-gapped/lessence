use super::Token;
use super::timestamp::detector::TIMESTAMP_PLACEHOLDER;
use regex::Regex;
use std::sync::LazyLock;

const OCTET: &str = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

static IPV4_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"\b(?:{OCTET}\.){{3}}{OCTET}\b")).unwrap());

static IPV6_LOOSE_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%[a-z0-9_]+(?:[.-][a-z0-9_]+)*)?")
        .unwrap()
});

const DOTTED_HOST: &str = r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+";
const LOCALHOST: &str = "localhost";

static DOTTED_HOST_PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"({DOTTED_HOST}|{LOCALHOST}):([1-9]\d{{1,4}})\b")).unwrap()
});

static IPV4_PORT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"\b((?:{OCTET}\.){{3}}{OCTET}):(\d{{1,5}})\b")).unwrap());

static RFC3986_IPV6_LITERAL_PORT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[([a-fA-F0-9:.]+(?:%\w+(?:[.-]\w+)*)?)\]:(\d{1,5})\b").unwrap());

static TAGGED_ADDRESS_PORT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(<IP>|\[<IP>\]):(\d{1,5})\b").unwrap());

static IPV4_MAPPED_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){1,6}:(?:\d{1,3}\.){3}\d{1,3}\b").unwrap()
});

static MAC_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b").unwrap());

static DOTTED_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b"
    ).unwrap()
});

const UNSPECIFIED_V4: &str = "0.0.0.0";
const NAME_GLUE_BEFORE: &[u8] = b"-./\\~";
const NAME_GLUE_AFTER: &[u8] = b"-/~";
const MAC_SEPARATORS: usize = 5;
const MAC_STRIDE: usize = 3;
const MIN_IPV6_LEN: usize = 2;
const MAX_IPV6_LEN: usize = 100;

const SYSLOG_FACILITIES: [&str; 20] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];
const SYSLOG_SEVERITIES: [&str; 10] = [
    "emerg", "alert", "crit", "err", "error", "warning", "warn", "notice", "info", "debug",
];

const DNS_ONLY_SUFFIXES: [&str; 7] = [
    "arpa",
    "local",
    "localdomain",
    "internal",
    "lan",
    "home",
    "svc",
];

const HOST_KEYS: [&str; 17] = [
    "host",
    "hostname",
    "hosts",
    "server",
    "servername",
    "addr",
    "address",
    "fqdn",
    "domain",
    "endpoint",
    "peer",
    "remote",
    "upstream",
    "origin",
    "target",
    "url",
    "uri",
];

const SCRUB_TLDS: &[&str] = &[
    "com",
    "net",
    "org",
    "io",
    "dev",
    "edu",
    "gov",
    "mil",
    "int",
    "info",
    "biz",
    "app",
    "ai",
    "cloud",
    "tech",
    "co",
    "us",
    "uk",
    "de",
    "fr",
    "nl",
    "se",
    "no",
    "fi",
    "dk",
    "eu",
    "ca",
    "au",
    "jp",
    "cn",
    "in",
    "br",
    "arpa",
    "local",
    "internal",
    "localdomain",
    "lan",
    "corp",
    "home",
    "svc",
];

pub struct NetworkDetector;

impl NetworkDetector {
    fn is_version_not_address(ip: &str) -> bool {
        ip.starts_with("0.") && ip != UNSPECIFIED_V4
    }

    fn in_dotted_name(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let before =
            m.start() >= 2 && b[m.start() - 1] == b'.' && b[m.start() - 2].is_ascii_alphanumeric();
        let after =
            m.end() + 1 < b.len() && b[m.end()] == b'.' && b[m.end() + 1].is_ascii_alphanumeric();
        before || after
    }

    fn is_ipv4_address(haystack: &str, m: &regex::Match) -> bool {
        !Self::is_version_not_address(m.as_str()) && !Self::in_dotted_name(haystack, m)
    }

    fn is_systemd_escape(b: &[u8], at: usize) -> bool {
        b[at] == b'\\' && b.get(at + 1) == Some(&b'x')
    }

    fn fqdn_stands_alone(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let before = m.start() > 0 && NAME_GLUE_BEFORE.contains(&b[m.start() - 1]);
        let after = m.end() < b.len()
            && (NAME_GLUE_AFTER.contains(&b[m.end()]) || Self::is_systemd_escape(b, m.end()));
        !(before || after)
    }

    fn ipv6_rejected_by_context(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let glued_to_letter = (m.start() > 0 && b[m.start() - 1].is_ascii_alphanumeric())
            || (m.end() < b.len() && b[m.end()].is_ascii_alphanumeric());
        let dotted_tail_follows = haystack[m.end()..]
            .strip_prefix('.')
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
        glued_to_letter || dotted_tail_follows || Self::in_longer_colon_chain(haystack, m)
    }

    fn parses_as_ipv6(candidate: &str) -> bool {
        let without_zone = candidate.split('%').next().unwrap_or("");
        Self::is_plausible_ipv6(without_zone) && without_zone.parse::<std::net::Ipv6Addr>().is_ok()
    }

    fn ipv6_len(haystack: &str, m: &regex::Match) -> Option<usize> {
        if Self::ipv6_rejected_by_context(haystack, m) {
            return None;
        }
        let text = m.as_str();
        if Self::parses_as_ipv6(text) {
            Some(text.len())
        } else if let Some(without_sentence_colon) = text.strip_suffix(':')
            && Self::parses_as_ipv6(without_sentence_colon)
        {
            Some(without_sentence_colon.len())
        } else {
            None
        }
    }

    fn has_mac_shape(text: &str) -> bool {
        let b = text.as_bytes();
        let mut seps = 0;
        let mut last = usize::MAX;
        for (i, c) in b.iter().enumerate() {
            if *c == b':' {
                if last != usize::MAX && i == last + MAC_STRIDE {
                    seps += 1;
                    if seps >= MAC_SEPARATORS {
                        return true;
                    }
                } else {
                    seps = 1;
                }
                last = i;
            }
        }
        false
    }

    fn port_match_glued_to_a_word(b: &[u8], m: &regex::Match) -> bool {
        m.start() > 0 && (b[m.start() - 1].is_ascii_alphanumeric() || b[m.start() - 1] == b'_')
    }

    fn is_source_line_reference(b: &[u8], m: &regex::Match) -> bool {
        m.end() < b.len() && b[m.end()] == b':'
    }

    fn port_rejected(haystack: &str, m: &regex::Match, hostname: &str) -> bool {
        let b = haystack.as_bytes();
        Self::in_longer_colon_chain(haystack, m)
            || Self::port_match_glued_to_a_word(b, m)
            || Self::is_source_line_reference(b, m)
            || Self::is_source_file(hostname)
    }

    fn touches_ipv6_compression(haystack: &str, m: &regex::Match) -> bool {
        haystack[m.end()..].starts_with("::") || haystack[..m.start()].ends_with("::")
    }

    fn in_longer_colon_chain(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let before =
            m.start() >= 2 && b[m.start() - 1] == b':' && b[m.start() - 2].is_ascii_hexdigit();
        let after =
            m.end() + 1 < b.len() && b[m.end()] == b':' && b[m.end() + 1].is_ascii_hexdigit();
        before || after
    }

    fn is_endpoint_fqdn(haystack: &str, m: &regex::Match) -> bool {
        Self::is_fqdn_candidate(m.as_str())
            && Self::fqdn_stands_alone(haystack, m)
            && Self::fqdn_has_endpoint_evidence(haystack, m)
    }
}

impl NetworkDetector {
    pub fn detect_and_replace(
        text: &str,
        normalize_ips: bool,
        normalize_ports: bool,
        normalize_fqdns: bool,
    ) -> (String, Vec<Token>) {
        if !Self::has_network_indicators(text, normalize_ips, normalize_ports, normalize_fqdns) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        if normalize_ips {
            Self::fold_macs_before_ports_and_sizes_can_split_them(text, &mut result, &mut tokens);
            Self::fold_ipv4_with_port(&mut result, &mut tokens, normalize_ports);
            Self::fold_ipv6_literal_with_port(&mut result, &mut tokens, normalize_ports);
            Self::fold_port_after_an_address_tag(&mut result, &mut tokens, normalize_ports);
            Self::fold_ipv4_mapped_before_ipv4_takes_its_tail(&mut result, &mut tokens);
            Self::fold_ipv4(&mut result, &mut tokens);
            Self::fold_ipv6(&mut result, &mut tokens);
        }
        if normalize_ports {
            Self::fold_host_ports(&mut result, &mut tokens);
        }
        if normalize_fqdns {
            Self::fold_endpoint_names(&mut result, &mut tokens);
        }

        (result, tokens)
    }

    fn fold_macs_before_ports_and_sizes_can_split_them(
        text: &str,
        result: &mut String,
        tokens: &mut Vec<Token>,
    ) {
        if !Self::has_mac_shape(text) {
            return;
        }
        let folded = MAC_REGEX.replace_all(result, |caps: &regex::Captures| {
            let m = caps.get(0).unwrap();
            if Self::in_longer_colon_chain(result, &m) || Self::touches_ipv6_compression(result, &m)
            {
                m.as_str().to_string()
            } else {
                tokens.push(Token::Mac(m.as_str().to_string()));
                "<MAC>".to_string()
            }
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn fold_ipv4_with_port(result: &mut String, tokens: &mut Vec<Token>, normalize_ports: bool) {
        let folded = IPV4_PORT_REGEX.replace_all(result, |caps: &regex::Captures| {
            let ip = caps.get(1).unwrap();
            if !Self::is_ipv4_address(result, &ip) {
                return caps[0].to_string();
            }
            tokens.push(Token::IPv4(ip.as_str().to_string()));
            let port_str = caps.get(2).unwrap().as_str();
            match port_str.parse::<u16>() {
                Ok(port) => {
                    if normalize_ports {
                        tokens.push(Token::Port(port));
                    }
                    "<IP>:<PORT>".to_string()
                }
                Err(_) => format!("<IP>:{port_str}"),
            }
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn fold_ipv6_literal_with_port(
        result: &mut String,
        tokens: &mut Vec<Token>,
        normalize_ports: bool,
    ) {
        *result = RFC3986_IPV6_LITERAL_PORT_REGEX
            .replace_all(result, |caps: &regex::Captures| {
                let ipv6_str = caps.get(1).unwrap().as_str();
                let port = caps.get(2).unwrap().as_str();
                if !Self::parses_as_ipv6(ipv6_str) {
                    return caps[0].to_string();
                }
                tokens.push(Token::IPv6(ipv6_str.to_string()));
                let parsed = port.parse::<u16>();
                if normalize_ports && let Ok(port) = parsed {
                    tokens.push(Token::Port(port));
                }
                if parsed.is_ok() {
                    "[<IP>]:<PORT>".to_string()
                } else {
                    format!("[<IP>]:{port}")
                }
            })
            .to_string();
    }

    fn fold_port_after_an_address_tag(
        result: &mut String,
        tokens: &mut Vec<Token>,
        normalize_ports: bool,
    ) {
        if !result.contains("<IP>") {
            return;
        }
        let folded = TAGGED_ADDRESS_PORT_REGEX.replace_all(result, |caps: &regex::Captures| {
            let address = caps.get(1).unwrap().as_str();
            let port = caps.get(2).unwrap().as_str();
            match port.parse::<u16>() {
                Ok(parsed) => {
                    if normalize_ports {
                        tokens.push(Token::Port(parsed));
                    }
                    format!("{address}:<PORT>")
                }
                Err(_) => caps[0].to_string(),
            }
        });
        if let std::borrow::Cow::Owned(s) = folded {
            *result = s;
        }
    }

    fn fold_ipv4_mapped_before_ipv4_takes_its_tail(result: &mut String, tokens: &mut Vec<Token>) {
        *result = IPV4_MAPPED_REGEX
            .replace_all(result, |caps: &regex::Captures| {
                let m = caps.get(0).unwrap();
                if Self::ipv6_rejected_by_context(result, &m) || !Self::parses_as_ipv6(m.as_str()) {
                    return m.as_str().to_string();
                }
                tokens.push(Token::IPv6(m.as_str().to_string()));
                "<IP>".to_string()
            })
            .to_string();
    }

    fn fold_ipv4(result: &mut String, tokens: &mut Vec<Token>) {
        *result = IPV4_REGEX
            .replace_all(result, |caps: &regex::Captures| {
                let m = caps.get(0).unwrap();
                if !Self::is_ipv4_address(result, &m) {
                    return m.as_str().to_string();
                }
                let ip_str = m.as_str();
                if !tokens
                    .iter()
                    .any(|t| matches!(t, Token::IPv4(s) if s == ip_str))
                {
                    tokens.push(Token::IPv4(ip_str.to_string()));
                }
                "<IP>".to_string()
            })
            .to_string();
    }

    fn fold_ipv6(result: &mut String, tokens: &mut Vec<Token>) {
        *result = IPV6_LOOSE_CANDIDATE
            .replace_all(result, |caps: &regex::Captures| {
                let m = caps.get(0).unwrap();
                match Self::ipv6_len(result, &m) {
                    Some(len) => {
                        tokens.push(Token::IPv6(m.as_str()[..len].to_string()));
                        format!("<IP>{}", &m.as_str()[len..])
                    }
                    None => m.as_str().to_string(),
                }
            })
            .to_string();
    }

    fn fold_host_ports(result: &mut String, tokens: &mut Vec<Token>) {
        *result = DOTTED_HOST_PORT_REGEX
            .replace_all(result, |caps: &regex::Captures| {
                let whole = caps.get(0).unwrap();
                let hostname = caps.get(1).unwrap().as_str();
                if Self::port_rejected(result, &whole, hostname) {
                    return whole.as_str().to_string();
                }
                let Ok(port) = caps.get(2).unwrap().as_str().parse::<u16>() else {
                    return whole.as_str().to_string();
                };
                if !tokens
                    .iter()
                    .any(|t| matches!(t, Token::Port(p) if *p == port))
                {
                    tokens.push(Token::Port(port));
                }
                format!("{hostname}:<PORT>")
            })
            .to_string();
    }

    fn fold_endpoint_names(result: &mut String, tokens: &mut Vec<Token>) {
        *result = DOTTED_NAME_REGEX
            .replace_all(result, |caps: &regex::Captures| {
                let m = caps.get(0).unwrap();
                if Self::is_endpoint_fqdn(result, &m) {
                    tokens.push(Token::Fqdn(m.as_str().to_string()));
                    "<FQDN>".to_string()
                } else {
                    m.as_str().to_string()
                }
            })
            .to_string();
    }

    fn is_syslog_facility_level(s: &str) -> bool {
        s.split_once('.').is_some_and(|(facility, level)| {
            !level.contains('.')
                && SYSLOG_FACILITIES.contains(&facility)
                && SYSLOG_SEVERITIES.contains(&level)
        })
    }

    fn is_fqdn_candidate(s: &str) -> bool {
        !Self::is_syslog_facility_level(s) && s.contains('.')
    }

    fn is_source_file(name: &str) -> bool {
        super::is_source_file_name(name)
    }

    pub fn dns_shaped_names(text: &str) -> Vec<&str> {
        Self::dns_shaped_spans(text)
            .into_iter()
            .map(|(s, e)| &text[s..e])
            .collect()
    }

    fn is_scrub_worthy_name(name: &str) -> bool {
        name.matches('.').count() >= 2
            || name
                .rsplit_once('.')
                .is_some_and(|(_, tld)| SCRUB_TLDS.iter().any(|t| t.eq_ignore_ascii_case(tld)))
    }

    pub fn dns_shaped_spans(text: &str) -> Vec<(usize, usize)> {
        if !text.contains('.') {
            return Vec::new();
        }
        DOTTED_NAME_REGEX
            .find_iter(text)
            .filter(|m| {
                let name = m.as_str();
                Self::is_fqdn_candidate(name)
                    && Self::fqdn_stands_alone(text, m)
                    && !Self::is_source_file(name)
                    && Self::is_scrub_worthy_name(name)
            })
            .map(|m| (m.start(), m.end()))
            .collect()
    }

    pub fn ipv4_spans(text: &str) -> Vec<(usize, usize)> {
        if !text.contains('.') {
            return Vec::new();
        }
        IPV4_REGEX
            .find_iter(text)
            .filter(|m| Self::is_ipv4_address(text, m))
            .map(|m| (m.start(), m.end()))
            .collect()
    }

    fn has_dns_only_suffix(name: &str) -> bool {
        name.rsplit_once('.').is_some_and(|(_, last)| {
            DNS_ONLY_SUFFIXES
                .iter()
                .any(|s| s.eq_ignore_ascii_case(last))
        })
    }

    fn has_port_after(b: &[u8], m: &regex::Match) -> bool {
        let rest = &b[m.end()..];
        let numeric_port = rest.len() >= 2 && rest[0] == b':' && rest[1].is_ascii_digit();
        (numeric_port || rest.starts_with(b":<PORT>")) && !Self::is_source_file(m.as_str())
    }

    fn has_scheme_before(haystack: &str, m: &regex::Match) -> bool {
        haystack[..m.start()].ends_with("://")
    }

    fn in_syslog_host_slot(haystack: &str, m: &regex::Match) -> bool {
        m.start() == TIMESTAMP_PLACEHOLDER.len() + 1
            && haystack.starts_with(TIMESTAMP_PLACEHOLDER)
            && haystack.as_bytes()[TIMESTAMP_PLACEHOLDER.len()] == b' '
    }

    fn is_value_of_a_host_key(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let mut i = m.start();
        while i > 0 && matches!(b[i - 1], b'"' | b'\'' | b' ') {
            i -= 1;
        }
        if !(i > 0 && matches!(b[i - 1], b'=' | b':')) {
            return false;
        }
        i -= 1;
        while i > 0 && matches!(b[i - 1], b'"' | b'\'') {
            i -= 1;
        }
        let key_end = i;
        while i > 0 && (b[i - 1].is_ascii_alphanumeric() || matches!(b[i - 1], b'_' | b'-' | b'.'))
        {
            i -= 1;
        }
        let key = haystack[i..key_end].to_ascii_lowercase();
        let last_word = key.rsplit(['_', '-', '.']).next().unwrap_or("");
        HOST_KEYS.contains(&last_word)
    }

    fn fqdn_has_endpoint_evidence(haystack: &str, m: &regex::Match) -> bool {
        Self::has_dns_only_suffix(m.as_str())
            || Self::has_port_after(haystack.as_bytes(), m)
            || Self::has_scheme_before(haystack, m)
            || Self::in_syslog_host_slot(haystack, m)
            || Self::is_value_of_a_host_key(haystack, m)
    }

    /// ```
    /// use lessence::patterns::network::NetworkDetector;
    /// let check = NetworkDetector::is_plausible_ipv6("2001:db8::1");
    /// assert!(check);
    /// let check = NetworkDetector::is_plausible_ipv6(":");
    /// assert!(!check);
    /// ```
    pub fn is_plausible_ipv6(input: &str) -> bool {
        if !(MIN_IPV6_LEN..=MAX_IPV6_LEN).contains(&input.len()) {
            return false;
        }

        let mut has_colon = false;
        let mut has_hex = false;

        for ch in input.chars() {
            match ch {
                ':' => has_colon = true,
                '.' => {}
                '0'..='9' | 'a'..='f' | 'A'..='F' => has_hex = true,
                _ => return false,
            }
        }

        has_colon && (has_hex || input == "::")
    }

    #[inline]
    fn has_network_indicators(
        text: &str,
        normalize_ips: bool,
        normalize_ports: bool,
        normalize_fqdns: bool,
    ) -> bool {
        let may_have_address = normalize_ips && (text.contains('.') || text.contains(':'));
        let may_have_port = normalize_ports && text.contains(':');
        let may_have_name = normalize_fqdns && text.contains('.');
        may_have_address || may_have_port || may_have_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ipv4_address_folds_to_ip() {
        let text = "Connection failed to 192.168.1.100 (timeout)";
        let (result, tokens) = NetworkDetector::detect_and_replace(text, true, false, false);
        assert_eq!(result, "Connection failed to <IP> (timeout)");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::IPv4(_)));
    }

    #[test]
    fn a_port_after_an_address_tag_is_a_port() {
        for (text, folded) in [
            ("dial <IP>:5432 failed", "dial <IP>:<PORT> failed"),
            (
                "fetch http://[<IP>]:8080/health",
                "fetch http://[<IP>]:<PORT>/health",
            ),
        ] {
            let (result, tokens) = NetworkDetector::detect_and_replace(text, true, true, false);
            assert_eq!(result, folded, "{text}");
            assert_eq!(
                tokens.iter().any(|t| matches!(t, Token::Port(_))),
                folded.contains("<PORT>"),
                "{text}: {tokens:?}"
            );
        }
        let (result, tokens) =
            NetworkDetector::detect_and_replace("dial <IP>:5432 failed", true, false, false);
        assert_eq!(result, "dial <IP>:<PORT> failed");
        assert!(tokens.is_empty(), "{tokens:?}");
    }

    #[test]
    fn an_ipv4_with_port_folds_both() {
        let text = "Connection failed to 192.168.1.100:8080 (timeout)";
        let (result, tokens) = NetworkDetector::detect_and_replace(text, true, true, false);
        assert_eq!(result, "Connection failed to <IP>:<PORT> (timeout)");
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[0], Token::IPv4(_)));
        assert!(matches!(tokens[1], Token::Port(8080)));
    }

    #[test]
    fn a_port_without_a_host_stays_literal() {
        let text = "Listening on port :8080";
        let (result, tokens) = NetworkDetector::detect_and_replace(text, false, true, false);
        assert_eq!(
            result, "Listening on port :8080",
            "a port needs a dotted host or localhost before the colon"
        );
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn a_full_ipv6_address_folds_to_ip() {
        let text = "Connected to 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let (result, tokens) = NetworkDetector::detect_and_replace(text, true, false, false);
        assert_eq!(result, "Connected to <IP>");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::IPv6(_)));
    }

    #[test]
    fn plausible_ipv6_empty_rejected() {
        assert!(!NetworkDetector::is_plausible_ipv6(""));
    }

    #[test]
    fn plausible_ipv6_too_short() {
        assert!(!NetworkDetector::is_plausible_ipv6("x"));
    }

    #[test]
    fn plausible_ipv6_too_long() {
        let long = "a".repeat(101);
        assert!(!NetworkDetector::is_plausible_ipv6(&long));
    }

    #[test]
    fn plausible_ipv6_no_colons() {
        assert!(!NetworkDetector::is_plausible_ipv6("abcdef"));
    }

    #[test]
    fn plausible_ipv6_valid() {
        assert!(NetworkDetector::is_plausible_ipv6("2001:db8::1"));
    }

    #[test]
    fn net_ind_ip_dot() {
        assert!(NetworkDetector::has_network_indicators(
            "192.168.1.1",
            true,
            false,
            false
        ));
    }

    #[test]
    fn net_ind_ip_colon() {
        assert!(NetworkDetector::has_network_indicators(
            "2001:db8::1",
            true,
            false,
            false
        ));
    }

    #[test]
    fn net_ind_port_colon() {
        assert!(NetworkDetector::has_network_indicators(
            "host:8080",
            false,
            true,
            false
        ));
    }

    #[test]
    fn any_dotted_text_passes_the_name_prefilter() {
        for name in ["example.com", "example.org", "example.net"] {
            assert!(
                NetworkDetector::has_network_indicators(name, false, false, true),
                "{name}"
            );
        }
    }

    #[test]
    fn net_ind_all_disabled() {
        assert!(!NetworkDetector::has_network_indicators(
            "192.168.1.1",
            false,
            false,
            false
        ));
    }

    #[test]
    fn net_ind_fqdn_no_dot() {
        assert!(!NetworkDetector::has_network_indicators(
            "localhost",
            false,
            false,
            true
        ));
    }

    #[test]
    fn a_source_file_and_line_is_never_a_port() {
        for line in [
            "server.go:1234",
            "main.rs:42",
            "app.py:100",
            "index.js:55",
            "App.java:200",
            "main.c:30",
            "main.cpp:30",
            "header.h:10",
        ] {
            let (result, tokens) = NetworkDetector::detect_and_replace(line, false, true, false);
            assert!(!result.contains("<PORT>"), "{line}: {result}");
            assert!(
                !tokens.iter().any(|t| matches!(t, Token::Port(_))),
                "{line}: {tokens:?}"
            );
        }
    }

    #[test]
    fn ipv4_port_split() {
        let (result, tokens) =
            NetworkDetector::detect_and_replace("connect 10.0.0.1:8080", true, true, false);
        assert!(result.contains("<IP>"));
        assert!(result.contains("<PORT>"));
        assert!(tokens.iter().any(|t| matches!(t, Token::IPv4(_))));
        assert!(tokens.iter().any(|t| matches!(t, Token::Port(8080))));
    }

    #[test]
    fn ports_stay_untokenised_when_port_folding_is_off() {
        let (result, tokens) =
            NetworkDetector::detect_and_replace("host 10.0.0.1:8080", true, false, false);
        assert!(result.contains("<IP>"));
        assert!(
            !tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "a port must not tokenise when port folding is off"
        );
    }

    #[test]
    fn ipv4_port_extracts_correct_ip() {
        let (_, tokens) =
            NetworkDetector::detect_and_replace("connect 172.16.0.1:443", true, true, false);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::IPv4(s) if s == "172.16.0.1")),
            "should extract exact IP '172.16.0.1', got: {tokens:?}"
        );
        assert!(
            tokens.iter().any(|t| matches!(t, Token::Port(443))),
            "should extract port 443, got: {tokens:?}"
        );
    }

    #[test]
    fn a_five_digit_port_splits_off_the_exact_address() {
        let (_, tokens) =
            NetworkDetector::detect_and_replace("host 10.0.0.99:65535", true, true, false);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::IPv4(s) if s == "10.0.0.99")),
            "a five-digit port must split off exactly the address, got: {tokens:?}"
        );
        assert!(
            tokens.iter().any(|t| matches!(t, Token::Port(65535))),
            "should extract port 65535, got: {tokens:?}"
        );
    }

    #[test]
    fn a_one_digit_port_splits_off_the_exact_address() {
        let (_, tokens) =
            NetworkDetector::detect_and_replace("addr 192.168.0.1:8", true, true, false);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::IPv4(s) if s == "192.168.0.1")),
            "should extract exact IP '192.168.0.1', got: {tokens:?}"
        );
        assert!(
            tokens.iter().any(|t| matches!(t, Token::Port(8))),
            "should extract port 8, got: {tokens:?}"
        );
    }

    #[test]
    fn an_endpoint_is_folded_only_when_its_parts_are_valid() {
        for (line, want) in [
            (
                "dial pkg.12.51.100.77:443 ok",
                "dial pkg.12.51.100.77:<PORT> ok",
            ),
            ("v 0.8.10.3:443 ok", "v 0.8.10.3:<PORT> ok"),
            ("dial [1234]:443 ok", "dial [1234]:443 ok"),
            ("from ::ffff:999.1.1.1 ok", "from ::ffff:999.1.1.1 ok"),
            ("from 2001:db8::ffff:192.0.2.1 ok", "from <IP> ok"),
            ("from 64:ff9b::192.0.2.33 ok", "from <IP> ok"),
            ("dial [aa:bb:cc:dd:ee:ff::]:443 ok", "dial [<IP>]:<PORT> ok"),
            ("ping fe80::1%eth0.100 ok", "ping <IP> ok"),
            ("dial localhost:65536 ok", "dial localhost:65536 ok"),
            ("connect example.com:443 ok", "connect <FQDN>:<PORT> ok"),
            ("dial db.LOCAL ok", "dial <FQDN> ok"),
        ] {
            let (r, tokens) = NetworkDetector::detect_and_replace(line, true, true, true);
            assert_eq!(r, want, "{line}: {tokens:?}");
        }
        let (_, tokens) =
            NetworkDetector::detect_and_replace("ping fe80::1%eth0.100 ok", true, true, true);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::IPv6(s) if s == "fe80::1%eth0.100")),
            "{tokens:?}"
        );
        assert_eq!(
            NetworkDetector::dns_shaped_names("see EXAMPLE.COM now"),
            vec!["EXAMPLE.COM"]
        );
        assert!(NetworkDetector::dns_shaped_spans("see report.XYZ and notes.Abc now").is_empty());
    }

    #[test]
    fn no_duplicate_ipv4_tokens() {
        let (_, tokens) =
            NetworkDetector::detect_and_replace("from 10.0.0.1 to 10.0.0.1", true, false, false);
        let ip_count = tokens
            .iter()
            .filter(|t| matches!(t, Token::IPv4(s) if s == "10.0.0.1"))
            .count();
        assert_eq!(
            ip_count, 1,
            "duplicate IPv4 tokens should be suppressed, got: {tokens:?}"
        );
    }

    #[test]
    fn no_duplicate_port_tokens() {
        let (_, tokens) = NetworkDetector::detect_and_replace(
            "server1.example.com:8080 server2.example.net:8080",
            false,
            true,
            true,
        );
        let port_count = tokens
            .iter()
            .filter(|t| matches!(t, Token::Port(8080)))
            .count();
        assert_eq!(
            port_count, 1,
            "duplicate Port tokens should be suppressed, got: {tokens:?}"
        );
    }

    #[test]
    fn the_shortest_plausible_ipv6_is_two_colons() {
        assert!(NetworkDetector::is_plausible_ipv6("::"));
    }

    #[test]
    fn one_char_is_too_short_for_ipv6() {
        assert!(!NetworkDetector::is_plausible_ipv6(":"));
    }

    #[test]
    fn a_hundred_chars_is_the_longest_plausible_ipv6() {
        let mut s = String::new();
        for _ in 0..50 {
            s.push_str("a:");
        }
        assert_eq!(s.len(), 100);
        assert!(
            NetworkDetector::is_plausible_ipv6(&s),
            "len=100 should be accepted"
        );
    }

    #[test]
    fn a_hundred_and_one_chars_is_too_long_for_ipv6() {
        let mut s = String::new();
        for _ in 0..50 {
            s.push_str("a:");
        }
        s.push('a');
        assert_eq!(s.len(), 101);
        assert!(
            !NetworkDetector::is_plausible_ipv6(&s),
            "len=101 should be rejected"
        );
    }

    #[test]
    fn plausible_ipv6_ipv4_mapped() {
        assert!(
            NetworkDetector::is_plausible_ipv6("::ffff:192.168.1.1"),
            "IPv4-mapped IPv6 should be plausible: dots are allowed"
        );
    }

    #[test]
    fn dots_and_colons_without_hex_are_not_ipv6() {
        assert!(
            !NetworkDetector::is_plausible_ipv6(":..:.."),
            "dots and colons without hex digits should be rejected"
        );
    }

    #[test]
    fn plausible_ipv6_double_colon_special_case() {
        assert!(
            NetworkDetector::is_plausible_ipv6("::"),
            ":: should be accepted even without hex digits"
        );
    }

    #[test]
    fn plausible_ipv6_colons_only_not_double_colon() {
        assert!(
            !NetworkDetector::is_plausible_ipv6(":::"),
            "::: should be rejected: has no hex and is not ::"
        );
    }

    #[test]
    fn plausible_ipv6_invalid_char() {
        assert!(
            !NetworkDetector::is_plausible_ipv6("20g1:db8::1"),
            "non-hex letter should be rejected"
        );
    }

    #[test]
    fn ports_need_a_colon() {
        assert!(
            !NetworkDetector::has_network_indicators("no-colon-here", false, true, false),
            "port folding on, but no colon"
        );
    }

    #[test]
    fn net_ind_fqdn_any_dot_passes() {
        assert!(NetworkDetector::has_network_indicators(
            "file.txt", false, false, true
        ));
        let (result, tokens) =
            NetworkDetector::detect_and_replace("open file.txt ok", false, false, true);
        assert_eq!(
            result, "open file.txt ok",
            "the prefilter passes any dot; precision is endpoint evidence"
        );
        assert!(tokens.is_empty());
    }

    #[test]
    fn a_tld_word_without_a_dot_is_no_name() {
        assert!(!NetworkDetector::has_network_indicators(
            "dotcom", false, false, true
        ));
    }

    #[test]
    fn port_detected_for_non_source_file_hostname() {
        let (result, tokens) =
            NetworkDetector::detect_and_replace("myserver.local:9090", false, true, false);
        assert!(
            result.contains("<PORT>"),
            "hostname:port should be detected: {result}"
        );
        assert!(
            tokens.iter().any(|t| matches!(t, Token::Port(9090))),
            "Port token should be emitted: {tokens:?}"
        );
    }

    #[test]
    fn ipv6_port_detection_tokens() {
        let (result, tokens) =
            NetworkDetector::detect_and_replace("[2001:db8::1]:443", true, true, false);
        assert!(
            result.contains("[<IP>]:<PORT>"),
            "IPv6 port should be replaced: {result}"
        );
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::IPv6(s) if s == "2001:db8::1")),
            "should extract IPv6 address: {tokens:?}"
        );
        assert!(
            tokens.iter().any(|t| matches!(t, Token::Port(443))),
            "should extract port: {tokens:?}"
        );
    }

    #[test]
    fn a_name_before_a_port_is_a_host() {
        let (r, tokens) =
            NetworkDetector::detect_and_replace("connect example.com:443 ok", false, false, true);
        assert_eq!(r, "connect <FQDN>:443 ok");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Fqdn(s) if s == "example.com")),
            "valid FQDN should produce Fqdn token: {tokens:?}"
        );
    }

    #[test]
    fn a_dotted_name_is_a_host_only_on_evidence() {
        for (line, want, evidence) in [
            ("connect example.com ok", "connect example.com ok", "none"),
            (
                "denied cephclusters.ceph.rook.io",
                "denied cephclusters.ceph.rook.io",
                "none",
            ),
            (
                "denied postgresqls.acid.zalan.do",
                "denied postgresqls.acid.zalan.do",
                "none",
            ),
            (
                "GroupVersion apiextensions.k8s.io v1",
                "GroupVersion apiextensions.k8s.io v1",
                "none",
            ),
            (
                "connect example.com:443 ok",
                "connect <FQDN>:443 ok",
                "port",
            ),
            ("host=db-01.example.com up", "host=<FQDN> up", "host key"),
            (
                "remote_addr=db-01.example.com",
                "remote_addr=<FQDN>",
                "host key",
            ),
            (
                r#""server":"db-01.example.com""#,
                r#""server":"<FQDN>""#,
                "host key",
            ),
            (
                "upstream: db-01.example.com",
                "upstream: <FQDN>",
                "host key",
            ),
            (
                "<TIMESTAMP> gw.example.com kernel: up",
                "<TIMESTAMP> <FQDN> kernel: up",
                "syslog host slot",
            ),
            (
                "PTR 77.100.51.198.in-addr.arpa",
                "PTR <FQDN>",
                "DNS-only suffix",
            ),
            (
                "dial postgres.staging.svc ok",
                "dial <FQDN> ok",
                "DNS-only suffix",
            ),
            ("class=hibernate.SQL", "class=hibernate.SQL", "none"),
            (
                "caller=checkpoint.go:123 ok",
                "caller=checkpoint.go:123 ok",
                "none: a source file's number is its line",
            ),
            (
                "resource=cephclusters.ceph.rook.io",
                "resource=cephclusters.ceph.rook.io",
                "none",
            ),
        ] {
            let (r, _) = NetworkDetector::detect_and_replace(line, false, false, true);
            assert_eq!(r, want, "{line}: evidence {evidence}");
        }
    }

    #[test]
    fn fqdn_rejects_dotted_code_identifiers() {
        for line in ["loading hibernate.SQL config", "file scope.go ok"] {
            let (result, tokens) = NetworkDetector::detect_and_replace(line, false, false, true);
            assert_eq!(result, line, "code identifier must stay intact");
            assert!(
                !tokens.iter().any(|t| matches!(t, Token::Fqdn(_))),
                "no FQDN token expected for {line}: {tokens:?}"
            );
        }
    }

    #[test]
    fn fqdn_accepts_internal_cluster_names() {
        let (result, tokens) =
            NetworkDetector::detect_and_replace("dial postgres.staging.svc ok", false, false, true);
        assert!(result.contains("<FQDN>"), "got: {result}");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Fqdn(s) if s == "postgres.staging.svc")),
        );
    }

    #[test]
    fn a_leading_dot_never_enters_a_name_token() {
        let (_, tokens) = NetworkDetector::detect_and_replace(".example.com", false, false, true);
        assert!(
            !tokens
                .iter()
                .any(|t| matches!(t, Token::IPv4(s) | Token::Fqdn(s) if s.starts_with('.'))),
            "leading dot FQDN should not produce token: {tokens:?}"
        );
    }

    #[test]
    fn a_trailing_dot_never_enters_a_name_token() {
        let (_, tokens) = NetworkDetector::detect_and_replace("example.com.", false, false, true);
        assert!(
            !tokens
                .iter()
                .any(|t| matches!(t, Token::IPv4(s) | Token::Fqdn(s) if s.ends_with('.'))),
            "trailing dot FQDN should not produce token: {tokens:?}"
        );
    }

    #[test]
    fn a_bare_word_before_a_colon_is_a_field_not_a_host() {
        for (input, expected) in [
            ("count:26 objects", "count:26 objects"),
            ("size:107 bytes", "size:107 bytes"),
            ("args=&{Threshold:80}", "args=&{Threshold:80}"),
            ("CacheBlockSize:1600 x", "CacheBlockSize:1600 x"),
            ("dial harbor-core:80 ok", "dial harbor-core:80 ok"),
            (
                "dial redis.svc.cluster.local:6379",
                "dial redis.svc.cluster.local:<PORT>",
            ),
        ] {
            let (r, t) = NetworkDetector::detect_and_replace(input, false, true, false);
            assert_eq!(r, expected, "input: {input}");
            assert_eq!(
                t.iter().any(|t| matches!(t, Token::Port(_))),
                expected.contains("<PORT>")
            );
        }
    }

    #[test]
    fn a_port_stands_alone() {
        for (input, expected) in [
            (
                "[ERROR] utm_cloud_is_alive:46: UTM Cloud x",
                "[ERROR] utm_cloud_is_alive:46: UTM Cloud x",
            ),
            ("dial localhost:8080 ok", "dial localhost:<PORT> ok"),
            (
                "at db.example.com:5432, done",
                "at db.example.com:<PORT>, done",
            ),
        ] {
            let (r, _) = NetworkDetector::detect_and_replace(input, false, true, false);
            assert_eq!(r, expected, "input: {input}");
        }
    }

    #[test]
    fn a_mac_is_one_atom() {
        for (input, expected) in [
            (
                "DHCPREQUEST(br0) 10.63.37.193 f2:ff:9b:f1:5f:29",
                "DHCPREQUEST(br0) <IP> <MAC>",
            ),
            (
                "[IGMP] Failed to find 6A:D1:EA:BB:8B:14 vid:1",
                "[IGMP] Failed to find <MAC> vid:1",
            ),
            ("using 86:5a:a5:af:c8:7e now", "using <MAC> now"),
            (
                "RSA 01:67:32:d9:b3:20:5d:2d:5f:b4:35:c5:a5:8b:0a:5e",
                "RSA 01:67:32:d9:b3:20:5d:2d:5f:b4:35:c5:a5:8b:0a:5e",
            ),
            ("addr 2001:db8:12:34:56:78:9a:bc x", "addr <IP> x"),
            ("at 12:34:56 today", "at 12:34:56 today"),
        ] {
            let (r, _) = NetworkDetector::detect_and_replace(input, true, true, false);
            assert_eq!(r, expected, "input: {input}");
        }
        let (_, t) =
            NetworkDetector::detect_and_replace("mac 6A:D1:EA:BB:8B:14", true, true, false);
        assert!(
            t.iter()
                .any(|t| matches!(t, Token::Mac(s) if s == "6A:D1:EA:BB:8B:14"))
        );
        assert!(NetworkDetector::has_mac_shape("x aa:bb:cc:dd:ee:ff"));
        assert!(!NetworkDetector::has_mac_shape(
            "2025-01-20 10:15:30 a:b:c:d"
        ));
    }

    #[test]
    fn ipv4_inside_a_hostname_is_part_of_the_name() {
        let (r, t) = NetworkDetector::detect_and_replace(
            "hostname=pool-198.51.100.77.washdc.example.net rev 77.100.51.198.in-addr.arpa addr=198.51.100.77 range 10.0.0.1-10.0.0.9",
            true,
            false,
            true,
        );
        assert_eq!(r, "hostname=<FQDN> rev <FQDN> addr=<IP> range <IP>-<IP>");
        assert_eq!(t.iter().filter(|t| matches!(t, Token::IPv4(_))).count(), 3);
        assert_eq!(t.iter().filter(|t| matches!(t, Token::Fqdn(_))).count(), 2);
    }

    #[test]
    fn fqdn_glued_to_a_longer_name_stays_literal() {
        for line in [
            "key feature.node.kubernetes.io/cpu-cpuid.X87=true",
            "image docker.io/library/nginx:1.25",
            r"unit pods-abc\x2ddef-volumes-kubernetes.io\x7eprojected.mount",
            "svc <UUID>.svc.cluster.local up",
            "api coordination.k8s.io/v1beta1 skipped",
        ] {
            let (r, t) = NetworkDetector::detect_and_replace(line, true, true, true);
            assert_eq!(r, line);
            assert!(
                !t.iter().any(|t| matches!(t, Token::Fqdn(_))),
                "{line}: {t:?}"
            );
        }
        let (r, _) = NetworkDetector::detect_and_replace(
            "GroupVersion apiextensions.k8s.io v1",
            true,
            true,
            true,
        );
        assert_eq!(
            r, "GroupVersion apiextensions.k8s.io v1",
            "a standalone API group reads like a host and stays literal"
        );
        let (r, _) = NetworkDetector::detect_and_replace(
            r#"msg="loading \"io.containerd.store.v1.local\"...""#,
            true,
            true,
            true,
        );
        assert_eq!(
            r, r#"msg="loading \"<FQDN>\"...""#,
            "an escaped quote after the name is not glue"
        );
    }

    #[test]
    fn dns_shaped_names_err_toward_scrubbing() {
        let names = NetworkDetector::dns_shaped_names(
            "denied cephclusters.ceph.rook.io and postgresqls.acid.zalan.do at db-01.example.com caller=checkpoint.go:12 daemon.info x.y",
        );
        assert_eq!(
            names,
            vec![
                "cephclusters.ceph.rook.io",
                "postgresqls.acid.zalan.do",
                "db-01.example.com"
            ]
        );
        assert!(NetworkDetector::dns_shaped_names("no dots here").is_empty());
    }

    #[test]
    fn ipv6_forms_are_whole_addresses() {
        for (input, expected) in [
            ("at 2001:db8::1 x", "at <IP> x"),
            ("at 2001:db8:85a3::8a2e:370:7334 x", "at <IP> x"),
            ("at fe80::1%eth0 x", "at <IP> x"),
            ("at ::1 x", "at <IP> x"),
            ("at 2001:db8::1: failed", "at <IP>: failed"),
            ("std::io::Error x", "std::io::Error x"),
            ("mac 00:11:22:33:44:55 x", "mac <MAC> x"),
            (
                "RSA 01:67:32:d9:b3:20:5d:2d:5f:b4:35:c5:a5:8b:0a:5e",
                "RSA 01:67:32:d9:b3:20:5d:2d:5f:b4:35:c5:a5:8b:0a:5e",
            ),
            ("to [::ffff:172.26.1.74]:60835 x", "to [<IP>]:<PORT> x"),
            ("to ::ffff:10.0.0.1 x", "to <IP> x"),
        ] {
            let (r, _) = NetworkDetector::detect_and_replace(input, true, true, false);
            assert_eq!(r, expected, "input: {input}");
        }
    }

    #[test]
    fn a_zero_led_dotted_quad_is_a_version() {
        let (r, t) = NetworkDetector::detect_and_replace(
            "package (0.8.10.3) at 0.0.0.0 and 10.0.0.1",
            true,
            false,
            false,
        );
        assert_eq!(r, "package (0.8.10.3) at <IP> and <IP>");
        assert_eq!(t.len(), 2);
    }
}

#[cfg(test)]
mod shapes_2026_08_29 {
    use super::*;

    #[test]
    fn every_source_extension_is_a_file_and_a_line() {
        for ext in crate::patterns::SOURCE_EXTENSIONS {
            let line = format!("panic at handler.{ext}:123 in worker");
            let (_, tokens) = NetworkDetector::detect_and_replace(&line, true, true, true);
            assert!(
                !tokens.iter().any(|t| matches!(t, Token::Port(_))),
                "{line}: {tokens:?}"
            );
            let site = format!("panic at handler.{ext}:123] in worker");
            let (r, _) = crate::patterns::path::PathDetector::detect_and_replace(&site);
            assert_eq!(r, format!("panic at handler.{ext}:<LINE>] in worker"));
        }
    }

    #[test]
    fn the_syslog_facility_level_is_not_a_domain() {
        for line in [
            "USWProHD24 syslog.info syslogd started",
            "USW16PoE daemon.err mcad: x",
            "x authpriv.notice y",
            "x local7.debug y",
        ] {
            let (r, t) = NetworkDetector::detect_and_replace(line, true, true, true);
            assert_eq!(r, line, "{line}");
            assert!(t.is_empty(), "{line}");
        }
        let (r, _) = NetworkDetector::detect_and_replace(
            "creating proc entry for system.info",
            true,
            true,
            true,
        );
        assert_eq!(
            r, "creating proc entry for system.info",
            "system.info is not facility.level, and still no host: no evidence"
        );
    }
}

#[cfg(test)]
mod network_boundaries {
    use super::*;

    fn net(line: &str) -> (String, Vec<Token>) {
        NetworkDetector::detect_and_replace(line, true, true, true)
    }

    fn has_ip(t: &[Token]) -> bool {
        t.iter()
            .any(|t| matches!(t, Token::IPv4(_) | Token::IPv6(_)))
    }

    fn has_port(t: &[Token]) -> bool {
        t.iter().any(|t| matches!(t, Token::Port(_)))
    }

    #[test]
    fn four_octets_ending_a_dotted_name_are_labels() {
        let (r, t) = net("a.12.51.100.77 done");
        assert_eq!(r, "a.12.51.100.77 done");
        assert!(!has_ip(&t), "{t:?}");
    }

    #[test]
    fn an_address_before_a_sentence_dot_is_an_address() {
        let (r, t) = net("peer 10.0.0.1. retry");
        assert_eq!(r, "peer <IP>. retry");
        assert!(has_ip(&t), "{t:?}");
    }

    #[test]
    fn an_address_with_a_trailing_dot_at_end_of_input_does_not_panic() {
        let (r, t) = net("peer 10.0.0.1.");
        assert_eq!(r, "peer <IP>.");
        assert!(has_ip(&t), "{t:?}");
    }

    #[test]
    fn a_keyed_name_glued_to_a_path_stays_literal() {
        let (r, t) = net("host=docker.io/library/nginx up");
        assert_eq!(r, "host=docker.io/library/nginx up");
        assert!(!t.iter().any(|t| matches!(t, Token::Fqdn(_))), "{t:?}");
    }

    #[test]
    fn a_keyed_name_continued_by_a_systemd_escape_stays_literal() {
        let (r, t) = net(r"host=kubernetes.io\x2dfoo up");
        assert_eq!(r, r"host=kubernetes.io\x2dfoo up");
        assert!(!t.iter().any(|t| matches!(t, Token::Fqdn(_))), "{t:?}");
    }

    #[test]
    fn an_ipv6_run_glued_to_letters_on_one_side_stays_literal() {
        for line in ["x2001:db8::1 up", "2001:db8::1x up"] {
            let (r, t) = net(line);
            assert_eq!(r, line);
            assert!(!has_ip(&t), "{line}: {t:?}");
        }
        let (r, t) = net("2001:db8::1 up");
        assert_eq!(r, "<IP> up", "the same run standing alone is one");
        assert!(has_ip(&t), "{t:?}");
    }

    #[test]
    fn a_port_shape_is_kept_literal_by_each_rejection_alone() {
        for (line, rejection) in [
            ("xlocalhost:80 ok", "glued to a letter before the match"),
            ("x_a.b:80 ok", "glued to an underscore"),
            (
                "a.b:12:zz ok",
                "a trailing colon makes a source line reference",
            ),
            ("ab:db.local:80 ok", "a hex pair before it is a colon chain"),
            ("main.go:12 ok", "a source file"),
        ] {
            let (r, t) = NetworkDetector::detect_and_replace(line, false, true, false);
            assert_eq!(r, line, "{rejection}");
            assert!(!has_port(&t), "{line}: {t:?}");
        }
        for (line, want) in [
            ("foo.bar:80 ok", "foo.bar:<PORT> ok"),
            ("localhost:80 ok", "localhost:<PORT> ok"),
        ] {
            let (r, t) = NetworkDetector::detect_and_replace(line, false, true, false);
            assert_eq!(r, want);
            assert!(has_port(&t), "{line}: {t:?}");
        }
    }

    #[test]
    fn a_mac_stays_literal_when_addresses_are_disabled() {
        let line = "link aa:bb:cc:dd:ee:ff example.com";
        let (r, t) = NetworkDetector::detect_and_replace(line, false, false, true);
        assert_eq!(
            r, line,
            "dotted text passes the name prefilter with addresses off"
        );
        assert!(!t.iter().any(|t| matches!(t, Token::Mac(_))), "{t:?}");
    }

    #[test]
    fn mac_boundaries_distinguish_hex_chains_from_sentence_colons() {
        for (line, expected) in [
            ("a:aa:bb:cc:dd:ee:ff", "a:aa:bb:cc:dd:ee:ff"),
            ("aa:bb:cc:dd:ee:ff:ab", "aa:bb:cc:dd:ee:ff:ab"),
            ("aa:bb:cc:dd:ee:ff:", "<MAC>:"),
            ("aa:bb:cc:dd:ee:ff:zz", "<MAC>:zz"),
        ] {
            let (result, tokens) = NetworkDetector::detect_and_replace(line, true, false, false);
            assert_eq!(result, expected, "{line}");
            assert_eq!(
                tokens.iter().any(|token| matches!(token, Token::Mac(_))),
                expected.contains("<MAC>"),
                "{line}: {tokens:?}"
            );
        }
    }

    #[test]
    fn a_name_before_a_lone_colon_at_end_of_input_does_not_panic() {
        let (r, t) =
            NetworkDetector::detect_and_replace("connect example.com:", false, false, true);
        assert_eq!(r, "connect example.com:");
        assert!(!t.iter().any(|t| matches!(t, Token::Fqdn(_))), "{t:?}");
    }

    #[test]
    fn a_name_with_no_preceding_key_stays_literal() {
        for line in ["example.com up", "=example.com up"] {
            let (r, t) = NetworkDetector::detect_and_replace(line, false, false, true);
            assert_eq!(r, line);
            assert!(!t.iter().any(|t| matches!(t, Token::Fqdn(_))), "{t:?}");
        }
    }
}
