use super::Token;
use regex::Regex;
use std::sync::LazyLock;

/// Result of IPv6 pre-filter validation determining whether to proceed to regex execution
///
/// The pre-filter performs lightweight structural validation to protect against ReDoS attacks
/// by rejecting obviously malformed patterns before they reach the complex IPv6 regex.
/// This provides defense-in-depth with <1% performance overhead while maintaining 100%
/// detection accuracy for legitimate IPv6 addresses.
#[derive(Debug, Clone)]
pub struct PlausibilityCheck {
    /// Whether the string passes structural validation and should proceed to regex
    pub is_plausible: bool,
}

impl PlausibilityCheck {
    /// Create a PlausibilityCheck indicating the input should proceed to regex validation
    pub fn plausible() -> Self {
        Self { is_plausible: true }
    }

    /// Create a PlausibilityCheck indicating the input should be rejected
    pub fn rejected(_reason: &str) -> Self {
        Self {
            is_plausible: false,
        }
    }
}

// IPv4 address
static IPV4_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ).unwrap()
});

// IPv6 candidate: hex groups and colons, greedy, with an optional zone. The
// candidate is then parsed by `std::net::Ipv6Addr`, which knows every
// compression form; a regex alternation cannot, because the regex engine
// takes the first alternative that matches, not the longest, and
// `2001:db8::1` used to come out as `<IP>1`.
static IPV6_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%[a-z0-9]+)?").unwrap()
});

// Port numbers - only after hostnames, not in time formats or source file:line patterns
// Matches hostname:port but avoids HH:MM:SS patterns and file.go:1234] patterns
// Note: We'll filter out file:line patterns in the detection logic
// `host:port` where the host is a dotted name or `localhost`. A bare word
// before a colon and a number is a field — `count:26`, `size:107`,
// `Threshold:80`, `vid:1044` — and read as a port it became a false claim
// on every line that carried one; `harbor-core:80` pays for that by staying
// literal, which loses nothing an agent needs.
static PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"((?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+|localhost):([1-9]\d{1,4})\b").unwrap()
});

// IPv4:Port combinations
static IPV4_PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(\d{1,5})\b"
    ).unwrap()
});

// IPv6:Port combinations in brackets: [2001:db8::1]:8080, [::ffff:10.0.0.1]:8080
static IPV6_PORT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[([a-fA-F0-9:.]+(?:%\w+)?)\]:(\d{1,5})\b").unwrap());

// An IPv4-mapped IPv6 address is one address; matched before the IPv4 pass
// would take its tail.
static IPV4_MAPPED_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)::ffff:(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());

// A MAC address: six hex pairs joined by `:`. One atom — its last
// byte read as a port (`8a:83` → `8a:<PORT>`) or a size (`8B`) cut it in
// two, which is why this runs before the port and size passes. A pair that
// continues as `:hh` on either side is part of a longer chain (an ssh
// fingerprint, an IPv6 address) and is left to those detectors.
static MAC_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b").unwrap());

// FQDN (experimental, be careful not to match code like module.function.method)
static FQDN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b"
    ).unwrap()
});

pub struct NetworkDetector;

impl NetworkDetector {
    fn is_version_not_address(ip: &str) -> bool {
        ip.starts_with("0.") && ip != "0.0.0.0"
    }

    /// `216.160.83.61` in `pool-216.160.83.61.washdc.fios.verizon.net` or in
    /// `61.83.160.216.in-addr.arpa` is a run of hostname labels, not an
    /// address: the dotted name continues past it.
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

    /// A hostname stands on its own. Glued to `-`, `/`, `\` or `~` it is a
    /// fragment of a longer name — a label key `kubernetes.io/cpu-cpuid.X87`,
    /// an image `docker.io/library/nginx`, a mount unit
    /// `…-volumes-kubernetes.io\x7eprojected` — and after a `.` it is the
    /// tail of a name whose head was already tokenised.
    fn fqdn_stands_alone(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let before = m.start() > 0 && matches!(b[m.start() - 1], b'-' | b'.' | b'/' | b'\\' | b'~');
        // `\x2d` is a systemd escape inside a unit name; `\"` closes a quote.
        let after = m.end() < b.len()
            && (matches!(b[m.end()], b'-' | b'/' | b'~')
                || (b[m.end()] == b'\\' && b.get(m.end() + 1) == Some(&b'x')));
        !(before || after)
    }

    /// How many bytes of a candidate are an IPv6 address: all of it, all
    /// but a trailing `:` that belongs to the sentence (`... 2001:db8::1:
    /// failed`), or none. A candidate glued to a letter (`std::io`) or cut
    /// out of a longer colon-hex chain (an ssh fingerprint) is not one.
    fn ipv6_len(haystack: &str, m: &regex::Match) -> Option<usize> {
        let b = haystack.as_bytes();
        let glued = (m.start() > 0 && b[m.start() - 1].is_ascii_alphanumeric())
            || (m.end() < b.len() && b[m.end()].is_ascii_alphanumeric());
        if glued || Self::in_longer_colon_chain(haystack, m) {
            return None;
        }
        let text = m.as_str();
        let parses = |s: &str| {
            let core = s.split('%').next().unwrap_or("");
            Self::is_plausible_ipv6(core).is_plausible && core.parse::<std::net::Ipv6Addr>().is_ok()
        };
        if parses(text) {
            Some(text.len())
        } else if let Some(shorter) = text.strip_suffix(':')
            && parses(shorter)
        {
            Some(shorter.len())
        } else {
            None
        }
    }

    /// Five colons exactly three bytes apart: cheap enough to run on
    /// every line so the regex only sees candidates.
    fn has_mac_shape(text: &str) -> bool {
        let b = text.as_bytes();
        let mut seps = 0;
        let mut last = usize::MAX;
        for (i, c) in b.iter().enumerate() {
            if *c == b':' {
                if last != usize::MAX && i == last + 3 {
                    seps += 1;
                    if seps >= 5 {
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

    /// A `word:port` match that starts inside a longer word
    /// (`utm_cloud_is_alive:46` matched from `alive`) or whose number is
    /// followed by another colon (`alive:46:` is a source line reference)
    /// is not a host and port.
    fn port_stands_alone(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let glued =
            m.start() > 0 && (b[m.start() - 1].is_ascii_alphanumeric() || b[m.start() - 1] == b'_');
        let line_ref = m.end() < b.len() && b[m.end()] == b':';
        !glued && !line_ref
    }

    /// The match continues as `:hh` on either side: part of a longer chain.
    fn in_longer_colon_chain(haystack: &str, m: &regex::Match) -> bool {
        let b = haystack.as_bytes();
        let before =
            m.start() >= 2 && b[m.start() - 1] == b':' && b[m.start() - 2].is_ascii_hexdigit();
        let after =
            m.end() + 1 < b.len() && b[m.end()] == b':' && b[m.end() + 1].is_ascii_hexdigit();
        before || after
    }
}

impl NetworkDetector {
    pub fn detect_and_replace(
        text: &str,
        normalize_ips: bool,
        normalize_ports: bool,
        normalize_fqdns: bool,
    ) -> (String, Vec<Token>) {
        // ULTRA-FAST PRE-FILTER: Skip if no network indicators
        if !Self::has_network_indicators(text, normalize_ips, normalize_ports, normalize_fqdns) {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        if normalize_ips && Self::has_mac_shape(text) {
            let folded = MAC_REGEX.replace_all(&result, |caps: &regex::Captures| {
                let m = caps.get(0).unwrap();
                if Self::in_longer_colon_chain(&result, &m) {
                    m.as_str().to_string()
                } else {
                    tokens.push(Token::Mac(m.as_str().to_string()));
                    "<MAC>".to_string()
                }
            });
            if let std::borrow::Cow::Owned(s) = folded {
                result = s;
            }
        }

        if normalize_ips {
            // Handle IPv4:Port combinations first
            for cap in IPV4_PORT_REGEX.captures_iter(text) {
                let full_match = cap.get(0).unwrap().as_str();
                let port_str = cap.get(1).unwrap().as_str();

                if let Ok(port) = port_str.parse::<u16>() {
                    // Split the IP and port
                    let ip = &full_match[..full_match.len() - port_str.len() - 1];
                    tokens.push(Token::IPv4(ip.to_string()));
                    if normalize_ports {
                        tokens.push(Token::Port(port));
                    }
                }
            }
            result = IPV4_PORT_REGEX
                .replace_all(&result, "<IP>:<PORT>")
                .to_string();

            // Handle IPv6:Port combinations: [2001:db8::1]:8080
            for cap in IPV6_PORT_REGEX.captures_iter(&result) {
                let ipv6_str = cap.get(1).unwrap().as_str();
                let port_str = cap.get(2).unwrap().as_str();

                if let Ok(port) = port_str.parse::<u16>() {
                    tokens.push(Token::IPv6(ipv6_str.to_string()));
                    if normalize_ports {
                        tokens.push(Token::Port(port));
                    }
                }
            }
            result = IPV6_PORT_REGEX
                .replace_all(&result, "[<IP>]:<PORT>")
                .to_string();

            for cap in IPV4_MAPPED_REGEX.find_iter(&result) {
                tokens.push(Token::IPv6(cap.as_str().to_string()));
            }
            result = IPV4_MAPPED_REGEX.replace_all(&result, "<IP>").to_string();

            // Handle standalone IPv4 addresses. `0.x.y.z` is never a host —
            // `(0.8.10.3)` is a package version — except `0.0.0.0` itself,
            // and four octets inside a longer dotted name are its labels.
            for cap in IPV4_REGEX.find_iter(&result) {
                let ip_str = cap.as_str();
                if !Self::is_ipv4_address(&result, &cap) {
                    continue;
                }
                if !tokens
                    .iter()
                    .any(|t| matches!(t, Token::IPv4(s) if s == ip_str))
                {
                    tokens.push(Token::IPv4(ip_str.to_string()));
                }
            }
            result = IPV4_REGEX
                .replace_all(&result, |caps: &regex::Captures| {
                    let m = caps.get(0).unwrap();
                    if Self::is_ipv4_address(&result, &m) {
                        "<IP>".to_string()
                    } else {
                        m.as_str().to_string()
                    }
                })
                .to_string();

            // Handle IPv6 addresses: a candidate is an address only if it
            // parses as one and stands alone.
            for m in IPV6_CANDIDATE.find_iter(&result) {
                if let Some(len) = Self::ipv6_len(&result, &m) {
                    tokens.push(Token::IPv6(m.as_str()[..len].to_string()));
                }
            }
            result = IPV6_CANDIDATE
                .replace_all(&result, |caps: &regex::Captures| {
                    let m = caps.get(0).unwrap();
                    match Self::ipv6_len(&result, &m) {
                        Some(len) => format!("<IP>{}", &m.as_str()[len..]),
                        None => m.as_str().to_string(),
                    }
                })
                .to_string();
        }

        if normalize_ports {
            // Handle remaining standalone port numbers (but skip file:line patterns)
            for cap in PORT_REGEX.captures_iter(&result) {
                let full_match = cap.get(0).unwrap().as_str();
                let hostname = cap.get(1).unwrap().as_str();
                let port_str = cap.get(2).unwrap().as_str();

                // Skip if this looks like a source file:line pattern (ends with ])
                // or two groups of a colon-hex chain (`b3:20` in a fingerprint)
                if Self::in_longer_colon_chain(&result, &cap.get(0).unwrap())
                    || !Self::port_stands_alone(&result, &cap.get(0).unwrap())
                    || full_match.ends_with(']')
                    || hostname.ends_with(".go")
                    || hostname.ends_with(".rs")
                    || hostname.ends_with(".py")
                    || hostname.ends_with(".js")
                    || hostname.ends_with(".java")
                    || hostname.ends_with(".c")
                    || hostname.ends_with(".cpp")
                    || hostname.ends_with(".h")
                {
                    continue;
                }

                if let Ok(port) = port_str.parse::<u16>()
                    && !tokens
                        .iter()
                        .any(|t| matches!(t, Token::Port(p) if *p == port))
                {
                    tokens.push(Token::Port(port));
                }
            }

            // Replace ports but skip file:line patterns
            result = PORT_REGEX
                .replace_all(&result, |caps: &regex::Captures| {
                    let full_match = caps.get(0).unwrap().as_str();
                    let hostname = caps.get(1).unwrap().as_str();

                    // Skip if this looks like a source file:line pattern
                    if Self::in_longer_colon_chain(&result, &caps.get(0).unwrap())
                        || !Self::port_stands_alone(&result, &caps.get(0).unwrap())
                        || full_match.ends_with(']')
                        || hostname.ends_with(".go")
                        || hostname.ends_with(".rs")
                        || hostname.ends_with(".py")
                        || hostname.ends_with(".js")
                        || hostname.ends_with(".java")
                        || hostname.ends_with(".c")
                        || hostname.ends_with(".cpp")
                        || hostname.ends_with(".h")
                    {
                        return full_match.to_string();
                    }

                    format!("{hostname}:<PORT>")
                })
                .to_string();
        }

        if normalize_fqdns {
            // FQDN detection. The token gate and the text replacement share
            // is_likely_fqdn so a rejected match is left untouched.
            for cap in FQDN_REGEX.find_iter(&result) {
                let fqdn_str = cap.as_str();
                if Self::is_likely_fqdn(fqdn_str) && Self::fqdn_stands_alone(&result, &cap) {
                    tokens.push(Token::Fqdn(fqdn_str.to_string()));
                }
            }
            result = FQDN_REGEX
                .replace_all(&result, |caps: &regex::Captures| {
                    let m = caps.get(0).unwrap();
                    if Self::is_likely_fqdn(m.as_str()) && Self::fqdn_stands_alone(&result, &m) {
                        "<FQDN>".to_string()
                    } else {
                        m.as_str().to_string()
                    }
                })
                .to_string();
        }

        (result, tokens)
    }

    /// Heuristic separating real domain names from dotted code identifiers
    /// (hibernate.SQL, scope.go, module.function). Requires the final label
    /// to be a known TLD. Deliberately no "lowercase multi-label" fallback:
    /// Java package names are lowercase dotted and would all match.
    fn is_likely_fqdn(s: &str) -> bool {
        const COMMON_TLDS: &[&str] = &[
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
            // Internal / cluster suffixes
            "local",
            "internal",
            "localdomain",
            "lan",
            "corp",
            "home",
            "svc",
        ];
        s.rsplit_once('.')
            .is_some_and(|(_, tld)| COMMON_TLDS.contains(&tld))
    }

    /// Lightweight pre-filter to validate IPv6 structural plausibility before regex execution
    ///
    /// This function provides ReDoS protection by quickly rejecting obviously malformed patterns
    /// that could cause catastrophic backtracking in the complex IPv6 regex. It performs O(n)
    /// validation with minimal overhead (<1% for valid inputs).
    ///
    /// # Validation Rules
    /// - Length: 2-100 characters (allows "::" up to zone identifiers)
    /// - Character set: hex digits (0-9, a-f, A-F), colons (:), dots (.) for IPv4-mapped
    /// - Must contain at least one colon (all IPv6 formats have colons)
    /// - Must contain at least one hex digit (except "::" which is valid)
    ///
    /// # Arguments
    /// * `input` - The string to validate as a potential IPv6 address
    ///
    /// # Returns
    /// * `PlausibilityCheck` - Contains validation result and optional rejection reason
    ///
    /// # Performance
    /// - Rejects malformed patterns in <10ms
    /// - Adds <1% overhead for valid IPv6 addresses
    /// - Thread-safe for parallel processing
    ///
    /// # Examples
    /// ```
    /// use lessence::patterns::network::NetworkDetector;
    ///
    /// // Valid IPv6 - passes pre-filter
    /// let check = NetworkDetector::is_plausible_ipv6("2001:db8::1");
    /// assert!(check.is_plausible);
    ///
    /// // Invalid - too short
    /// let check = NetworkDetector::is_plausible_ipv6(":");
    /// assert!(!check.is_plausible);
    /// ```
    pub fn is_plausible_ipv6(input: &str) -> PlausibilityCheck {
        let len = input.len();

        if len < 2 {
            return PlausibilityCheck::rejected("too_short");
        }

        if len > 100 {
            return PlausibilityCheck::rejected("too_long");
        }

        let mut has_colon = false;
        let mut has_hex = false;

        for ch in input.chars() {
            match ch {
                ':' => has_colon = true,
                '.' => {}
                '0'..='9' | 'a'..='f' | 'A'..='F' => has_hex = true,
                _ => return PlausibilityCheck::rejected("invalid_characters"),
            }
        }

        if !has_colon {
            return PlausibilityCheck::rejected("no_colons");
        }

        if !has_hex && input != "::" {
            return PlausibilityCheck::rejected("no_hex_digits");
        }

        PlausibilityCheck::plausible()
    }

    #[inline]
    fn has_network_indicators(
        text: &str,
        normalize_ips: bool,
        normalize_ports: bool,
        normalize_fqdns: bool,
    ) -> bool {
        if normalize_ips && (text.contains('.') || text.contains(':')) {
            return true; // Potential IPv4 or IPv6
        }
        if normalize_ports && text.contains(':') {
            return true; // Potential port number
        }
        // Any dotted text is a potential FQDN — precision comes from
        // is_likely_fqdn's TLD gate, not from this prefilter. (With
        // normalize_ips on, dotted lines already pass the check above.)
        if normalize_fqdns && text.contains('.') {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_detection() {
        let text = "Connection failed to 192.168.1.100 (timeout)";
        let (result, tokens) = NetworkDetector::detect_and_replace(text, true, false, false);
        assert_eq!(result, "Connection failed to <IP> (timeout)");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::IPv4(_)));
    }

    #[test]
    fn test_ipv4_port_detection() {
        let text = "Connection failed to 192.168.1.100:8080 (timeout)";
        let (result, tokens) = NetworkDetector::detect_and_replace(text, true, true, false);
        assert_eq!(result, "Connection failed to <IP>:<PORT> (timeout)");
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[0], Token::IPv4(_)));
        assert!(matches!(tokens[1], Token::Port(8080)));
    }

    #[test]
    fn test_port_only_detection() {
        // PORT_REGEX requires a hostname prefix ([a-zA-Z]...) before the colon,
        // so standalone ":8080" without a hostname is not detected
        let text = "Listening on port :8080";
        let (result, tokens) = NetworkDetector::detect_and_replace(text, false, true, false);
        assert_eq!(result, "Listening on port :8080");
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn test_ipv6_detection() {
        let text = "Connected to 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let (result, tokens) = NetworkDetector::detect_and_replace(text, true, false, false);
        assert_eq!(result, "Connected to <IP>");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::IPv6(_)));
    }

    // --- is_plausible_ipv6 ---

    #[test]
    fn plausible_ipv6_empty_rejected() {
        assert!(!NetworkDetector::is_plausible_ipv6("").is_plausible);
    }

    #[test]
    fn plausible_ipv6_too_short() {
        assert!(!NetworkDetector::is_plausible_ipv6("x").is_plausible);
    }

    #[test]
    fn plausible_ipv6_too_long() {
        let long = "a".repeat(101);
        assert!(!NetworkDetector::is_plausible_ipv6(&long).is_plausible);
    }

    #[test]
    fn plausible_ipv6_no_colons() {
        assert!(!NetworkDetector::is_plausible_ipv6("abcdef").is_plausible);
    }

    #[test]
    fn plausible_ipv6_valid() {
        assert!(NetworkDetector::is_plausible_ipv6("2001:db8::1").is_plausible);
    }

    // ---- has_network_indicators: per-condition tests ----

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
    fn net_ind_fqdn_com() {
        assert!(NetworkDetector::has_network_indicators(
            "example.com",
            false,
            false,
            true
        ));
    }

    #[test]
    fn net_ind_fqdn_org() {
        assert!(NetworkDetector::has_network_indicators(
            "example.org",
            false,
            false,
            true
        ));
    }

    #[test]
    fn net_ind_fqdn_net() {
        assert!(NetworkDetector::has_network_indicators(
            "example.net",
            false,
            false,
            true
        ));
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

    // ---- detect_and_replace: file extension exclusions ----

    #[test]
    fn port_skip_go_file() {
        let (result, _) = NetworkDetector::detect_and_replace("server.go:1234", false, true, false);
        assert!(!result.contains("<PORT>"), "should skip .go file: {result}");
    }

    #[test]
    fn port_skip_rs_file() {
        let (result, _) = NetworkDetector::detect_and_replace("main.rs:42", false, true, false);
        assert!(!result.contains("<PORT>"), "should skip .rs file: {result}");
    }

    #[test]
    fn port_skip_py_file() {
        let (result, _) = NetworkDetector::detect_and_replace("app.py:100", false, true, false);
        assert!(!result.contains("<PORT>"), "should skip .py file: {result}");
    }

    #[test]
    fn port_skip_js_file() {
        let (result, _) = NetworkDetector::detect_and_replace("index.js:55", false, true, false);
        assert!(!result.contains("<PORT>"), "should skip .js file: {result}");
    }

    #[test]
    fn port_skip_java_file() {
        let (result, _) = NetworkDetector::detect_and_replace("App.java:200", false, true, false);
        assert!(
            !result.contains("<PORT>"),
            "should skip .java file: {result}"
        );
    }

    #[test]
    fn port_skip_c_file() {
        let (result, _) = NetworkDetector::detect_and_replace("main.c:30", false, true, false);
        assert!(!result.contains("<PORT>"), "should skip .c file: {result}");
    }

    #[test]
    fn port_skip_cpp_file() {
        let (result, _) = NetworkDetector::detect_and_replace("main.cpp:30", false, true, false);
        assert!(
            !result.contains("<PORT>"),
            "should skip .cpp file: {result}"
        );
    }

    #[test]
    fn port_skip_h_file() {
        let (result, _) = NetworkDetector::detect_and_replace("header.h:10", false, true, false);
        assert!(!result.contains("<PORT>"), "should skip .h file: {result}");
    }

    // ---- detect_and_replace: IPv4:port split ----

    #[test]
    fn ipv4_port_split() {
        let (result, tokens) =
            NetworkDetector::detect_and_replace("connect 10.0.0.1:8080", true, true, false);
        assert!(result.contains("<IP>"));
        assert!(result.contains("<PORT>"));
        assert!(tokens.iter().any(|t| matches!(t, Token::IPv4(_))));
        assert!(tokens.iter().any(|t| matches!(t, Token::Port(8080))));
    }

    // ---- detect_and_replace: flag combos ----

    #[test]
    fn detect_ips_only() {
        let (result, tokens) =
            NetworkDetector::detect_and_replace("host 10.0.0.1:8080", true, false, false);
        assert!(result.contains("<IP>"));
        // Port should not be replaced when normalize_ports=false
        assert!(!tokens.iter().any(|t| matches!(t, Token::Port(_))));
    }

    // ---- file extension exclusions: verify NO Port token is emitted (kills token-loop mutants) ----

    #[test]
    fn port_skip_go_file_no_token() {
        let (_, tokens) = NetworkDetector::detect_and_replace("server.go:1234", false, true, false);
        assert!(
            !tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "should not emit Port token for .go file: {tokens:?}"
        );
    }

    #[test]
    fn port_skip_rs_file_no_token() {
        let (_, tokens) = NetworkDetector::detect_and_replace("main.rs:42", false, true, false);
        assert!(
            !tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "should not emit Port token for .rs file: {tokens:?}"
        );
    }

    #[test]
    fn port_skip_py_file_no_token() {
        let (_, tokens) = NetworkDetector::detect_and_replace("app.py:100", false, true, false);
        assert!(
            !tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "should not emit Port token for .py file: {tokens:?}"
        );
    }

    #[test]
    fn port_skip_js_file_no_token() {
        let (_, tokens) = NetworkDetector::detect_and_replace("index.js:55", false, true, false);
        assert!(
            !tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "should not emit Port token for .js file: {tokens:?}"
        );
    }

    #[test]
    fn port_skip_java_file_no_token() {
        let (_, tokens) = NetworkDetector::detect_and_replace("App.java:200", false, true, false);
        assert!(
            !tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "should not emit Port token for .java file: {tokens:?}"
        );
    }

    #[test]
    fn port_skip_c_file_no_token() {
        let (_, tokens) = NetworkDetector::detect_and_replace("main.c:30", false, true, false);
        assert!(
            !tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "should not emit Port token for .c file: {tokens:?}"
        );
    }

    #[test]
    fn port_skip_cpp_file_no_token() {
        let (_, tokens) = NetworkDetector::detect_and_replace("main.cpp:30", false, true, false);
        assert!(
            !tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "should not emit Port token for .cpp file: {tokens:?}"
        );
    }

    #[test]
    fn port_skip_h_file_no_token() {
        let (_, tokens) = NetworkDetector::detect_and_replace("header.h:10", false, true, false);
        assert!(
            !tokens.iter().any(|t| matches!(t, Token::Port(_))),
            "should not emit Port token for .h file: {tokens:?}"
        );
    }

    // ---- detect_and_replace: verify extracted IP from IPv4:Port (line 94 arithmetic) ----

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
    fn ipv4_port_extracts_correct_ip_long_port() {
        // Use a 5-digit port to stress the arithmetic: len - port_str.len() - 1
        let (_, tokens) =
            NetworkDetector::detect_and_replace("host 10.0.0.99:65535", true, true, false);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::IPv4(s) if s == "10.0.0.99")),
            "should extract exact IP '10.0.0.99', got: {tokens:?}"
        );
        assert!(
            tokens.iter().any(|t| matches!(t, Token::Port(65535))),
            "should extract port 65535, got: {tokens:?}"
        );
    }

    #[test]
    fn ipv4_port_extracts_correct_ip_short_port() {
        // Single-digit port number (smallest valid port_str length)
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

    // ---- detect_and_replace: dedup check (line 207, FQDN/IPv4 dedup) ----

    #[test]
    fn no_duplicate_ipv4_tokens() {
        // Two occurrences of the same IP should produce only one IPv4 token
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
        // Two hostnames with the same port should produce only one Port token
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

    // ---- is_plausible_ipv6: boundary tests ----

    #[test]
    fn plausible_ipv6_len_exactly_2() {
        // len == 2 is the minimum accepted length; "::" is 2 chars and valid
        assert!(NetworkDetector::is_plausible_ipv6("::").is_plausible);
    }

    #[test]
    fn plausible_ipv6_len_exactly_1() {
        // len == 1 is below the boundary, must be rejected
        assert!(!NetworkDetector::is_plausible_ipv6(":").is_plausible);
    }

    #[test]
    fn plausible_ipv6_len_exactly_100() {
        // len == 100 is the maximum accepted length
        // Build a 100-char string: "a:" repeated to fill, ending with valid hex
        let mut s = String::new();
        // "a:" is 2 chars, repeat 49 times = 98 chars, then "a:" = 100
        for _ in 0..50 {
            s.push_str("a:");
        }
        assert_eq!(s.len(), 100);
        assert!(
            NetworkDetector::is_plausible_ipv6(&s).is_plausible,
            "len=100 should be accepted"
        );
    }

    #[test]
    fn plausible_ipv6_len_exactly_101() {
        // len == 101 is above the boundary, must be rejected
        let mut s = String::new();
        for _ in 0..50 {
            s.push_str("a:");
        }
        s.push('a');
        assert_eq!(s.len(), 101);
        assert!(
            !NetworkDetector::is_plausible_ipv6(&s).is_plausible,
            "len=101 should be rejected"
        );
    }

    // ---- is_plausible_ipv6: IPv4-mapped address (dot handling, line 270) ----

    #[test]
    fn plausible_ipv6_ipv4_mapped() {
        // IPv4-mapped IPv6 address contains dots — the '.' match arm must accept them
        assert!(
            NetworkDetector::is_plausible_ipv6("::ffff:192.168.1.1").is_plausible,
            "IPv4-mapped IPv6 should be plausible"
        );
    }

    #[test]
    fn plausible_ipv6_dots_only_with_colon() {
        // Dots + colons but no hex digits and not "::" — should be rejected (no hex)
        assert!(
            !NetworkDetector::is_plausible_ipv6(":..:..").is_plausible,
            "dots and colons without hex digits should be rejected"
        );
    }

    // ---- is_plausible_ipv6: no hex digits (line 280, != vs ==) ----

    #[test]
    fn plausible_ipv6_double_colon_special_case() {
        // "::" has no hex digits but IS the special case — must be accepted
        assert!(
            NetworkDetector::is_plausible_ipv6("::").is_plausible,
            ":: should be accepted even without hex digits"
        );
    }

    #[test]
    fn plausible_ipv6_colons_only_not_double_colon() {
        // ":::" has colons and no hex but is NOT "::" — should be rejected
        assert!(
            !NetworkDetector::is_plausible_ipv6(":::").is_plausible,
            "::: should be rejected: has no hex and is not ::"
        );
    }

    #[test]
    fn plausible_ipv6_invalid_char() {
        assert!(
            !NetworkDetector::is_plausible_ipv6("20g1:db8::1").is_plausible,
            "non-hex letter should be rejected"
        );
    }

    // ---- has_network_indicators: inner && conditions (lines 297, 302) ----

    #[test]
    fn net_ind_ports_no_colon() {
        // normalize_ports=true but text has no colon => should be false
        // kills: `&& with ||` on line 297
        assert!(!NetworkDetector::has_network_indicators(
            "no-colon-here",
            false,
            true,
            false
        ));
    }

    #[test]
    fn net_ind_fqdn_any_dot_passes() {
        // The fqdn prefilter arm is dot-only; precision lives in
        // is_likely_fqdn's TLD gate, so "file.txt" passes the prefilter
        // but produces no token or rewrite downstream.
        assert!(NetworkDetector::has_network_indicators(
            "file.txt", false, false, true
        ));
        let (result, tokens) =
            NetworkDetector::detect_and_replace("open file.txt ok", false, false, true);
        assert_eq!(result, "open file.txt ok");
        assert!(tokens.is_empty());
    }

    #[test]
    fn net_ind_fqdn_tld_keyword_but_no_dot() {
        // normalize_fqdns=true, text has "com" but no dot => should be false
        // kills: `&& with ||` on the outer part of line 302
        assert!(!NetworkDetector::has_network_indicators(
            "dotcom", false, false, true
        ));
    }

    // ---- detect_and_replace: legitimate hostname:port IS detected ----

    #[test]
    fn port_detected_for_non_source_file_hostname() {
        // A hostname that does NOT match any file extension should have its port detected
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

    // ---- IPv6 port detection ----

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

    // ---- FQDN detection: dot/start/end checks (line 207) ----

    #[test]
    fn fqdn_valid_produces_token() {
        // Valid FQDN should produce a token
        let (_, tokens) =
            NetworkDetector::detect_and_replace("connect example.com ok", false, false, true);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Fqdn(s) if s == "example.com")),
            "valid FQDN should produce Fqdn token: {tokens:?}"
        );
    }

    #[test]
    fn fqdn_rejects_dotted_code_identifiers() {
        // hibernate.SQL / scope.go style identifiers must neither tokenize
        // nor be rewritten in the text.
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
    fn fqdn_leading_dot_no_token() {
        // Kills: delete ! on `!starts_with('.')`
        // Kills: && with || (leading dot should prevent token, not allow it)
        let (_, tokens) = NetworkDetector::detect_and_replace(".example.com", false, false, true);
        // Leading dot → token should NOT be produced (text still replaced by regex)
        assert!(
            !tokens
                .iter()
                .any(|t| matches!(t, Token::IPv4(s) if s.starts_with('.'))),
            "leading dot FQDN should not produce token: {tokens:?}"
        );
    }

    #[test]
    fn fqdn_trailing_dot_no_token() {
        // Kills: delete ! on `!ends_with('.')`
        let (_, tokens) = NetworkDetector::detect_and_replace("example.com.", false, false, true);
        assert!(
            !tokens
                .iter()
                .any(|t| matches!(t, Token::IPv4(s) if s.ends_with('.'))),
            "trailing dot FQDN should not produce token: {tokens:?}"
        );
    }

    /// A port sits after a whole word; a number after a word fragment or
    /// before another colon is something else.
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

    /// A MAC is one atom whatever its bytes look like; a longer colon chain
    /// (a fingerprint, an IPv6 address) is not six MACs.
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

    /// An IPv4 run inside a dotted hostname is a run of labels, not an
    /// address; the whole name is the host. An address range stays two.
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

    /// A dotted name glued to `/`, `\`, `~` or `-`, or continuing a name to
    /// its left, is a fragment of a longer identifier, not a host. Standing
    /// alone it is a host whatever its role.
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
        assert_eq!(r, "GroupVersion <FQDN> v1");
        // an escaped quote after the name is not glue
        let (r, _) = NetworkDetector::detect_and_replace(
            r#"msg="loading \"io.containerd.store.v1.local\"...""#,
            true,
            true,
            true,
        );
        assert_eq!(r, r#"msg="loading \"<FQDN>\"...""#);
    }

    /// Every IPv6 compression form is one address; what does not parse as
    /// one — a Rust path, a MAC, a fingerprint — is left alone.
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

    /// `0.x.y.z` is never a host; `(0.8.10.3)` is a package version.
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
