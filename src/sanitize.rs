use crate::anonymize::at_token_boundary;
use crate::config::{Config, PATTERN_REGISTRY};
use crate::normalize::Normalizer;
use crate::patterns::Token;
use crate::patterns::email::EmailPatternDetector;
use crate::patterns::network::NetworkDetector;
use hmac::{Hmac, KeyInit, Mac};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::ops::Range;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Redact,
    KeyedPseudonym,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Entity {
    Email,
    Credential,
    Host,
    Ip,
}

impl Entity {
    const ALL: [Entity; 4] = [Entity::Email, Entity::Credential, Entity::Host, Entity::Ip];

    fn name(self) -> &'static str {
        match self {
            Entity::Email => "email",
            Entity::Credential => "credential",
            Entity::Host => "host",
            Entity::Ip => "ip",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Entity::ALL.into_iter().find(|e| e.name() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sanitizer {
    actions: [Option<Action>; 4],
    key: Option<PseudonymKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PseudonymKey([u8; 32]);

const TAG_BITS: usize = 64;

type HmacSha256 = Hmac<Sha256>;

pub(crate) static CREDENTIAL_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|master[_-]?key|access[_-]?key)"?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)"#,
    )
    .expect("static regex")
});

/// JSON Web Token: three base64url segments, the first always `eyJ`
/// (base64 of `{"`). Catches both `Bearer eyJ...` headers and bare JWTs.
pub(crate) static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").expect("static regex")
});

/// Provider-prefixed API keys: `sk-` (OpenAI/Stripe style), `ghp_`/`gho_`/
/// `ghu_`/`ghs_`/`ghr_` (GitHub), `xox?-` (Slack). The length floor keeps
/// hyphenated prose like `sk-learn` unmasked.
pub(crate) static PROVIDER_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|xox[a-z]-[A-Za-z0-9-]{8,})")
        .expect("static regex")
});

/// The credentials of an HTTP `Authorization` / `Proxy-Authorization`
/// header (`auth-scheme credentials`, RFC 9110 §11.6.2) and an RFC 6750
/// `Bearer` token wherever it stands. The header name and the scheme stay;
/// the capture is the credentials, in the `token68` alphabet.
pub(crate) static AUTHORIZATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:\b(?:proxy-)?authorization"?\s*[=:]\s*"?(?:[a-z][a-z0-9_-]*\s+)?|\bbearer\s+)([A-Za-z0-9._~+/-]+=*)"#,
    )
    .expect("static regex")
});

/// The password of URL userinfo, `scheme://user:password@host` (RFC 3986
/// §3.2.1). The scheme, the user and the host stay; the capture runs to the
/// last `@` of the authority, so an unencoded `@` in the password is inside
/// it.
pub(crate) static URL_USERINFO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/?#@:"'<>]*:([^\s/?#"'<>\\]+)@"#)
        .expect("static regex")
});

pub(crate) fn authorization_credential_spans(text: &str) -> Vec<Range<usize>> {
    capture_spans(&AUTHORIZATION, text)
}

pub(crate) fn userinfo_password_spans(text: &str) -> Vec<Range<usize>> {
    capture_spans(&URL_USERINFO, text)
}

fn capture_spans(re: &Regex, text: &str) -> Vec<Range<usize>> {
    re.captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.range()))
        .collect()
}

static EMAILS: LazyLock<EmailPatternDetector> =
    LazyLock::new(|| EmailPatternDetector::new().expect("static regex"));

static SYSLOG_HOST_PLACER: LazyLock<Normalizer> = LazyLock::new(|| {
    let mut config = Config::default();
    for entry in PATTERN_REGISTRY {
        let wanted = matches!(entry.name, "timestamp" | "process" | "network");
        config.set_pattern_enabled(entry.name, wanted);
    }
    Normalizer::new(config)
});

pub(crate) fn scanned_entities_without_syslog_host(
    text: &str,
    email: bool,
    ip: bool,
    host: bool,
) -> Vec<Token> {
    let mut tokens = Vec::new();
    if email && text.contains('@') {
        tokens.extend(EMAILS.detect_and_replace(text).1);
    }
    if ip || host {
        tokens.extend(NetworkDetector::detect_and_replace(text, ip, false, host).1);
    }
    tokens
}

pub const KEY_ENV: &str = "LESSENCE_SANITIZE_KEY";

static RUN_KEY: LazyLock<PseudonymKey> = LazyLock::new(|| {
    let mut key = [0u8; 32];
    if getrandom::fill(&mut key).is_err() {
        use std::hash::BuildHasher;
        let state = std::collections::hash_map::RandomState::new();
        let seed = [state.hash_one(0u8), state.hash_one(1u8)];
        return Sanitizer::derive_key(&[seed[0].to_le_bytes(), seed[1].to_le_bytes()].concat());
    }
    PseudonymKey(key)
});

pub struct MaskedLine {
    pub shown: String,
    pub normalizable: String,
    pub tokens: Vec<Token>,
}

impl Sanitizer {
    pub fn pii_alias() -> Self {
        Self {
            actions: [Some(Action::Redact), Some(Action::Redact), None, None],
            key: None,
        }
    }

    fn from_actions_or_refuse_without_entropy(
        actions: [Option<Action>; 4],
    ) -> Result<Self, String> {
        let key = if actions.contains(&Some(Action::KeyedPseudonym)) {
            Some(Self::pseudonym_key_from_env_or_os()?)
        } else {
            None
        };
        Ok(Self { actions, key })
    }

    fn pseudonym_key_from_env_or_os() -> Result<PseudonymKey, String> {
        match std::env::var(KEY_ENV) {
            Ok(k) if !k.is_empty() => Ok(Self::derive_key(k.as_bytes())),
            _ => {
                let mut key = [0u8; 32];
                getrandom::fill(&mut key).map_err(|e| {
                    format!(
                        "cannot draw a pseudonym key from the operating system ({e}); set {KEY_ENV}"
                    )
                })?;
                Ok(PseudonymKey(key))
            }
        }
    }

    fn derive_key(bytes: &[u8]) -> PseudonymKey {
        PseudonymKey(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub fn with_test_key(mut self, key: u64) -> Self {
        self.key = Some(Self::derive_key(&key.to_le_bytes()));
        self
    }

    pub fn parse(specs: &[String], legacy_pii: bool) -> Result<Option<Self>, String> {
        let mut actions: [Option<Action>; 4] = if legacy_pii {
            Self::pii_alias().actions
        } else {
            [None; 4]
        };
        for spec in specs.iter().flat_map(|s| s.split(',')) {
            let spec = spec.trim();
            if spec.is_empty() {
                continue;
            }
            let (entity, action) = match spec.split_once(':') {
                Some((e, a)) => (e.trim(), a.trim()),
                None => (spec, "redact"),
            };
            let Some(entity) = Entity::parse(entity) else {
                return Err(format!(
                    "unknown sanitize entity `{entity}` (expected one of: email, credential, host, ip)"
                ));
            };
            let action = match action {
                "redact" => Action::Redact,
                "pseudonym" => Action::KeyedPseudonym,
                other => {
                    return Err(format!(
                        "unknown sanitize action `{other}` for `{}` (expected redact or pseudonym)",
                        entity.name()
                    ));
                }
            };
            last_action_wins(&mut actions, entity, action);
        }
        let nothing_enabled = actions.iter().all(Option::is_none);
        if nothing_enabled {
            return Ok(None);
        }
        Self::from_actions_or_refuse_without_entropy(actions).map(Some)
    }

    fn action(&self, entity: Entity) -> Option<Action> {
        self.actions[entity as usize]
    }

    fn tag(&self, entity: Entity, class: &str, value: &str) -> String {
        match self.action(entity) {
            Some(Action::KeyedPseudonym) => {
                let key = self
                    .key
                    .as_ref()
                    .expect("a pseudonym action always carries a key");
                format!("<{class}:{}>", keyed_tag64(key, value))
            }
            _ => format!("<{class}>"),
        }
    }

    pub fn mask_line(&self, original: &str, hints: &[Token]) -> String {
        self.mask(original, hints)
    }

    pub fn mask_text(&self, text: &str) -> String {
        self.mask(text, &[])
    }

    fn mask(&self, text: &str, hints: &[Token]) -> String {
        let regions = self.regions(text, hints);
        if regions.is_empty() {
            return text.to_string();
        }
        render(text, &regions)
    }

    pub fn mask_for_folding(&self, line: &str, hints: &[Token]) -> Option<MaskedLine> {
        let regions = self.regions(line, hints);
        if regions.is_empty() {
            return None;
        }
        let tokens = regions
            .in_text_order()
            .iter()
            .filter_map(|r| {
                let kind = r.kind?;
                Some(kind.token(self.token_value(r, &line[r.start..r.end])))
            })
            .collect();
        Some(MaskedLine {
            shown: render_with(line, &regions, |out, r| out.push_str(&r.tag)),
            normalizable: render_with(line, &regions, |out, r| {
                out.push('<');
                out.push_str(r.class);
                out.push('>');
            }),
            tokens,
        })
    }

    fn token_value(&self, region: &Region, value: &str) -> String {
        match self.action(region.entity) {
            Some(Action::KeyedPseudonym) => region.tag.clone(),
            _ => format!("<{}:{}>", region.class, keyed_tag64(&RUN_KEY, value)),
        }
    }

    fn regions(&self, text: &str, hints: &[Token]) -> Regions {
        let mut spans: Vec<Span> = Vec::new();
        self.credential_spans(text, &mut spans);
        self.entity_spans(text, hints, &mut spans);
        self.merge_spans(text, spans)
    }

    fn credential_spans(&self, text: &str, spans: &mut Vec<Span>) {
        if self.action(Entity::Credential).is_none() {
            return;
        }
        let mut push = |range: Range<usize>, class: &'static str, rank: ClaimRank| {
            spans.push(Span {
                start: range.start,
                end: range.end,
                entity: Entity::Credential,
                class,
                kind: None,
                rank,
            });
        };
        for c in CREDENTIAL_ASSIGNMENT.captures_iter(text) {
            if let Some(value) = c.get(2) {
                push(value.range(), "SECRET", ClaimRank::AssignmentValue);
            }
        }
        for m in JWT.find_iter(text) {
            push(m.range(), "JWT", ClaimRank::Jwt);
        }
        for m in PROVIDER_KEY.find_iter(text) {
            push(m.range(), "KEY", ClaimRank::ProviderKey);
        }
        for range in authorization_credential_spans(text) {
            push(range, "SECRET", ClaimRank::AuthorizationHeader);
        }
        for range in userinfo_password_spans(text) {
            push(range, "SECRET", ClaimRank::UrlPassword);
        }
    }

    fn entity_spans(&self, text: &str, hints: &[Token], spans: &mut Vec<Span>) {
        let email = self.action(Entity::Email).is_some();
        let ip = self.action(Entity::Ip).is_some();
        let host = self.action(Entity::Host).is_some();
        if !(email || ip || host) {
            return;
        }
        let mut detector_tokens = scanned_entities_without_syslog_host(text, email, ip, host);
        if host {
            if let Ok(line) = SYSLOG_HOST_PLACER.normalize_line(text.to_string()) {
                detector_tokens.extend(line.tokens);
            }
            for (start, end) in NetworkDetector::dns_shaped_spans(text) {
                spans.push(Span::entity(start, end, Kind::Fqdn));
            }
        }
        if ip {
            for (start, end) in NetworkDetector::ipv4_spans(text) {
                spans.push(Span::entity(start, end, Kind::Ipv4));
            }
        }
        let mut values: Vec<(Kind, &str)> = hints
            .iter()
            .chain(&detector_tokens)
            .filter_map(entity_value)
            .filter(|(kind, value)| !value.is_empty() && self.action(kind.entity()).is_some())
            .collect();
        values.sort_unstable();
        values.dedup();
        for (kind, value) in values {
            for (start, _) in text.match_indices(value) {
                let end = start + value.len();
                if at_token_boundary(text, start, end) {
                    spans.push(Span::entity(start, end, kind));
                }
            }
        }
    }

    fn merge_spans(&self, text: &str, mut spans: Vec<Span>) -> Regions {
        spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
        let mut regions = Vec::new();
        let mut i = 0;
        while i < spans.len() {
            let start = spans[i].start;
            let mut end = spans[i].end;
            let mut highest_ranked = spans[i];
            let mut j = i + 1;
            while j < spans.len() && spans[j].start < end {
                end = end.max(spans[j].end);
                if spans[j].outranks(&highest_ranked) {
                    highest_ranked = spans[j];
                }
                j += 1;
            }
            let whole_region = &text[start..end];
            regions.push(Region {
                start,
                end,
                tag: self.tag(highest_ranked.entity, highest_ranked.class, whole_region),
                entity: highest_ranked.entity,
                class: highest_ranked.class,
                kind: highest_ranked.kind,
            });
            i = j;
        }
        Regions(regions)
    }

    pub fn rollup_entity(&self, type_name: &str) -> Option<(Action, &'static str)> {
        let (entity, class) = match type_name {
            "EMAIL" => (Entity::Email, "EMAIL"),
            "FQDN" | "HOST" => (Entity::Host, "HOST"),
            "IPV4" | "IPV6" => (Entity::Ip, "IP"),
            _ => return None,
        };
        self.action(entity).map(|a| (a, class))
    }

    pub fn names(&self, entity: Entity) -> bool {
        self.action(entity).is_some()
    }
}

struct Region {
    start: usize,
    end: usize,
    tag: String,
    entity: Entity,
    class: &'static str,
    kind: Option<Kind>,
}

struct Regions(Vec<Region>);

impl Regions {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn in_text_order(&self) -> &[Region] {
        &self.0
    }
}

fn last_action_wins(actions: &mut [Option<Action>; 4], entity: Entity, action: Action) {
    actions[entity as usize] = Some(action);
}

fn keyed_tag64(key: &PseudonymKey, value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
    mac.update(value.as_bytes());
    let out = mac.finalize().into_bytes();
    let tag_bytes = TAG_BITS / 8;
    let mut tag = String::with_capacity(tag_bytes * 2);
    for b in &out[..tag_bytes] {
        use std::fmt::Write as _;
        let _ = write!(tag, "{b:02x}");
    }
    tag
}

fn render(text: &str, regions: &Regions) -> String {
    render_with(text, regions, |out, r| out.push_str(&r.tag))
}

fn render_with(text: &str, regions: &Regions, tag: impl Fn(&mut String, &Region)) -> String {
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for r in regions.in_text_order() {
        out.push_str(&text[copied..r.start]);
        tag(&mut out, r);
        copied = r.end;
    }
    out.push_str(&text[copied..]);
    out
}

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    entity: Entity,
    class: &'static str,
    kind: Option<Kind>,
    rank: ClaimRank,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Email,
    Fqdn,
    SyslogHost,
    Ipv4,
    Ipv6,
}

impl Kind {
    fn entity(self) -> Entity {
        match self {
            Kind::Email => Entity::Email,
            Kind::Fqdn | Kind::SyslogHost => Entity::Host,
            Kind::Ipv4 | Kind::Ipv6 => Entity::Ip,
        }
    }

    fn class(self) -> &'static str {
        match self {
            Kind::Email => "EMAIL",
            Kind::Fqdn | Kind::SyslogHost => "HOST",
            Kind::Ipv4 | Kind::Ipv6 => "IP",
        }
    }

    fn token(self, value: String) -> Token {
        match self {
            Kind::Email => Token::Email(value),
            Kind::Fqdn => Token::Fqdn(value),
            Kind::SyslogHost => Token::SyslogHost(value),
            Kind::Ipv4 => Token::IPv4(value),
            Kind::Ipv6 => Token::IPv6(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ClaimRank {
    AssignmentValue,
    Jwt,
    ProviderKey,
    AuthorizationHeader,
    UrlPassword,
    Entity,
}

impl Span {
    fn entity(start: usize, end: usize, kind: Kind) -> Self {
        Self {
            start,
            end,
            entity: kind.entity(),
            class: kind.class(),
            kind: Some(kind),
            rank: ClaimRank::Entity,
        }
    }

    fn outranks(&self, other: &Span) -> bool {
        self.claim_order() < other.claim_order()
    }

    fn claim_order(&self) -> (ClaimRank, std::cmp::Reverse<usize>, usize) {
        (
            self.rank,
            std::cmp::Reverse(self.end - self.start),
            self.start,
        )
    }
}

fn entity_value(token: &Token) -> Option<(Kind, &str)> {
    match token {
        Token::Email(v) => Some((Kind::Email, v.as_str())),
        Token::Fqdn(v) => Some((Kind::Fqdn, v.as_str())),
        Token::SyslogHost(v) => Some((Kind::SyslogHost, v.as_str())),
        Token::IPv4(v) => Some((Kind::Ipv4, v.as_str())),
        Token::IPv6(v) => Some((Kind::Ipv6, v.as_str())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(specs: &[&str], legacy: bool) -> Option<Sanitizer> {
        let specs: Vec<String> = specs.iter().map(ToString::to_string).collect();
        Sanitizer::parse(&specs, legacy)
            .unwrap()
            .map(|s| s.with_test_key(7))
    }

    #[test]
    fn the_bare_flag_is_email_and_credential_redacted_and_nothing_else() {
        let legacy = s(&[], true).unwrap();
        let explicit = s(&["email,credential"], false).unwrap();
        assert_eq!(legacy.actions, explicit.actions);
        assert_eq!(legacy.action(Entity::Host), None);
        assert_eq!(legacy.action(Entity::Ip), None);
        assert!(s(&[], false).is_none());
    }

    #[test]
    fn specs_parse_and_the_last_action_wins() {
        let z = s(&["host", "ip:pseudonym", "host:pseudonym"], false).unwrap();
        assert_eq!(z.action(Entity::Host), Some(Action::KeyedPseudonym));
        assert_eq!(z.action(Entity::Ip), Some(Action::KeyedPseudonym));
        assert_eq!(z.action(Entity::Email), None);
        let both = s(&["host"], true).unwrap();
        assert_eq!(both.action(Entity::Email), Some(Action::Redact));
        assert_eq!(both.action(Entity::Host), Some(Action::Redact));
    }

    #[test]
    fn an_unknown_entity_or_action_is_an_error_naming_the_valid_set() {
        let e = Sanitizer::parse(&["hostname".to_string()], false).unwrap_err();
        assert!(e.contains("email, credential, host, ip"), "{e}");
        let e = Sanitizer::parse(&["host:hash".to_string()], false).unwrap_err();
        assert!(e.contains("redact or pseudonym"), "{e}");
    }

    #[test]
    fn hosts_and_addresses_are_masked_from_tokens_and_from_text() {
        let z = s(&["host", "ip"], false).unwrap();
        let line = "conn from 10.0.0.7 to db-01.example.com and api.example.com:443";
        let tokens = vec![
            Token::IPv4("10.0.0.7".into()),
            Token::Fqdn("api.example.com".into()),
        ];
        assert_eq!(
            z.mask_line(line, &tokens),
            "conn from <IP> to <HOST> and <HOST>:443"
        );
        assert_eq!(
            z.mask_text("peer 10.0.0.7 host db-01.example.com"),
            "peer <IP> host <HOST>"
        );
    }

    #[test]
    fn a_pseudonym_is_stable_within_a_key_and_distinct_per_value() {
        let z = s(&["host:pseudonym"], false).unwrap();
        let a1 = z.mask_text("a.example.com");
        let a2 = z.mask_text("a.example.com");
        let b = z.mask_text("b.example.com");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert!(
            a1.starts_with("<HOST:") && a1.len() == "<HOST:>".len() + 16,
            "{a1}"
        );
        assert!(!a1.contains("example"));
        let other_key = s(&["host:pseudonym"], false).unwrap().with_test_key(8);
        assert_ne!(other_key.mask_text("a.example.com"), a1);
    }

    #[test]
    fn pseudonyms_do_not_collide_at_log_cardinalities() {
        let z = s(&["ip:pseudonym"], false).unwrap();
        assert_ne!(
            z.mask_text("10.0.7.67"),
            z.mask_text("10.0.10.120"),
            "this pair collided under the old 24-bit FNV tag after 2,681 addresses with key 7"
        );
        let mut seen = std::collections::HashSet::new();
        for a in 0..40u32 {
            for b in 0..250u32 {
                assert!(
                    seen.insert(z.mask_text(&format!("10.{a}.{b}.7"))),
                    "collision at 10.{a}.{b}.7 among 10,000 addresses under a 64-bit keyed tag"
                );
            }
        }
    }

    #[test]
    fn redaction_carries_no_key() {
        assert!(Sanitizer::pii_alias().key.is_none());
        assert!(
            Sanitizer::parse(&["host".to_string()], false)
                .unwrap()
                .unwrap()
                .key
                .is_none()
        );
    }

    #[test]
    fn the_env_key_makes_runs_comparable_and_its_absence_does_not() {
        assert_eq!(Sanitizer::derive_key(b"one"), Sanitizer::derive_key(b"one"));
        assert_ne!(Sanitizer::derive_key(b"one"), Sanitizer::derive_key(b"two"));
        if std::env::var(KEY_ENV).is_err() {
            let a = Sanitizer::from_actions_or_refuse_without_entropy([
                None,
                None,
                Some(Action::KeyedPseudonym),
                None,
            ])
            .unwrap();
            let b = Sanitizer::from_actions_or_refuse_without_entropy([
                None,
                None,
                Some(Action::KeyedPseudonym),
                None,
            ])
            .unwrap();
            assert_ne!(a.mask_text("db.example.com"), b.mask_text("db.example.com"));
        }
    }

    #[test]
    fn credentials_pseudonymise_too() {
        let z = s(&["credential:pseudonym"], false).unwrap();
        let out = z.mask_text("password=hunter2 token=eyJhbGciOi.eyJzdWIiOi.SflKxwRJ");
        assert!(out.starts_with("password=<SECRET:"), "{out}");
        assert!(out.contains("token=<SECRET:"), "{out}");
        assert!(!out.contains("hunter2"));
        assert_eq!(
            z.mask_text("password=hunter2"),
            z.mask_text("password=hunter2")
        );
    }

    #[test]
    fn a_disabled_entity_is_left_alone() {
        let z = s(&["email"], false).unwrap();
        let line = "mail bob@example.com from 10.0.0.7 password=x";
        assert_eq!(
            z.mask_line(line, &[Token::Email("bob@example.com".into())]),
            "mail <EMAIL> from 10.0.0.7 password=x"
        );
    }

    #[test]
    fn masking_replaces_whole_addresses() {
        let line = "route from 192.0.2.1 to 192.0.2.15 ok";
        let tokens = vec![
            Token::IPv4("192.0.2.1".into()),
            Token::IPv4("192.0.2.15".into()),
        ];
        let z = s(&["ip"], false).unwrap();
        assert_eq!(z.mask_line(line, &tokens), "route from <IP> to <IP> ok");
        let z = s(&["ip:pseudonym"], false).unwrap();
        let a = z.mask_text("192.0.2.1");
        let b = z.mask_text("192.0.2.15");
        assert_ne!(a, b);
        assert_eq!(
            z.mask_line(line, &tokens),
            format!("route from {a} to {b} ok")
        );
        assert_eq!(z.mask_text(line), format!("route from {a} to {b} ok"));
    }

    #[test]
    fn a_named_value_is_replaced_only_where_it_stands_whole() {
        let z = s(&["host", "email"], false).unwrap();
        let tokens = vec![
            Token::SyslogHost("db".into()),
            Token::Email("ann@example.com".into()),
        ];
        assert_eq!(
            z.mask_line(
                "db dbus mydb db: joann@example.com ann@example.com",
                &tokens
            ),
            "<HOST> dbus mydb <HOST>: <EMAIL> <EMAIL>"
        );
    }

    #[test]
    fn masking_finds_every_entity_without_tokens() {
        let z = s(&["email", "ip", "host"], false).unwrap();
        assert_eq!(
            z.mask_line(
                "Nov 10 10:00:00 gwlab sshd[12]: alice@example.com from 2001:db8::7 via 198.51.100.9",
                &[]
            ),
            "Nov 10 10:00:00 <HOST> sshd[12]: <EMAIL> from <IP> via <IP>"
        );
        assert_eq!(
            z.mask_text(r#""GET /reset?user=bob@example.com HTTP/1.1" 200"#),
            r#""GET /reset?user=<EMAIL> HTTP/1.1" 200"#
        );
        assert_eq!(
            z.mask_text("fetch http://[2001:db8::9]:8080/health"),
            "fetch http://[<IP>]:8080/health"
        );
    }

    #[test]
    fn credential_forms_mask_only_the_secret() {
        let z = s(&["credential"], false).unwrap();
        for (line, masked) in [
            (
                "Authorization: Bearer Zm9vYmFyYmF6cXV4",
                "Authorization: Bearer <SECRET>",
            ),
            (
                "proxy-authorization=Basic YWxhZGRpbjpvcGVu==;",
                "proxy-authorization=Basic <SECRET>;",
            ),
            (
                r#"{"Authorization":"Bearer abc.def-123_x~y"}"#,
                r#"{"Authorization":"Bearer <SECRET>"}"#,
            ),
            (
                "headers map[Authorization:[Bearer Qx9Rt]]",
                "headers map[Authorization:[Bearer <SECRET>]]",
            ),
            (
                "dial postgres://app:Hunter2Secret@db.example.com:5432/x",
                "dial postgres://app:<SECRET>@db.example.com:5432/x",
            ),
            ("redis://:pw@cache:6379", "redis://:<SECRET>@cache:6379"),
            (
                "amqp://u:p@ss@mq.example.com/vh",
                "amqp://u:<SECRET>@mq.example.com/vh",
            ),
            (
                "session Bearer eyJhbGciOi.eyJzdWIiOi.SflKxwRJ",
                "session Bearer <JWT>",
            ),
        ] {
            assert_eq!(z.mask_text(line), masked, "{line}");
        }
        for unchanged in [
            "GET http://db.example.com:8080/path?q=1",
            "mailto user@example.com",
            "ssh://deploy@host.example.com/repo",
        ] {
            assert_eq!(z.mask_text(unchanged), unchanged);
        }
        let z = s(&["credential:pseudonym"], false).unwrap();
        let out = z.mask_text("redis://:pw@cache:6379");
        assert!(
            out.starts_with("redis://:<SECRET:") && out.ends_with(">@cache:6379"),
            "{out}"
        );
    }

    #[test]
    fn overlapping_values_are_replaced_as_one() {
        let z = s(&["email", "credential", "host", "ip"], false).unwrap();
        assert_eq!(
            z.mask_text("password=alice@example.com next"),
            "password=<SECRET> next"
        );
        assert_eq!(z.mask_text("to alice@db.example.com"), "to <EMAIL>");
        assert_eq!(z.mask_text("token: eyJa.eyJb.c1"), "token: <SECRET>");
    }

    #[test]
    fn a_pseudonym_is_the_same_wherever_the_value_stands() {
        let z = s(&["ip:pseudonym"], false).unwrap();
        let tag = z.mask_text("198.51.100.4");
        assert_eq!(
            z.mask_line(
                "peer 198.51.100.4 url http://198.51.100.4:80/x",
                &[Token::IPv4("198.51.100.4".into())]
            ),
            format!("peer {tag} url http://{tag}:80/x")
        );
    }

    #[test]
    fn a_line_masked_for_folding_carries_shown_text_bare_tags_and_entity_tokens() {
        let line = "peer 198.51.100.4 mail ann@example.com password=Quill7Fern";
        let z = s(&["ip:pseudonym", "email", "credential"], false).unwrap();
        let tag = z.mask_text("198.51.100.4");
        let masked = z.mask_for_folding(line, &[]).unwrap();
        assert_eq!(
            masked.shown,
            format!("peer {tag} mail <EMAIL> password=<SECRET>")
        );
        assert_eq!(
            masked.normalizable,
            "peer <IP> mail <EMAIL> password=<SECRET>"
        );
        assert_eq!(masked.tokens.len(), 2, "{:?}", masked.tokens);
        assert_eq!(masked.tokens[0], Token::IPv4(tag));
        let Token::Email(email) = &masked.tokens[1] else {
            panic!("{:?}", masked.tokens);
        };
        assert!(
            email.starts_with("<EMAIL:") && !email.contains("example"),
            "{email}"
        );
        let again = z.mask_for_folding("to ann@example.com", &[]).unwrap();
        assert_eq!(again.tokens, vec![Token::Email(email.clone())]);
        let other = z.mask_for_folding("to bob@example.com", &[]).unwrap();
        assert_ne!(other.tokens, again.tokens);
        assert!(z.mask_for_folding("nothing to hide here", &[]).is_none());
    }
}
