//! `--sanitize <entity>[:<action>]`: which kinds of value leave the output
//! and how (lessence-eu3, lessence-2fu, lessence-o0w).
//!
//! Four entities — `email`, `credential`, `host`, `ip` — and two actions.
//! `redact` replaces a value with its class tag (`<HOST>`); `pseudonym`
//! replaces it with a keyed tag (`<HOST:1a2b3c>`) that is the same on every
//! occurrence of the same value, so a masked host still folds with itself,
//! the rollup still counts four distinct hosts, and the value is gone.
//!
//! `--sanitize-pii` is an exact alias of `--sanitize email,credential` and is
//! never widened: adding an entity to it would change output for every
//! existing user. `host` and `ip` are opt-in only.

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

/// What happens to a value the sanitizer recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The value becomes its class tag: `<EMAIL>`.
    Redact,
    /// The value becomes a keyed tag that is stable for the run:
    /// `<EMAIL:1a2b3c>`. Same value, same tag; the value itself is gone.
    Pseudonym,
}

/// The kinds of value the sanitizer can act on.
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

/// The sanitizer a run was configured with: one optional action per entity
/// and the key that pseudonyms are drawn under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sanitizer {
    actions: [Option<Action>; 4],
    /// The pseudonym key: 256 bits, derived from `LESSENCE_SANITIZE_KEY`
    /// or drawn from the operating system. Only present when some entity
    /// pseudonymises; plain redaction never touches a key.
    key: Option<[u8; 32]>,
}

type HmacSha256 = Hmac<Sha256>;

/// Credential-class value in a `key = value` / `key: value` assignment.
/// Matches any key ending in a credential word (so `client_secret`,
/// `api_key`, `access_token` all count), an optional closing quote, the
/// separator, and masks only the value. Over-masking prose like
/// `invalid token: expected` is accepted: under --sanitize the
/// conservative direction is to mask too much, never too little.
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

/// Byte ranges of the credentials in [`AUTHORIZATION`] matches.
pub(crate) fn authorization_spans(text: &str) -> Vec<Range<usize>> {
    capture_spans(&AUTHORIZATION, text)
}

/// Byte ranges of the passwords in [`URL_USERINFO`] matches.
pub(crate) fn userinfo_spans(text: &str) -> Vec<Range<usize>> {
    capture_spans(&URL_USERINFO, text)
}

fn capture_spans(re: &Regex, text: &str) -> Vec<Range<usize>> {
    re.captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.range()))
        .collect()
}

/// The email detector, run by the masker on the text it is given.
static EMAILS: LazyLock<EmailPatternDetector> =
    LazyLock::new(|| EmailPatternDetector::new().expect("static regex"));

/// The detectors that place a positional syslog host — timestamp, process
/// and network, in the run's own order — and nothing else. The masker runs
/// them itself.
static HOST_SLOT: LazyLock<Normalizer> = LazyLock::new(|| {
    let mut config = Config::default();
    for entry in PATTERN_REGISTRY {
        let wanted = matches!(entry.name, "timestamp" | "process" | "network");
        config.set_pattern_enabled(entry.name, wanted);
    }
    Normalizer::new(config)
});

/// Email, address and host values in `text`, found by the detectors
/// themselves. `email`, `ip` and `host` choose the classes. The positional syslog host is not here:
/// it needs the timestamp pass in front of it (see [`HOST_SLOT`]).
pub(crate) fn scanned_entities(text: &str, email: bool, ip: bool, host: bool) -> Vec<Token> {
    let mut tokens = Vec::new();
    if email && text.contains('@') {
        tokens.extend(EMAILS.detect_and_replace(text).1);
    }
    if ip || host {
        tokens.extend(NetworkDetector::detect_and_replace(text, ip, false, host).1);
    }
    tokens
}

/// The environment variable that fixes the pseudonym key across runs.
pub const KEY_ENV: &str = "LESSENCE_SANITIZE_KEY";

impl Sanitizer {
    /// What a bare `--sanitize-pii` means, exactly as it always has:
    /// emails and credentials, redacted. No key is involved.
    pub fn legacy() -> Self {
        Self {
            actions: [Some(Action::Redact), Some(Action::Redact), None, None],
            key: None,
        }
    }

    /// Build from a decided action set, drawing a key only if one is
    /// needed. Fails only when a pseudonym is asked for and the operating
    /// system cannot supply entropy — a clock-and-pid fallback would
    /// quietly defeat the private-key guarantee, so it is refused instead.
    fn from_actions(actions: [Option<Action>; 4]) -> Result<Self, String> {
        let key = if actions.contains(&Some(Action::Pseudonym)) {
            Some(Self::key_from_env()?)
        } else {
            None
        };
        Ok(Self { actions, key })
    }

    /// The pseudonym key: `LESSENCE_SANITIZE_KEY` hashed to 256 bits when
    /// set, so two runs under the same key give the same tags; otherwise
    /// 32 bytes from the operating system, private to this run. A fixed
    /// public default was considered and rejected: a tag over a small
    /// value space (RFC 1918 addresses) would be dictionary-recoverable by
    /// anyone. Cross-run correlation is a choice the caller makes by
    /// setting the key.
    fn key_from_env() -> Result<[u8; 32], String> {
        match std::env::var(KEY_ENV) {
            Ok(k) if !k.is_empty() => Ok(Self::derive_key(k.as_bytes())),
            _ => {
                let mut key = [0u8; 32];
                getrandom::fill(&mut key).map_err(|e| {
                    format!(
                        "cannot draw a pseudonym key from the operating system ({e}); set {KEY_ENV}"
                    )
                })?;
                Ok(key)
            }
        }
    }

    /// A caller-chosen key string, hashed to 256 bits.
    fn derive_key(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// Fix the key explicitly — tests and library callers.
    #[must_use]
    pub fn with_key(mut self, key: u64) -> Self {
        self.key = Some(Self::derive_key(&key.to_le_bytes()));
        self
    }

    /// Parse the repeatable `--sanitize` specs plus the legacy flag. Each
    /// spec is `entity` or `entity:action`; several specs may name one
    /// entity and the last action wins. `None` when nothing is enabled.
    pub fn parse(specs: &[String], legacy_pii: bool) -> Result<Option<Self>, String> {
        let mut actions: [Option<Action>; 4] = if legacy_pii {
            Self::legacy().actions
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
                "pseudonym" => Action::Pseudonym,
                other => {
                    return Err(format!(
                        "unknown sanitize action `{other}` for `{}` (expected redact or pseudonym)",
                        entity.name()
                    ));
                }
            };
            actions[entity as usize] = Some(action);
        }
        if actions.iter().all(Option::is_none) {
            return Ok(None);
        }
        Self::from_actions(actions).map(Some)
    }

    fn action(&self, entity: Entity) -> Option<Action> {
        self.actions[entity as usize]
    }

    /// The tag a value of `entity` becomes.
    fn tag(&self, entity: Entity, class: &str, value: &str) -> String {
        match self.action(entity) {
            Some(Action::Pseudonym) => {
                // HMAC-SHA256 under the run's key, truncated to 64 bits: a
                // standard keyed construction, so a known value-and-tag
                // pair reveals nothing about the key. Truncation keeps the
                // tag readable inside a template and leaves a birthday
                // collision past four billion distinct values in one log.
                let key = self
                    .key
                    .as_ref()
                    .expect("a pseudonym action always carries a key");
                let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
                mac.update(value.as_bytes());
                let out = mac.finalize().into_bytes();
                let mut tag = String::with_capacity(16);
                for b in &out[..8] {
                    use std::fmt::Write as _;
                    let _ = write!(tag, "{b:02x}");
                }
                format!("<{class}:{tag}>")
            }
            _ => format!("<{class}>"),
        }
    }

    /// `text` as an output shows it: masked when the run sanitizes,
    /// unchanged when it does not.
    pub fn masked(sanitizer: Option<&Self>, text: &str, tokens: &[Token]) -> String {
        sanitizer.map_or_else(|| text.to_string(), |z| z.mask_line(text, tokens))
    }

    /// Mask one original line, given the tokens its normalization found.
    /// The tokens add values to look for; they are not what decides
    /// masking, which is [`Self::mask_text`] on the same line.
    pub fn mask_line(&self, original: &str, tokens: &[Token]) -> String {
        self.mask(original, tokens)
    }

    /// Mask any text — a whole line, a template, a rollup sample, an
    /// essence-mode line. Every output path masks through here.
    ///
    /// Each value is replaced over exactly the span it occupies: a value a
    /// detector names is replaced wherever it stands as a whole token
    /// (`at_token_boundary`). The detectors for each enabled entity run on
    /// the text itself. Spans that overlap are replaced as one region.
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

    /// The part of `text` at `range` as the masked `text` shows it, and the
    /// byte offset where that part starts in the masked text. The values are
    /// found in the whole of `text`, so a piece of one that `range` holds
    /// (`password=hunter2` as a word of a line) is masked as the line masks
    /// it, and a value `range` only partly covers is its whole tag.
    pub fn mask_range(&self, text: &str, hints: &[Token], range: Range<usize>) -> (String, usize) {
        let regions = self.regions(text, hints);
        let at = masked_offset(&regions, range.start);
        if range.is_empty() {
            return (String::new(), at);
        }
        (render_window(text, &regions, range), at)
    }

    /// The credentials `line` holds, found once so that each value cut from
    /// the line can be masked where it stands in it. `None` when the run
    /// masks no credentials or the line holds none.
    pub fn line_secrets<'a>(&self, line: &'a str) -> Option<LineSecrets<'a>> {
        let mut spans = Vec::new();
        self.credential_spans(line, &mut spans);
        if spans.is_empty() {
            return None;
        }
        Some(LineSecrets {
            line,
            regions: self.merge_spans(line, spans),
        })
    }

    /// Every region of `text` the masker replaces, in text order.
    fn regions(&self, text: &str, hints: &[Token]) -> Vec<Region> {
        let mut spans: Vec<Span> = Vec::new();
        self.credential_spans(text, &mut spans);
        self.entity_spans(text, hints, &mut spans);
        self.merge_spans(text, spans)
    }

    /// Where each credential shape puts its secret, ranked in the order the
    /// shapes claim a value: an assignment's value is one secret even when
    /// it is a JWT (`token: eyJ...` is one `<SECRET>`), and a JWT or a
    /// provider key keeps its own class behind an `Authorization` header.
    fn credential_spans(&self, text: &str, spans: &mut Vec<Span>) {
        if self.action(Entity::Credential).is_none() {
            return;
        }
        let mut push = |range: Range<usize>, class: &'static str, rank: u8| {
            spans.push(Span {
                start: range.start,
                end: range.end,
                entity: Entity::Credential,
                class,
                rank,
            });
        };
        for c in CREDENTIAL_ASSIGNMENT.captures_iter(text) {
            if let Some(value) = c.get(2) {
                push(value.range(), "SECRET", 0);
            }
        }
        for m in JWT.find_iter(text) {
            push(m.range(), "JWT", 1);
        }
        for m in PROVIDER_KEY.find_iter(text) {
            push(m.range(), "KEY", 2);
        }
        for range in authorization_spans(text) {
            push(range, "SECRET", 3);
        }
        for range in userinfo_spans(text) {
            push(range, "SECRET", 4);
        }
    }

    /// Every email, address and host value in `text`: the values the run's
    /// tokens name, the values the masker's own detector pass names, and
    /// the DNS- and IPv4-shaped spans of the text, each located at token
    /// boundaries.
    fn entity_spans(&self, text: &str, hints: &[Token], spans: &mut Vec<Span>) {
        let email = self.action(Entity::Email).is_some();
        let ip = self.action(Entity::Ip).is_some();
        let host = self.action(Entity::Host).is_some();
        if !(email || ip || host) {
            return;
        }
        let mut scanned = scanned_entities(text, email, ip, host);
        if host {
            if let Ok(line) = HOST_SLOT.normalize_line(text.to_string()) {
                scanned.extend(line.tokens);
            }
            for (start, end) in NetworkDetector::dns_shaped_spans(text) {
                spans.push(Span::entity(start, end, Entity::Host, "HOST"));
            }
        }
        if ip {
            for (start, end) in NetworkDetector::ipv4_spans(text) {
                spans.push(Span::entity(start, end, Entity::Ip, "IP"));
            }
        }
        let mut values: Vec<(Entity, &'static str, &str)> = hints
            .iter()
            .chain(&scanned)
            .filter_map(entity_value)
            .filter(|(entity, _, value)| !value.is_empty() && self.action(*entity).is_some())
            .collect();
        values.sort_unstable();
        values.dedup();
        for (entity, class, value) in values {
            for (start, _) in text.match_indices(value) {
                let end = start + value.len();
                if at_token_boundary(text, start, end) {
                    spans.push(Span::entity(start, end, entity, class));
                }
            }
        }
    }

    /// The regions every span is replaced over. Overlapping spans are merged
    /// into one region, and the region takes the tag of its highest-ranked
    /// span (a credential first, then the longest value), computed over the
    /// whole region, so a pseudonym is a function of the text it replaces.
    fn merge_spans(&self, text: &str, mut spans: Vec<Span>) -> Vec<Region> {
        spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
        let mut regions = Vec::new();
        let mut i = 0;
        while i < spans.len() {
            let start = spans[i].start;
            let mut end = spans[i].end;
            let mut best = spans[i];
            let mut j = i + 1;
            while j < spans.len() && spans[j].start < end {
                end = end.max(spans[j].end);
                if spans[j].outranks(&best) {
                    best = spans[j];
                }
                j += 1;
            }
            regions.push(Region {
                start,
                end,
                tag: self.tag(best.entity, best.class, &text[start..end]),
            });
            i = j;
        }
        regions
    }

    /// The rollup entries whose samples are values of an enabled entity,
    /// with the tag class each becomes: under `redact` the samples collapse
    /// to one tag; under `pseudonym` each sample becomes its own tag and
    /// the distinct count stands.
    pub fn rollup_entity(&self, type_name: &str) -> Option<(Action, &'static str)> {
        let (entity, class) = match type_name {
            "EMAIL" => (Entity::Email, "EMAIL"),
            "FQDN" | "HOST" => (Entity::Host, "HOST"),
            "IPV4" | "IPV6" => (Entity::Ip, "IP"),
            _ => return None,
        };
        self.action(entity).map(|a| (a, class))
    }

    /// One rollup sample of an entity type, masked.
    pub fn mask_sample(&self, class: &str, value: &str) -> String {
        let entity = match class {
            "EMAIL" => Entity::Email,
            "HOST" => Entity::Host,
            "IP" => Entity::Ip,
            _ => return value.to_string(),
        };
        self.tag(entity, class, value)
    }

    /// Whether the run masks values of `entity`.
    pub fn names(&self, entity: Entity) -> bool {
        self.action(entity).is_some()
    }

    /// Whether the run credential-masks at all — the essence-mode path
    /// only ever had credentials to mask.
    pub fn masks_credentials(&self) -> bool {
        self.action(Entity::Credential).is_some()
    }
}

/// One replaced region of a text: its byte range and the tag it becomes.
/// Regions are disjoint and in text order.
struct Region {
    start: usize,
    end: usize,
    tag: String,
}

/// `text` with every region replaced by its tag.
fn render(text: &str, regions: &[Region]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for r in regions {
        out.push_str(&text[copied..r.start]);
        out.push_str(&r.tag);
        copied = r.end;
    }
    out.push_str(&text[copied..]);
    out
}

/// The part of `text` at `range` with every region it touches replaced by
/// its tag: a region the range only partly covers is its whole tag.
fn render_window(text: &str, regions: &[Region], range: Range<usize>) -> String {
    let mut out = String::new();
    let mut copied = range.start;
    for r in regions
        .iter()
        .filter(|r| r.start < range.end && range.start < r.end)
    {
        if copied < r.start {
            out.push_str(&text[copied..r.start]);
        }
        out.push_str(&r.tag);
        copied = r.end;
    }
    if copied < range.end {
        out.push_str(&text[copied..range.end]);
    }
    out
}

/// Where byte `pos` of a text stands once its regions are replaced. A
/// position inside a region stands at the start of its tag.
fn masked_offset(regions: &[Region], pos: usize) -> usize {
    let mut removed = 0;
    let mut added = 0;
    for r in regions {
        if r.end <= pos {
            removed += r.end - r.start;
            added += r.tag.len();
        } else {
            if r.start < pos {
                return r.start - removed + added;
            }
            break;
        }
    }
    pos - removed + added
}

/// The credentials of one line ([`Sanitizer::line_secrets`]).
pub struct LineSecrets<'a> {
    line: &'a str,
    regions: Vec<Region>,
}

impl LineSecrets<'_> {
    /// `value` as the masked line shows it where it stands in the line:
    /// `pw@db.example.com`, cut from `scheme://user:pw@db.example.com`,
    /// reads `<SECRET>@db.example.com`. `None` when no credential of the
    /// line touches it.
    pub fn mask(&self, value: &str) -> Option<String> {
        if value.is_empty() {
            return None;
        }
        self.line.match_indices(value).find_map(|(start, _)| {
            let range = start..start + value.len();
            self.regions
                .iter()
                .any(|r| r.start < range.end && range.start < r.end)
                .then(|| render_window(self.line, &self.regions, range))
        })
    }
}

/// One value to replace: its byte range in the text, the entity and tag
/// class it is masked as, and its rank among credential shapes (entities
/// rank after every credential shape).
#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    entity: Entity,
    class: &'static str,
    rank: u8,
}

impl Span {
    const ENTITY_RANK: u8 = u8::MAX;

    fn entity(start: usize, end: usize, entity: Entity, class: &'static str) -> Self {
        Self {
            start,
            end,
            entity,
            class,
            rank: Self::ENTITY_RANK,
        }
    }

    /// Lower rank first, then the longer span, then the earlier one.
    fn outranks(&self, other: &Span) -> bool {
        (
            self.rank,
            std::cmp::Reverse(self.end - self.start),
            self.start,
        ) < (
            other.rank,
            std::cmp::Reverse(other.end - other.start),
            other.start,
        )
    }
}

/// A rollup sample of an entity type as the token it was cut from, so the
/// masker can look for it in other text. `None` for any other type.
pub(crate) fn entity_token(type_name: &str, value: &str) -> Option<Token> {
    let value = value.to_string();
    Some(match type_name {
        "EMAIL" => Token::Email(value),
        "FQDN" => Token::Fqdn(value),
        "HOST" => Token::Host(value),
        "IPV4" => Token::IPv4(value),
        "IPV6" => Token::IPv6(value),
        _ => return None,
    })
}

/// The entity, tag class and value of a token the masker acts on.
fn entity_value(token: &Token) -> Option<(Entity, &'static str, &str)> {
    match token {
        Token::Email(v) => Some((Entity::Email, "EMAIL", v.as_str())),
        Token::Fqdn(v) | Token::Host(v) => Some((Entity::Host, "HOST", v.as_str())),
        Token::IPv4(v) | Token::IPv6(v) => Some((Entity::Ip, "IP", v.as_str())),
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
            .map(|s| s.with_key(7))
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
        assert_eq!(z.action(Entity::Host), Some(Action::Pseudonym));
        assert_eq!(z.action(Entity::Ip), Some(Action::Pseudonym));
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
        let other_key = s(&["host:pseudonym"], false).unwrap().with_key(8);
        assert_ne!(other_key.mask_text("a.example.com"), a1);
    }

    /// The pair that collided under the 24-bit FNV tag (found after 2,681
    /// invented addresses, key 7) is distinct now, and so is every pair in
    /// a run of ten thousand.
    #[test]
    fn pseudonyms_do_not_collide_at_log_cardinalities() {
        let z = s(&["ip:pseudonym"], false).unwrap();
        assert_ne!(z.mask_text("10.0.7.67"), z.mask_text("10.0.10.120"));
        let mut seen = std::collections::HashSet::new();
        for a in 0..40u32 {
            for b in 0..250u32 {
                assert!(
                    seen.insert(z.mask_text(&format!("10.{a}.{b}.7"))),
                    "collision at 10.{a}.{b}.7"
                );
            }
        }
    }

    /// The env key is hashed, so two runs under it agree; a run without it
    /// draws its own and matches neither; redaction alone carries no key.
    #[test]
    fn the_env_key_makes_runs_comparable_and_its_absence_does_not() {
        assert_eq!(Sanitizer::derive_key(b"one"), Sanitizer::derive_key(b"one"));
        assert_ne!(Sanitizer::derive_key(b"one"), Sanitizer::derive_key(b"two"));
        assert!(Sanitizer::legacy().key.is_none());
        assert!(
            Sanitizer::parse(&["host".to_string()], false)
                .unwrap()
                .unwrap()
                .key
                .is_none()
        );
        if std::env::var(KEY_ENV).is_err() {
            let a = Sanitizer::from_actions([None, None, Some(Action::Pseudonym), None]).unwrap();
            let b = Sanitizer::from_actions([None, None, Some(Action::Pseudonym), None]).unwrap();
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
            Token::Host("db".into()),
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
    fn a_range_reads_as_the_masked_text_reads_it() {
        let z = s(&["credential", "ip"], false).unwrap();
        let text = r#"api_key: "Heron5 Stoat8" from 198.51.100.21 ok"#;
        let masked = z.mask_text(text);
        assert_eq!(masked, "api_key: <SECRET> from <IP> ok");
        let range = |word: &str| {
            let at = text.find(word).unwrap();
            at..at + word.len()
        };
        // A word holding part of a value is that value's whole tag.
        for word in [r#""Heron5"#, r#"Stoat8""#] {
            let (shown, at) = z.mask_range(text, &[], range(word));
            assert_eq!((shown.as_str(), at), ("<SECRET>", 9), "{word}");
        }
        // A word after a masked value keeps its offset in the masked text.
        for word in ["from", "198.51.100.21", "ok"] {
            let (shown, at) = z.mask_range(text, &[], range(word));
            let expected = if word == "198.51.100.21" {
                "<IP>"
            } else {
                word
            };
            assert_eq!(shown, expected);
            assert_eq!(&masked[at..at + shown.len()], expected, "{word}");
        }
        assert_eq!(z.mask_range(text, &[], 0..8), ("api_key:".to_string(), 0));
        assert_eq!(
            z.mask_range(text, &[], text.len()..text.len()),
            (String::new(), masked.len())
        );
    }

    #[test]
    fn a_value_cut_from_a_line_is_masked_where_it_stands() {
        let line = "dial postgres://app:Gale4Hollow@db.example.com:5432/x as app";
        assert!(s(&["host"], false).unwrap().line_secrets(line).is_none());
        let z = s(&["credential"], false).unwrap();
        assert!(z.line_secrets("dial postgres://db.example.com/x").is_none());
        let secrets = z.line_secrets(line).unwrap();
        assert_eq!(
            secrets.mask("Gale4Hollow@db.example.com").as_deref(),
            Some("<SECRET>@db.example.com")
        );
        assert_eq!(secrets.mask("Hollow@db").as_deref(), Some("<SECRET>@db"));
        assert_eq!(secrets.mask("app:Gale4").as_deref(), Some("app:<SECRET>"));
        assert_eq!(secrets.mask("//app"), None);
        assert_eq!(secrets.mask("absent"), None);
        assert_eq!(secrets.mask(""), None);
    }

    #[test]
    fn masked_is_the_text_itself_without_a_sanitizer() {
        let line = "mail bob@example.com";
        assert_eq!(Sanitizer::masked(None, line, &[]), line);
        let z = s(&["email"], false).unwrap();
        assert_eq!(Sanitizer::masked(Some(&z), line, &[]), "mail <EMAIL>");
    }
}
