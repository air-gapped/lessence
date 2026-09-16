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

use crate::patterns::Token;
use crate::patterns::network::NetworkDetector;
use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::{Digest, Sha256};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Mask one original line, given the tokens its normalization found.
    /// Token values are replaced wherever they occur on the line; hosts and
    /// addresses are also found in the text itself, since a dotted name in
    /// prose is not a token (lessence-c2f) and a sample can carry an address
    /// no token named.
    pub fn mask_line(&self, original: &str, tokens: &[Token]) -> String {
        let mut edits: Vec<(usize, usize, String)> = Vec::new();
        for token in tokens {
            let (entity, class, value) = match token {
                Token::Email(v) => (Entity::Email, "EMAIL", v.as_str()),
                Token::Fqdn(v) | Token::Host(v) => (Entity::Host, "HOST", v.as_str()),
                Token::IPv4(v) | Token::IPv6(v) => (Entity::Ip, "IP", v.as_str()),
                _ => continue,
            };
            if value.is_empty() || self.action(entity).is_none() {
                continue;
            }
            let mut from = 0;
            while let Some(rel) = original[from..].find(value) {
                let start = from + rel;
                let end = start + value.len();
                from = end;
                edits.push((start, end, self.tag(entity, class, value)));
            }
        }
        self.text_edits(original, &mut edits);
        let mut result = apply(original, edits);
        result = self.mask_credentials(&result);
        result
    }

    /// Mask text that is not a whole line — a rollup sample, a template,
    /// an essence-mode line whose tokens are gone — by scanning it.
    pub fn mask_text(&self, text: &str) -> String {
        let mut edits: Vec<(usize, usize, String)> = Vec::new();
        self.text_edits(text, &mut edits);
        let result = apply(text, edits);
        self.mask_credentials(&result)
    }

    /// Hosts and addresses found in the text itself.
    fn text_edits(&self, text: &str, edits: &mut Vec<(usize, usize, String)>) {
        if self.action(Entity::Host).is_some() {
            for (start, end) in NetworkDetector::dns_shaped_spans(text) {
                if !overlaps(edits, start, end) {
                    edits.push((
                        start,
                        end,
                        self.tag(Entity::Host, "HOST", &text[start..end]),
                    ));
                }
            }
        }
        if self.action(Entity::Ip).is_some() {
            for (start, end) in NetworkDetector::ipv4_spans(text) {
                if !overlaps(edits, start, end) {
                    edits.push((start, end, self.tag(Entity::Ip, "IP", &text[start..end])));
                }
            }
        }
    }

    fn mask_credentials(&self, text: &str) -> String {
        let Some(action) = self.action(Entity::Credential) else {
            return text.to_string();
        };
        match action {
            Action::Redact => {
                let masked = CREDENTIAL_ASSIGNMENT.replace_all(text, "${1}<SECRET>");
                let masked = JWT.replace_all(&masked, "<JWT>");
                let masked = PROVIDER_KEY.replace_all(&masked, "<KEY>");
                masked.into_owned()
            }
            Action::Pseudonym => {
                let masked = CREDENTIAL_ASSIGNMENT.replace_all(text, |c: &regex::Captures| {
                    format!("{}{}", &c[1], self.tag(Entity::Credential, "SECRET", &c[2]))
                });
                let masked = JWT.replace_all(&masked, |m: &regex::Captures| {
                    self.tag(Entity::Credential, "JWT", &m[0])
                });
                let masked = PROVIDER_KEY.replace_all(&masked, |m: &regex::Captures| {
                    self.tag(Entity::Credential, "KEY", &m[0])
                });
                masked.into_owned()
            }
        }
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

    /// Whether the run credential-masks at all — the essence-mode path
    /// only ever had credentials to mask.
    pub fn masks_credentials(&self) -> bool {
        self.action(Entity::Credential).is_some()
    }
}

fn overlaps(edits: &[(usize, usize, String)], start: usize, end: usize) -> bool {
    edits.iter().any(|(s, e, _)| start < *e && *s < end)
}

/// Apply non-overlapping edits, last first so earlier offsets stay valid.
fn apply(text: &str, mut edits: Vec<(usize, usize, String)>) -> String {
    edits.sort_by_key(|(s, _, _)| std::cmp::Reverse(*s));
    let mut out = text.to_string();
    let mut last_start = usize::MAX;
    for (start, end, replacement) in edits {
        if end > last_start || !out.is_char_boundary(start) || !out.is_char_boundary(end) {
            continue;
        }
        out.replace_range(start..end, &replacement);
        last_start = start;
    }
    out
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
}
