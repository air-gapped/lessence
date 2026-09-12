//! `--anonymize`: replace every recognised value with an invented one of the
//! same class and shape.
//!
//! The point is not redaction — `<REDACTED>` would destroy the very thing a
//! distilled corpus exists to preserve. A hostname becomes another hostname
//! of the same label count, a 64-hex digest becomes another 64-hex digest, an
//! address becomes another address whose /24 co-members are still co-members.
//! The folder therefore sees the same shapes it saw in the original, and the
//! distilled file folds the way the log it came from did.
//!
//! Two invariants hold across a run: the same original always maps to the
//! same invention (consistency), and two originals never map to one
//! invention (injectivity). The map lives in memory and is never written.

use std::collections::{BTreeSet, HashMap, HashSet};

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

use crate::folder::credential_spans;
use crate::patterns::Token;
use crate::patterns::names::K8S_RAND_ALPHABET;

/// Crockford base32, the ULID alphabet: no I, L, O or U.
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// How many draws to make before accepting a colliding invention. Only
/// reachable for very short values (a one-letter hostname label has 26
/// candidates), where the alternative — changing the length — would break
/// the shape the invention exists to preserve.
// ponytail: bounded redraw, not a perfect bijection; a length-preserving
// permutation would be the upgrade if short labels ever collide in practice.
const REDRAW_ATTEMPTS: usize = 64;

/// What a recognised value is, and therefore how it is invented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Ipv4,
    Ipv6,
    Mac,
    /// A UUID or a ULID — told apart by shape when inventing.
    Uuid,
    /// Hash, hex id, `sha256:` digest.
    Hex,
    Email,
    /// FQDN, syslog `<HOST>`, bare hostname label.
    Host,
    /// A Kubernetes object name whose generated suffixes are invented.
    K8s,
    /// A credential value located by the `--sanitize-pii` patterns.
    Credential,
    /// A word from `--anonymize-words`.
    Word,
}

/// The class a token's value belongs to, or `None` for the kinds the table
/// in `docs/distill.md` leaves alone: timestamps, paths, ports, pids,
/// numbers, sizes, durations, levels, prose.
fn class_of(token: &Token) -> Option<(Class, &str)> {
    match token {
        Token::IPv4(v) => Some((Class::Ipv4, v)),
        // The loopback and the unspecified address are not identities and
        // the table keeps their prefix class, so there is nothing to invent
        // and nothing to check for afterwards.
        Token::IPv6(v) if v == "::1" || v == "::" => None,
        Token::IPv6(v) => Some((Class::Ipv6, v)),
        Token::Mac(v) => Some((Class::Mac, v)),
        Token::Uuid(v) => Some((Class::Uuid, v)),
        Token::Hash(_, v) => Some((Class::Hex, v)),
        Token::Email(v) => Some((Class::Email, v)),
        Token::Fqdn(v) | Token::Host(v) => Some((Class::Host, v)),
        Token::PodName(v) | Token::VolumeName(v) => Some((Class::K8s, v)),
        _ => None,
    }
}

/// The hyphen-separated segments at the end of a Kubernetes name that a
/// controller generated rather than a human named. Walking from the end and
/// stopping at the first segment that reads like a word is what keeps
/// `gpu-operator-node-feature-discovery-worker` intact while `-xhfsf` goes.
fn generated_segments(value: &str) -> Vec<&str> {
    let parts: Vec<&str> = value.split('-').collect();
    let last = parts.len().saturating_sub(1);
    let mut cut = parts.len();
    for i in (0..parts.len()).rev() {
        if !is_generated_segment(parts[i], i == last) {
            break;
        }
        cut = i;
    }
    // The whole name generated would mean no name at all; keep the first
    // segment so something still says what the object is.
    parts[cut.max(1).min(parts.len())..].to_vec()
}

pub struct Anonymizer {
    rng: ChaCha8Rng,
    /// original value → invented value, for the detector classes. Applied
    /// everywhere the value appears, not only where a detector saw it: a
    /// hostname inside a URL and a pod name inside a quoted string are the
    /// same identity as the ones the detectors named.
    values: HashMap<String, String>,
    /// First byte → the lengths of the values starting with it. Turns the
    /// "does a known value start here?" question into one lookup per
    /// position instead of one per known value.
    index: HashMap<u8, BTreeSet<usize>>,
    /// Credential values, keyed by text but matched only where the
    /// credential patterns find them — `token: Post` is a credential, the word
    /// `Post` elsewhere on the line is prose.
    creds: HashMap<String, String>,
    /// Vocabulary words, keyed lowercased.
    word_map: HashMap<String, String>,
    /// Values learned but not yet drawn, in first-appearance order. Nothing
    /// is drawn until every value is known, so no invention can collide with
    /// an original that had not been seen yet.
    pending: Vec<(String, Class)>,
    /// Every invention handed out, so no two originals share one.
    used: HashSet<String>,
    /// input /24 → invented second and third octet under `10.0.0.0/8`.
    subnets: HashMap<[u8; 3], (u8, u8)>,
    /// `--anonymize-words`, lowercased, longest first.
    words: Vec<String>,
}

impl Anonymizer {
    /// `seed` fixes the invention sequence; `words` is the `--anonymize-words`
    /// vocabulary (any case — it is lowercased and matched case-insensitively).
    pub fn new(seed: u64, mut words: Vec<String>) -> Self {
        for w in &mut words {
            *w = w.to_lowercase();
        }
        words.retain(|w| !w.is_empty());
        words.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        words.dedup();
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed),
            values: HashMap::new(),
            index: HashMap::new(),
            creds: HashMap::new(),
            word_map: HashMap::new(),
            pending: Vec::new(),
            used: HashSet::new(),
            subnets: HashMap::new(),
            words,
        }
    }

    /// A seed nobody chose: the wall clock. `--seed N` is the reproducible
    /// path; this one exists so an unseeded run is not silently deterministic.
    pub fn random_seed() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0x5eed, |d| d.as_nanos() as u64)
    }

    pub fn vocabulary(&self) -> &[String] {
        &self.words
    }

    /// Learn the values on one line: every token of an invented class gets
    /// its invention drawn now, in input order, so the mapping is a function
    /// of the seed and the log — not of which lines survive selection.
    pub fn learn(&mut self, tokens: &[Token]) {
        for token in tokens {
            if let Some((class, value)) = class_of(token) {
                // `used` doubles as the set of strings an invention may not
                // be: every original is reserved before anything is drawn,
                // so no rewrite can hand out a value that is somebody else's
                // real one.
                if !value.is_empty() && self.used.insert(value.to_string()) {
                    self.pending.push((value.to_string(), class));
                }
            }
        }
    }

    /// Draw an invention for everything learned. Call once, after the last
    /// `learn`, before the first `rewrite`.
    ///
    /// Kubernetes names are drawn last, because they are the one class whose
    /// invention keeps original text — the component words — and those words
    /// are mapped through everything else. A hostname first seen on the last
    /// line must already have its invention when the name that contains it
    /// is drawn.
    pub fn seal(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        for (value, class) in pending.iter().filter(|(_, c)| *c != Class::K8s) {
            self.invent_value(*class, value);
        }
        for (value, class) in pending.iter().filter(|(_, c)| *c == Class::K8s) {
            self.invent_value(*class, value);
        }
    }

    /// Every original whose invention differs from it. A value the table
    /// leaves unchanged — `::1`, a bare `fe80::` route prefix, a Kubernetes
    /// name of pure words that holds nothing else mapped — was never
    /// replaced, so demanding it be gone from the output would fail a check
    /// the rewriter never claimed to pass.
    pub fn replaced_originals(&self) -> HashSet<String> {
        self.values.keys().cloned().collect()
    }

    /// Rewrite one line against everything learned: credential values where
    /// the credential patterns find them, then every known value at token
    /// boundaries (longest match first, so a hostname inside an FQDN does not
    /// undo the FQDN and `db` never touches `dbus`), then the vocabulary.
    pub fn rewrite(&mut self, text: &str) -> String {
        let mut edits: Vec<(usize, usize, String)> = Vec::new();

        // Credentials are positional: the locator knows the value is a
        // secret, the detectors only see a string. Taking them first also
        // keeps the over-match the locator is documented to accept
        // (`invalid token: expected`) from leaking into every other line the
        // same word appears on.
        for span in credential_spans(text) {
            if span.is_empty() || !text.is_char_boundary(span.start) {
                continue;
            }
            let value = text[span.clone()].to_string();
            let invention = match self.values.get(&value) {
                Some(existing) => existing.clone(),
                None => self.invent(Class::Credential, &value),
            };
            edits.push((span.start, span.end, invention));
        }

        self.value_edits(text, &mut edits);
        self.word_edits(text, &mut edits);
        apply(text, edits)
    }

    /// Every mapped value and vocabulary word in `text`, replaced at token
    /// boundaries. `rewrite` for text that is not a whole input line: the
    /// component words a Kubernetes invention keeps are original text, and
    /// an original is replaced wherever it occurs — inside a compound token
    /// as much as standing alone.
    fn map_text(&mut self, text: &str) -> String {
        let mut edits: Vec<(usize, usize, String)> = Vec::new();
        self.value_edits(text, &mut edits);
        self.word_edits(text, &mut edits);
        apply(text, edits)
    }

    fn value_edits(&self, text: &str, edits: &mut Vec<(usize, usize, String)>) {
        let b = text.as_bytes();
        for start in 0..b.len() {
            if !text.is_char_boundary(start) {
                continue;
            }
            let Some(lengths) = self.index.get(&b[start]) else {
                continue;
            };
            let hit = lengths.iter().rev().find_map(|&len| {
                let end = start + len;
                if end > b.len()
                    || !text.is_char_boundary(end)
                    || !at_token_boundary(text, start, end)
                {
                    return None;
                }
                self.values
                    .get(&text[start..end])
                    .map(|inv| (end, inv.clone()))
            });
            if let Some((end, invention)) = hit
                && !overlaps(edits, start, end)
            {
                edits.push((start, end, invention));
            }
        }
    }

    fn word_edits(&mut self, text: &str, edits: &mut Vec<(usize, usize, String)>) {
        if self.words.is_empty() {
            return;
        }
        let lowered = text.to_lowercase();
        // Lowercasing can change byte length for non-ASCII; fall back to an
        // exact-case scan when it does, rather than misplace an edit.
        let haystack = if lowered.len() == text.len() {
            lowered
        } else {
            text.to_string()
        };
        for i in 0..self.words.len() {
            let word = self.words[i].clone();
            let mut from = 0;
            while let Some(rel) = haystack[from..].find(&word) {
                let start = from + rel;
                let end = start + word.len();
                from = end;
                if !at_token_boundary(text, start, end)
                    || overlaps(edits, start, end)
                    || !text.is_char_boundary(start)
                    || !text.is_char_boundary(end)
                {
                    continue;
                }
                let invention = self.invent(Class::Word, &text[start..end]);
                edits.push((start, end, invention));
            }
        }
    }

    /// A detector-class value's invention, drawn once and indexed for the
    /// whole-line scan.
    fn invent_value(&mut self, class: Class, value: &str) -> String {
        if let Some(existing) = self.values.get(value) {
            return existing.clone();
        }
        self.used.insert(value.to_string());
        let invention = self.draw_unique(class, value);
        // An invention identical to its original is no replacement at all.
        // Registering it would put a whole-token match in front of every
        // shorter value inside it — `cebo` inside `cebo-model-cache` — and
        // that value would then never be replaced anywhere the compound
        // token appears.
        if invention != value {
            self.index
                .entry(value.as_bytes()[0])
                .or_default()
                .insert(value.len());
            self.values.insert(value.to_string(), invention.clone());
        }
        invention
    }

    /// The invention for a credential or a vocabulary word. Words are keyed
    /// lowercased so `ACME` and `acme` share one invention.
    fn invent(&mut self, class: Class, value: &str) -> String {
        let key = if class == Class::Word {
            value.to_lowercase()
        } else {
            value.to_string()
        };
        let table = if class == Class::Word {
            &self.word_map
        } else {
            &self.creds
        };
        if let Some(existing) = table.get(&key) {
            return existing.clone();
        }
        let invention = self.draw_unique(class, value);
        if class == Class::Word {
            self.word_map.insert(key, invention.clone());
        } else {
            self.creds.insert(key, invention.clone());
        }
        invention
    }

    /// Draw until the invention is one no other original already holds.
    fn draw_unique(&mut self, class: Class, value: &str) -> String {
        let mut invention = String::new();
        for _ in 0..REDRAW_ATTEMPTS {
            invention = self.draw(class, value);
            // Its own original is not a collision: a class the table leaves
            // unchanged draws itself every time, and redrawing 64 times to
            // escape it would only burn the seed.
            if invention == value || !self.used.contains(&invention) {
                break;
            }
        }
        self.used.insert(invention.clone());
        invention
    }

    fn draw(&mut self, class: Class, value: &str) -> String {
        match class {
            Class::Ipv4 => self.draw_ipv4(value),
            Class::Ipv6 => self.draw_ipv6(value),
            Class::Mac => self.draw_mac(value),
            Class::Uuid => self.draw_uuid(value),
            Class::Hex => self.draw_hex(value),
            Class::Email => self.draw_email(value),
            Class::Host => self.draw_host(value),
            Class::K8s => self.draw_k8s(value),
            Class::Credential | Class::Word => invent_like(&mut self.rng, value),
        }
    }

    /// A random address in `10.0.0.0/8`. Two inputs that shared a /24 share
    /// one in the output, because co-membership of a subnet is a fact about
    /// the log — "these are all hosts on the storage VLAN" — and inventing it
    /// away would lose a shape the reader is entitled to see.
    fn draw_ipv4(&mut self, value: &str) -> String {
        let octets: Vec<u8> = value
            .split('.')
            .filter_map(|p| p.parse::<u8>().ok())
            .collect();
        if octets.len() != 4 {
            return invent_like(&mut self.rng, value);
        }
        let key = [octets[0], octets[1], octets[2]];
        let net = if let Some(net) = self.subnets.get(&key) {
            *net
        } else {
            let mut net = (self.rng.random::<u8>(), self.rng.random::<u8>());
            for _ in 0..REDRAW_ATTEMPTS {
                if !self.subnets.values().any(|v| *v == net) {
                    break;
                }
                net = (self.rng.random::<u8>(), self.rng.random::<u8>());
            }
            self.subnets.insert(key, net);
            net
        };
        // Probe forward from a random host octet: with only 254 of them a
        // redraw loop would spin once a /24 fills up.
        let start = self.rng.random_range(1..=254u8);
        let mut host = start;
        loop {
            let candidate = format!("10.{}.{}.{host}", net.0, net.1);
            if !self.used.contains(&candidate) {
                return candidate;
            }
            host = if host >= 254 { 1 } else { host + 1 };
            if host == start {
                return candidate;
            }
        }
    }

    /// Keep the prefix class — `fe80::` link-local, `fd`/`fc` unique-local,
    /// the `::1` loopback — and invent the rest. A link-local address that
    /// stopped being link-local would be a different fact.
    fn draw_ipv6(&mut self, value: &str) -> String {
        if value == "::1" || value == "::" {
            return value.to_string();
        }
        let mut groups: Vec<String> = Vec::new();
        for (i, group) in value.split(':').enumerate() {
            if group.is_empty() {
                groups.push(String::new());
                continue;
            }
            let lower = group.to_lowercase();
            if i == 0 && lower == "fe80" {
                groups.push(group.to_string());
            } else if i == 0 && (lower.starts_with("fd") || lower.starts_with("fc")) {
                let kept = &group[..2];
                groups.push(format!("{kept}{}", invent_hex(&mut self.rng, &group[2..])));
            } else {
                groups.push(invent_hex(&mut self.rng, group));
            }
        }
        groups.join(":")
    }

    /// Six hex pairs with the locally-administered bit set and the multicast
    /// bit clear, so an invented address cannot collide with a real vendor's
    /// assignment.
    fn draw_mac(&mut self, value: &str) -> String {
        let sep = if value.contains('-') { '-' } else { ':' };
        let upper = value.chars().any(|c| c.is_ascii_uppercase());
        let first = (self.rng.random::<u8>() & 0xfc) | 0x02;
        let mut octets = vec![format!("{first:02x}")];
        for _ in 1..6 {
            octets.push(format!("{:02x}", self.rng.random::<u8>()));
        }
        let joined = octets.join(&sep.to_string());
        if upper { joined.to_uppercase() } else { joined }
    }

    /// Same kind: a ULID stays 26 Crockford characters, a UUID keeps its
    /// dashes and its version nibble.
    fn draw_uuid(&mut self, value: &str) -> String {
        if value.len() == 26 && !value.contains('-') {
            let upper = !value.chars().any(|c| c.is_ascii_lowercase());
            let s: String = (0..26)
                .map(|_| CROCKFORD[self.rng.random_range(0..CROCKFORD.len())] as char)
                .collect();
            return if upper { s } else { s.to_lowercase() };
        }
        let mut out = String::with_capacity(value.len());
        for (i, c) in value.chars().enumerate() {
            // Byte 6's high nibble is the version and byte 8's high nibble
            // the variant; a v4 UUID that came out v7 would be a different
            // kind of identifier.
            if c == '-' || i == 14 || i == 19 {
                out.push(c);
            } else {
                out.push(hex_digit(&mut self.rng, c.is_ascii_uppercase()));
            }
        }
        out
    }

    /// Same length, same case. An algorithm prefix (`sha256:`) is kept: it
    /// names the shape, it is not part of the value.
    fn draw_hex(&mut self, value: &str) -> String {
        let split = value.rfind(':').map_or(0, |i| i + 1);
        let (prefix, tail) = value.split_at(split);
        format!("{prefix}{}", invent_hex(&mut self.rng, tail))
    }

    fn draw_email(&mut self, value: &str) -> String {
        let Some((local, domain)) = value.split_once('@') else {
            return invent_like(&mut self.rng, value);
        };
        format!(
            "{}@{}",
            invent_like(&mut self.rng, local),
            self.draw_host(domain)
        )
    }

    /// Invented labels, same count and same length; the TLD is kept because
    /// it is a shape, not an identity, and the detectors read it.
    fn draw_host(&mut self, value: &str) -> String {
        let labels: Vec<&str> = value.split('.').collect();
        let keep_tld = labels.len() >= 2
            && labels
                .last()
                .is_some_and(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphabetic()));
        let last = labels.len() - 1;
        labels
            .iter()
            .enumerate()
            .map(|(i, label)| {
                if keep_tld && i == last {
                    (*label).to_string()
                } else {
                    invent_like(&mut self.rng, label)
                }
            })
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Only the generated tail of a Kubernetes name is invented — the
    /// replicaset hash, the pod suffix, the ordinal. The component words in
    /// front are what the name says it is, so they stay — but a component
    /// word that is itself mapped (a hostname elsewhere in the log, a
    /// vocabulary entry) is still that identity, and it is replaced here
    /// exactly as it would be anywhere else. A segment drawn entirely from
    /// the Kubernetes generator alphabet is invented from that same
    /// alphabet, so it still folds to `<SUFFIX>` exactly as the original did.
    fn draw_k8s(&mut self, value: &str) -> String {
        let parts: Vec<&str> = value.split('-').collect();
        let keep = parts.len() - generated_segments(value).len();
        // Mapped across the joined prefix, not per segment: a vocabulary
        // entry can span the hyphens (`acme-stage`).
        let mut out = self.map_text(&parts[..keep].join("-"));
        for part in &parts[keep..] {
            out.push('-');
            let invented = if part.bytes().all(|b| K8S_RAND_ALPHABET.contains(&b)) {
                invent_k8s_rand(&mut self.rng, part)
            } else {
                invent_like(&mut self.rng, part)
            };
            out.push_str(&invented);
        }
        out
    }
}

/// A hyphen-separated segment that a controller generated rather than a
/// human named: alphanumeric, short, and either carrying a digit or being
/// the five-character tail Kubernetes appends to a pod name — `-xhfsf` has
/// no digit and is no less generated for it.
fn is_generated_segment(segment: &str, is_last: bool) -> bool {
    !segment.is_empty()
        && segment.len() <= 12
        && segment.chars().all(|c| c.is_ascii_alphanumeric())
        && (segment.chars().any(|c| c.is_ascii_digit()) || (is_last && segment.len() == 5))
}

/// A segment drawn from the Kubernetes generator alphabet is invented from
/// that alphabet — a digit stays a digit, a letter a letter — so the
/// invented name folds to `<SUFFIX>` exactly as the original did.
fn invent_k8s_rand(rng: &mut ChaCha8Rng, s: &str) -> String {
    let letters: Vec<u8> = K8S_RAND_ALPHABET
        .iter()
        .copied()
        .filter(u8::is_ascii_lowercase)
        .collect();
    let digits: Vec<u8> = K8S_RAND_ALPHABET
        .iter()
        .copied()
        .filter(u8::is_ascii_digit)
        .collect();
    s.bytes()
        .map(|b| {
            let pool = if b.is_ascii_digit() {
                &digits
            } else {
                &letters
            };
            pool[rng.random_range(0..pool.len())] as char
        })
        .collect()
}

/// Same length, same character classes: a digit stays a digit, a letter
/// stays a letter of the same case, everything else is kept verbatim.
fn invent_like(rng: &mut ChaCha8Rng, s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_digit() {
                (b'0' + rng.random_range(0..10u8)) as char
            } else if c.is_ascii_lowercase() {
                (b'a' + rng.random_range(0..26u8)) as char
            } else if c.is_ascii_uppercase() {
                (b'A' + rng.random_range(0..26u8)) as char
            } else {
                c
            }
        })
        .collect()
}

/// Same length, same case, still hex. Non-hex characters are kept.
fn invent_hex(rng: &mut ChaCha8Rng, s: &str) -> String {
    let upper = s.chars().any(|c| c.is_ascii_uppercase());
    s.chars()
        .map(|c| {
            if c.is_ascii_hexdigit() {
                hex_digit(rng, upper)
            } else {
                c
            }
        })
        .collect()
}

fn hex_digit(rng: &mut ChaCha8Rng, upper: bool) -> char {
    let d = rng.random_range(0..16u8);
    let c = char::from_digit(u32::from(d), 16).unwrap_or('0');
    if upper { c.to_ascii_uppercase() } else { c }
}

/// Does `[start, end)` sit at token boundaries in `text`? A neighbouring
/// alphanumeric means the match is part of a longer token — the hostname
/// `db` inside `dbus` — and is left alone. A `%XX` escape on either side is
/// a boundary too: `plugins_registry%2Frook-ceph.rbd.csi.ceph.com-reg.sock`
/// ends the escape in an `F`, and a value that hid behind one would be a
/// value that escaped.
pub fn at_token_boundary(text: &str, start: usize, end: usize) -> bool {
    let b = text.as_bytes();
    let left = start == 0
        || !b[start - 1].is_ascii_alphanumeric()
        || (start >= 3 && is_percent_escape(&b[start - 3..start]));
    let right = end >= b.len()
        || !b[end].is_ascii_alphanumeric()
        || (end + 3 <= b.len() && is_percent_escape(&b[end..end + 3]));
    left && right
}

fn is_percent_escape(bytes: &[u8]) -> bool {
    bytes[0] == b'%' && bytes[1].is_ascii_hexdigit() && bytes[2].is_ascii_hexdigit()
}

fn overlaps(edits: &[(usize, usize, String)], start: usize, end: usize) -> bool {
    edits.iter().any(|(s, e, _)| start < *e && *s < end)
}

/// Rewrite the collected spans back to front, so earlier offsets stay valid.
fn apply(text: &str, mut edits: Vec<(usize, usize, String)>) -> String {
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    let mut out = text.to_string();
    for (start, end, invention) in edits {
        out.replace_range(start..end, &invention);
    }
    out
}

/// Length at which a digit-bearing identifier run is read as an id, hash or
/// stamp rather than as words: a UUID, a 32-hex digest, a pod name with a
/// generated tail, an ISO timestamp. Below it the letters are kept.
const ID_RUN_MIN: usize = 16;

/// Is `c` part of an identifier run — the span a whole id, hash, stamp or
/// dotted name occupies? `.`, `_` and `-` are inside it, so a UUID and a
/// timestamp are each one run.
fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// An id, hash or stamp: long, and at least a quarter digits. A flag name
/// is long too (`--l2-pod-announcements-interface`) but carries one digit in
/// thirty; folding it to `#` would put every flag in one shape and let the
/// distiller drop all but one of them.
fn is_id_run(run: &str) -> bool {
    run.len() >= ID_RUN_MIN && run.bytes().filter(u8::is_ascii_digit).count() * 4 >= run.len()
}

/// Words of `line` for shape purposes: whitespace, and `,{}[]` outside a
/// quoted string, separate them — so a spaceless JSON record is one word per
/// field, not one word. Models `patterns::word_spans`, which is what the
/// folder splits on, plus the brackets of a JSON array.
fn shape_words(line: &str) -> impl Iterator<Item = &str> {
    let b = line.as_bytes();
    let mut i = 0;
    let mut quoted = false;
    let sep = |c: u8, quoted: bool| {
        c.is_ascii_whitespace() || (!quoted && matches!(c, b',' | b'{' | b'}' | b'[' | b']'))
    };
    std::iter::from_fn(move || {
        while i < b.len() && sep(b[i], quoted) {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        let start = i;
        while i < b.len() && !sep(b[i], quoted) {
            if b[i] == b'"' && (i == 0 || b[i - 1] != b'\\') {
                quoted = !quoted;
            }
            i += 1;
        }
        Some(&line[start..i])
    })
}

/// A line's word shape: the words above, with every maximal digit run
/// replaced by `#` and every id-shaped run replaced by `#` whole.
/// Detector-independent on purpose — it is the check that catches a fold
/// across a literal word, which is exactly the case where the detectors saw
/// nothing. Keeping the letters is what makes `"action":"liveness"` and
/// `"action":"readiness"`, or `--bpf-ct-global-tcp-max='16384'` and
/// `--bpf-policy-map-max='16384'`, two shapes instead of one.
pub fn word_shape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for word in shape_words(line) {
        if !out.is_empty() {
            out.push(' ');
        }
        let mut rest = word;
        while !rest.is_empty() {
            let run_end = rest.find(|c| !is_ident_char(c)).unwrap_or(rest.len());
            if run_end == 0 {
                let c = rest.chars().next().expect("rest is not empty");
                out.push(c);
                rest = &rest[c.len_utf8()..];
                continue;
            }
            let (run, tail) = rest.split_at(run_end);
            if is_id_run(run) {
                out.push('#');
            } else {
                let mut in_digits = false;
                for c in run.chars() {
                    if c.is_ascii_digit() {
                        if !in_digits {
                            out.push('#');
                            in_digits = true;
                        }
                    } else {
                        in_digits = false;
                        out.push(c);
                    }
                }
            }
            rest = tail;
        }
    }
    out
}

#[cfg(test)]
mod mac_tests {
    use super::*;

    #[test]
    fn mac_rewrites_preserve_notation_and_use_local_unicast_addresses() {
        for (original, separator, alphabet) in [
            ("00:1a:2b:3c:4d:5e", ':', "0123456789abcdef"),
            ("00:1A:2B:3C:4D:5E", ':', "0123456789ABCDEF"),
            ("00-1a-2b-3c-4d-5e", '-', "0123456789abcdef"),
            ("00-1A-2B-3C-4D-5E", '-', "0123456789ABCDEF"),
        ] {
            // Exercise the address-bit contract across a reproducible set
            // of draws, rather than pinning one random address as a golden.
            for seed in 0..32 {
                let mut a = Anonymizer::new(seed, Vec::new());
                a.learn(&[Token::Mac(original.to_string())]);
                a.seal();
                let out = a.rewrite(original);

                assert_ne!(out, original, "the hardware identity must be invented");
                let octets: Vec<&str> = out.split(separator).collect();
                assert_eq!(octets.len(), 6, "six pairs with {separator}: {out}");
                for octet in &octets {
                    assert_eq!(octet.len(), 2, "each octet is two hex digits: {out}");
                    assert!(
                        octet.bytes().all(|b| alphabet.as_bytes().contains(&b)),
                        "hex digits must preserve the input case: {out}"
                    );
                }
                let first = u8::from_str_radix(octets[0], 16).unwrap();
                assert_eq!(first & 1, 0, "invented addresses must be unicast: {out}");
                assert_eq!(first & 2, 2, "invented addresses must be local: {out}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anon() -> Anonymizer {
        Anonymizer::new(1, Vec::new())
    }

    #[test]
    fn ipv4_stays_ipv4_in_ten_slash_eight() {
        let mut a = anon();
        let out = a.draw_ipv4("203.0.113.9");
        let octets: Vec<u8> = out.split('.').map(|p| p.parse().unwrap()).collect();
        assert_eq!(octets.len(), 4, "{out} must still be an IPv4 address");
        assert_eq!(octets[0], 10, "{out} must live in 10.0.0.0/8");
    }

    #[test]
    fn ipv4_slash_24_co_membership_is_kept_and_separated() {
        let mut a = anon();
        let one = a.invent_value(Class::Ipv4, "203.0.113.9");
        let two = a.invent_value(Class::Ipv4, "203.0.113.240");
        let other = a.invent_value(Class::Ipv4, "203.0.114.9");
        let net = |s: &str| s.rsplit_once('.').unwrap().0.to_string();
        assert_eq!(net(&one), net(&two), "same input /24 → same output /24");
        assert_ne!(net(&one), net(&other), "different /24 must stay different");
        assert_ne!(one, two, "distinct hosts stay distinct");
    }

    #[test]
    fn uuid_stays_a_uuid_and_ulid_stays_a_ulid() {
        let mut a = anon();
        let uuid = a.draw_uuid("9c0e2dfe-6623-4cad-bc68-c9bc9bf2f9cc");
        assert_eq!(uuid.len(), 36);
        assert_eq!(
            uuid.split('-').map(str::len).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(uuid.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        assert!(uuid.starts_with(|c: char| c.is_ascii_hexdigit()));
        assert_eq!(&uuid[14..15], "4", "the version nibble is the kind");
        assert_ne!(uuid, "9c0e2dfe-6623-4cad-bc68-c9bc9bf2f9cc");

        let ulid = a.draw_uuid("01K5H2M4N6P8Q0R2S4T6V8W0X2");
        assert_eq!(ulid.len(), 26);
        assert!(
            ulid.bytes().all(|b| CROCKFORD.contains(&b)),
            "{ulid} must stay Crockford base32"
        );
    }

    #[test]
    fn hex_keeps_length_and_case() {
        let mut a = anon();
        let lower = a.draw_hex("a3f9c1d0e5b7");
        assert_eq!(lower.len(), 12);
        assert!(lower.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!lower.chars().any(|c| c.is_ascii_uppercase()), "{lower}");

        let upper = a.draw_hex("A3F9C1D0E5B7");
        assert_eq!(upper.len(), 12);
        assert!(!upper.chars().any(|c| c.is_ascii_lowercase()), "{upper}");

        let digest = a.draw_hex("sha256:0123456789abcdef0123456789abcdef");
        assert!(digest.starts_with("sha256:"), "prefix is a shape: {digest}");
        assert_eq!(
            digest.len(),
            "sha256:0123456789abcdef0123456789abcdef".len()
        );
    }

    #[test]
    fn k8s_suffix_keeps_alphabet_and_length_and_leaves_the_words() {
        let mut a = anon();
        let out = a.draw_k8s("pushprox-kube-proxy-client-9djm4");
        assert!(
            out.starts_with("pushprox-kube-proxy-client-"),
            "component words stay: {out}"
        );
        let suffix = out.rsplit('-').next().unwrap();
        assert_eq!(suffix.len(), 5);
        assert!(
            suffix.bytes().all(|b| K8S_RAND_ALPHABET.contains(&b)),
            "invented suffix stays in the k8s alphabet: {suffix}"
        );
        // Digit positions in the original stay digits in the invention:
        // "9djm4" has a digit at position 0 and position 4.
        let orig = "9djm4";
        for (i, c) in orig.char_indices() {
            let inv = suffix.as_bytes()[i] as char;
            assert_eq!(
                c.is_ascii_digit(),
                inv.is_ascii_digit(),
                "position {i}: {orig} -> {suffix}"
            );
        }
        assert_ne!(out, "pushprox-kube-proxy-client-9djm4");

        // A segment with a character outside the k8s alphabet (e.g. 'a')
        // falls back to invent_like: same length, digits stay digits, not
        // equal to the input.
        let out2 = a.draw_k8s("web-1a0e5f-abcde");
        let suffix2 = out2.rsplit('-').next().unwrap();
        assert_eq!(suffix2.len(), 5);
        assert!(
            suffix2.chars().all(|c| c.is_ascii_lowercase()),
            "invent_like keeps letter class: {suffix2}"
        );
        assert_ne!(suffix2, "abcde");
    }

    #[test]
    fn host_keeps_label_count_length_and_tld() {
        let mut a = anon();
        let out = a.draw_host("db1.prod.example.com");
        let labels: Vec<&str> = out.split('.').collect();
        assert_eq!(labels.len(), 4, "{out}");
        assert_eq!(labels[3], "com", "TLD is kept: {out}");
        assert_eq!(
            labels.iter().map(|l| l.len()).collect::<Vec<_>>(),
            vec![3, 4, 7, 3]
        );
        assert_ne!(labels[0], "db1");
    }

    #[test]
    fn mapping_is_consistent_and_injective() {
        let mut a = anon();
        let first = a.invent_value(Class::Host, "alpha.example.com");
        let again = a.invent_value(Class::Host, "alpha.example.com");
        assert_eq!(first, again, "one original, one invention");

        let mut seen = HashSet::new();
        for i in 0..500 {
            let value = format!("host{i}.example.com");
            let invention = a.invent_value(Class::Host, &value);
            assert!(seen.insert(invention.clone()), "collision on {invention}");
        }
        assert!(!seen.contains(&first) || seen.len() == 500);
    }

    #[test]
    fn word_replacement_respects_word_and_percent_boundaries() {
        let mut a = Anonymizer::new(1, vec!["acme".to_string()]);
        let out = a.rewrite("Host:acme dbus acme-01 x%2Dacme%2Dy acmed");
        assert_eq!(
            out.to_lowercase().matches("acme").count(),
            1,
            "every bounded occurrence is replaced; only the glued one stays: {out}"
        );
        assert!(
            out.contains("dbus"),
            "an unrelated word is untouched: {out}"
        );
        assert!(
            out.ends_with(" acmed"),
            "a word glued to more letters is not a match: {out}"
        );
        let invented = out.split_whitespace().next().unwrap();
        assert_eq!(invented.len(), "Host:acme".len(), "same length: {out}");
        assert!(
            out.split_whitespace().nth(2).unwrap().ends_with("-01"),
            "only the word is replaced: {out}"
        );
    }

    #[test]
    fn a_hostname_never_rewrites_a_longer_token() {
        let mut a = anon();
        a.learn(&[Token::Host("db".to_string())]);
        a.seal();
        let out = a.rewrite("db dbus /var/db");
        assert!(out.contains("dbus"), "{out}");
        assert!(!out.starts_with("db "), "{out}");
    }

    #[test]
    fn a_mapped_value_is_replaced_inside_a_compound_token_on_every_line() {
        let mut a = anon();
        // The volume name arrives on line 1, the bare host only on line 2.
        // The mapping is built over the whole log before a line is emitted,
        // so the later host is still replaced in the earlier compound token.
        a.learn(&[Token::VolumeName("zorvex-model-storage".to_string())]);
        a.learn(&[Token::Host("zorvex".to_string())]);
        a.seal();
        let one = a.rewrite("PVC=\"vllm/zorvex-model-storage\" mounted");
        let two = a.rewrite("Aug 29 08:40:15 zorvex kubelet: ready");
        assert!(
            !one.contains("zorvex"),
            "a component word is the identity: {one}"
        );
        assert!(!two.contains("zorvex"), "{two}");
        let invention = two.split_whitespace().nth(3).expect("host field");
        assert!(
            one.contains(&format!("vllm/{invention}-model-storage")),
            "one original, one invention, both lines: {one} vs {invention}"
        );
    }

    #[test]
    fn a_vocabulary_word_is_replaced_inside_a_compound_token() {
        let mut a = Anonymizer::new(1, vec!["quorlin".to_string()]);
        a.learn(&[Token::PodName(
            "logical-backup-quorlin-postgres-cluster-1756425600".to_string(),
        )]);
        a.seal();
        let out = a.rewrite(
            "job logical-backup-quorlin-postgres-cluster-1756425600 x%2Fquorlin%2Fy a-b-quorlin-c quorlind",
        );
        assert_eq!(
            out.to_lowercase().matches("quorlin").count(),
            1,
            "every bounded occurrence goes, glued to letters it stays: {out}"
        );
        assert!(out.ends_with(" quorlind"), "{out}");
        assert!(
            out.contains("logical-backup-") && out.contains("-postgres-cluster-"),
            "the other component words stay: {out}"
        );
    }

    #[test]
    fn a_value_the_table_keeps_is_not_a_replaced_original() {
        let mut a = anon();
        a.learn(&[
            Token::IPv6("fe80::".to_string()),
            Token::Host("zorvex".to_string()),
        ]);
        a.seal();
        let out = a.rewrite("route add fe80::/64 dev zorvex");
        assert!(out.contains("fe80::/64"), "a route prefix is kept: {out}");
        let replaced = a.replaced_originals();
        assert!(
            !replaced.contains("fe80::"),
            "nothing was replaced, so nothing must be demanded gone"
        );
        assert!(replaced.contains("zorvex"), "a real replacement is listed");
    }

    #[test]
    fn word_shape_splits_a_spaceless_json_record_into_fields() {
        // One whitespace word each: without the field split both records
        // were `#`, and the distiller dropped one of the two events.
        assert_ne!(
            word_shape(r#"{"action":"flomp","ms":12}"#),
            word_shape(r#"{"action":"blorb","ms":12}"#)
        );
    }

    #[test]
    fn word_shape_keeps_the_letters_around_a_digit() {
        assert_ne!(
            word_shape("switch0.1045: Gained carrier"),
            word_shape("eth0: Gained carrier")
        );
        assert_ne!(word_shape("/soc/csr@40000"), word_shape("/soc/cti@40000"));
        assert_ne!(
            word_shape("  --frobnicate-cache-max='16384'"),
            word_shape("  --frobnicate-queue-max='16384'")
        );
    }

    #[test]
    fn word_shape_folds_ids_stamps_and_pids() {
        assert_eq!(
            word_shape("2026-08-29T08:40:15.123456Z pid=4021 job done"),
            word_shape("2026-08-30T21:04:59.987654Z pid=77 job done")
        );
        assert_eq!(
            word_shape("blob a3f5b8c9d0e1f2a3b4c5d6e7f8091a2b done"),
            word_shape("blob 7c1d9e0f2a3b4c5d6e7f8091a2b3c4d5 done")
        );
    }

    /// lessence-defect: `"route_id":"liveness"` was classified as an
    /// opaque id and invented into `5f21025e`, taking `"action":"liveness"`
    /// down with it (same-value rewrite is global). A real 8-hex id must
    /// still be recognised and changed.
    #[test]
    fn a_plain_word_survives_anonymize_but_a_real_hex_id_does_not() {
        use crate::patterns::uuid::UuidDetector;
        let mut a = anon();
        let route_line = r#"{"route_id":"liveness","action":"liveness"}"#;
        let hex_line = r#"{"route_id":"a1b2c3d4"}"#;
        for line in [route_line, hex_line] {
            let (_, tokens) = UuidDetector::detect_and_replace(line);
            a.learn(&tokens);
        }
        a.seal();
        let rewritten = a.rewrite(route_line);
        assert!(
            rewritten.contains("liveness"),
            "a plain word is not an id: {rewritten}"
        );
        let rewritten_hex = a.rewrite(hex_line);
        assert!(
            !rewritten_hex.contains("a1b2c3d4"),
            "a real digit-bearing id is still invented: {rewritten_hex}"
        );
    }

    #[test]
    fn word_shape_folds_digits_and_keeps_words() {
        assert_eq!(word_shape("a 1 b2 c"), "a # b# c");
        assert_eq!(word_shape("   spaced   out  "), "spaced out");
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn a_value_behind_a_percent_escape_is_still_replaced() {
        let mut a = Anonymizer::new(1, Vec::new());
        a.learn(&[Token::Fqdn("rook-ceph.rbd.csi.ceph.com".to_string())]);
        a.seal();
        let out = a.rewrite(
            "x%2Frook-ceph.rbd.csi.ceph.com-reg.sock and /rook-ceph.rbd.csi.ceph.com^0001",
        );
        assert!(!out.contains("rook-ceph.rbd.csi.ceph.com"), "{out}");
    }
}
