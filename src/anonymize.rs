use std::collections::{BTreeSet, HashMap, HashSet};

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

use crate::folder::{MIN_CREDENTIAL_VALUE, credential_spans};
use crate::patterns::Token;
use crate::patterns::names::K8S_RAND_ALPHABET;
use crate::sanitize::{authorization_credential_spans, userinfo_password_spans};

const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const ULID_LEN: usize = 26;

const COLLISION_TOLERATED_AFTER: usize = 64;

const MIN_NAME_WORDS_KEPT: usize = 1;

const MAX_GENERATED_SEGMENT_LEN: usize = 12;

const POD_SUFFIX_LEN: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Ipv4,
    Ipv6,
    Mac,
    Uuid,
    Ulid,
    Hex,
    Email,
    Host,
    K8s,
    Credential,
    Word,
}

impl Class {
    fn reuses_mapped_words(self) -> bool {
        self == Class::K8s
    }
}

fn class_of(token: &Token) -> Option<(Class, &str)> {
    match token {
        Token::IPv4(v) => Some((Class::Ipv4, v)),
        Token::IPv6(v) if is_non_identity_ipv6(v) => None,
        Token::IPv6(v) => Some((Class::Ipv6, v)),
        Token::Mac(v) => Some((Class::Mac, v)),
        Token::Uuid(v) if is_ulid_shaped(v) => Some((Class::Ulid, v)),
        Token::Uuid(v) => Some((Class::Uuid, v)),
        Token::Hash(_, v) => Some((Class::Hex, v)),
        Token::Email(v) => Some((Class::Email, v)),
        Token::Fqdn(v) | Token::SyslogHost(v) => Some((Class::Host, v)),
        Token::PodName(v) | Token::VolumeName(v) => Some((Class::K8s, v)),
        Token::Timestamp(_)
        | Token::Port(_)
        | Token::Pid(_)
        | Token::ThreadID(_)
        | Token::Path(_)
        | Token::EmbeddedJson(_)
        | Token::Duration(_)
        | Token::CpuQuantity(_)
        | Token::Size(_)
        | Token::Number(_)
        | Token::HttpStatus(_)
        | Token::QuotedString(_)
        | Token::Name(_)
        | Token::KubernetesNamespace(_)
        | Token::KubernetesName(_)
        | Token::PluginType(_)
        | Token::HttpStatusClass(_)
        | Token::BracketContext(_)
        | Token::KeyValuePair { .. }
        | Token::LogWithModule { .. }
        | Token::StructuredMessage { .. } => None,
    }
}

fn is_non_identity_ipv6(value: &str) -> bool {
    value == "::1" || value == "::"
}

fn is_ulid_shaped(value: &str) -> bool {
    value.len() == ULID_LEN && !value.contains('-')
}

fn generated_tail_segments(value: &str) -> Vec<&str> {
    let parts: Vec<&str> = value.split('-').collect();
    let last = parts.len().saturating_sub(1);
    let mut cut = parts.len();
    for i in (0..parts.len()).rev() {
        if !is_generated_segment(parts[i], i == last) {
            break;
        }
        cut = i;
    }
    let first_generated = cut.max(MIN_NAME_WORDS_KEPT).min(parts.len());
    parts[first_generated..].to_vec()
}

pub struct Vocabulary(Vec<String>);

impl Vocabulary {
    pub fn new(mut words: Vec<String>) -> Self {
        for w in &mut words {
            *w = w.to_lowercase();
        }
        words.retain(|w| !w.is_empty());
        words.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        words.dedup();
        Self(words)
    }

    pub fn lowercased_longest_first(&self) -> &[String] {
        &self.0
    }
}

impl From<Vec<String>> for Vocabulary {
    fn from(words: Vec<String>) -> Self {
        Self::new(words)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Slash24([u8; 3]);

#[derive(Clone, Copy, PartialEq, Eq)]
struct Invented10Net {
    second: u8,
    third: u8,
}

type Edit = (usize, usize, String);

pub struct Anonymizer {
    rng: ChaCha8Rng,
    global_values: HashMap<String, String>,
    lengths_by_first_byte: HashMap<u8, BTreeSet<usize>>,
    positional_creds: HashMap<String, String>,
    inventions_by_lowercased_word: HashMap<String, String>,
    learned_in_input_order: Vec<(String, Class)>,
    reserved_originals: HashSet<String>,
    issued_inventions: HashSet<String>,
    invented_subnets: HashMap<Slash24, Invented10Net>,
    vocabulary: Vocabulary,
    forbidden_segments: HashSet<String>,
}

pub struct SealedAnonymizer(Anonymizer);

impl Anonymizer {
    pub fn new(seed: u64, vocabulary: impl Into<Vocabulary>) -> Self {
        let vocabulary = vocabulary.into();
        let forbidden_segments: HashSet<String> = vocabulary
            .lowercased_longest_first()
            .iter()
            .cloned()
            .collect();
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed),
            forbidden_segments,
            global_values: HashMap::new(),
            lengths_by_first_byte: HashMap::new(),
            positional_creds: HashMap::new(),
            inventions_by_lowercased_word: HashMap::new(),
            learned_in_input_order: Vec::new(),
            reserved_originals: HashSet::new(),
            issued_inventions: HashSet::new(),
            invented_subnets: HashMap::new(),
            vocabulary,
        }
    }

    pub fn clock_seed() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0x5eed, |d| d.as_nanos() as u64)
    }

    pub fn learn_line(&mut self, tokens: &[Token], text: &str) {
        self.learn(tokens);
        self.learn_text(text);
    }

    pub fn learn(&mut self, tokens: &[Token]) {
        for token in tokens {
            if let Some((class, value)) = class_of(token)
                && !value.is_empty()
            {
                self.reserve_original(value, class);
            }
        }
    }

    pub fn learn_text(&mut self, text: &str) {
        self.learn(&crate::sanitize::scanned_entities_without_syslog_host(
            text, true, true, false,
        ));
        self.learn_dns_names_from_text(text);
    }

    fn learn_dns_names_from_text(&mut self, text: &str) {
        for name in crate::patterns::network::NetworkDetector::dns_shaped_names(text) {
            self.reserve_original(name, Class::Host);
        }
    }

    fn reserve_original(&mut self, value: &str, class: Class) {
        if self.reserved_originals.insert(value.to_string()) {
            self.learned_in_input_order.push((value.to_string(), class));
        }
    }

    pub fn seal(mut self) -> SealedAnonymizer {
        let learned = std::mem::take(&mut self.learned_in_input_order);
        let (word_reusing, standalone): (Vec<_>, Vec<_>) = learned
            .into_iter()
            .partition(|(_, class)| class.reuses_mapped_words());
        for (value, class) in standalone.iter().chain(&word_reusing) {
            self.invent_value(*class, value);
        }
        SealedAnonymizer(self)
    }

    fn is_taken(&self, candidate: &str) -> bool {
        self.reserved_originals.contains(candidate) || self.issued_inventions.contains(candidate)
    }

    fn positional_credential_edits(&mut self, text: &str, edits: &mut Vec<Edit>) {
        for span in credential_spans(text) {
            if span.is_empty() || !text.is_char_boundary(span.start) {
                continue;
            }
            let invention = self.credential_invention(&text[span.clone()]);
            edits.push((span.start, span.end, invention));
        }
    }

    fn header_and_url_credential_edits(&mut self, text: &str, edits: &mut Vec<Edit>) {
        let header_credentials = authorization_credential_spans(text)
            .into_iter()
            .filter(|span| header_credential_is_secret(span.len()));
        let url_passwords = userinfo_password_spans(text);
        for span in header_credentials.chain(url_passwords) {
            if span.is_empty() || overlaps_without_containing(edits, span.start, span.end) {
                continue;
            }
            edits.retain(|(s, e, _)| !(span.start <= *s && *e <= span.end));
            let invention = self.credential_invention(&text[span.clone()]);
            edits.push((span.start, span.end, invention));
        }
    }

    fn credential_invention(&mut self, value: &str) -> String {
        match self.global_values.get(value) {
            Some(existing) => existing.clone(),
            None => self.invent_credential(value),
        }
    }

    fn map_fragment(&mut self, text: &str) -> String {
        let mut edits: Vec<Edit> = Vec::new();
        self.value_edits(text, &mut edits);
        self.word_edits(text, &mut edits);
        apply_edits_back_to_front(text, edits)
    }

    fn value_edits(&self, text: &str, edits: &mut Vec<Edit>) {
        let b = text.as_bytes();
        for start in 0..b.len() {
            if !text.is_char_boundary(start) {
                continue;
            }
            let Some(lengths) = self.lengths_by_first_byte.get(&b[start]) else {
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
                self.global_values
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

    fn word_edits(&mut self, text: &str, edits: &mut Vec<Edit>) {
        if self.vocabulary.lowercased_longest_first().is_empty() {
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
        for i in 0..self.vocabulary.lowercased_longest_first().len() {
            let word = self.vocabulary.lowercased_longest_first()[i].clone();
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
                let invention = self.invent_word(&text[start..end]);
                edits.push((start, end, invention));
            }
        }
    }

    fn invent_value(&mut self, class: Class, value: &str) -> String {
        if let Some(existing) = self.global_values.get(value) {
            return existing.clone();
        }
        self.reserved_originals.insert(value.to_string());
        let invention = self.draw_unique(class, value);
        if is_real_replacement(&invention, value) {
            self.lengths_by_first_byte
                .entry(value.as_bytes()[0])
                .or_default()
                .insert(value.len());
            self.global_values
                .insert(value.to_string(), invention.clone());
        }
        invention
    }

    fn invent_credential(&mut self, value: &str) -> String {
        if let Some(existing) = self.positional_creds.get(value) {
            return existing.clone();
        }
        let invention = self.draw_unique(Class::Credential, value);
        self.positional_creds
            .insert(value.to_string(), invention.clone());
        invention
    }

    fn invent_word(&mut self, word: &str) -> String {
        let key = word.to_lowercase();
        if let Some(existing) = self.inventions_by_lowercased_word.get(&key) {
            return existing.clone();
        }
        let invention = self.draw_unique(Class::Word, word);
        self.inventions_by_lowercased_word
            .insert(key, invention.clone());
        invention
    }

    fn draw_unique(&mut self, class: Class, value: &str) -> String {
        let mut invention = String::new();
        for _ in 0..COLLISION_TOLERATED_AFTER {
            invention = self.draw(class, value);
            let drew_its_own_original = !is_real_replacement(&invention, value);
            if drew_its_own_original && class == Class::Credential {
                continue;
            }
            if drew_its_own_original || self.is_free_invention(&invention) {
                break;
            }
        }
        if class == Class::Credential && !is_real_replacement(&invention, value) {
            invention = invent_ascii_for_every_char(&mut self.rng, value);
        }
        self.issued_inventions.insert(invention.clone());
        invention
    }

    fn is_free_invention(&self, invention: &str) -> bool {
        !self.is_taken(invention) && !self.carries_vocabulary_segment(invention)
    }

    fn carries_vocabulary_segment(&self, invention: &str) -> bool {
        if self.forbidden_segments.is_empty() {
            return false;
        }
        invention
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|seg| {
                !seg.is_empty() && self.forbidden_segments.contains(&seg.to_ascii_lowercase())
            })
    }

    fn draw(&mut self, class: Class, value: &str) -> String {
        match class {
            Class::Ipv4 => self.draw_ipv4_keeping_subnet_membership(value),
            Class::Ipv6 => self.draw_ipv6_keeping_prefix_class(value),
            Class::Mac => self.draw_mac(value),
            Class::Uuid => self.draw_uuid(value),
            Class::Ulid => self.draw_ulid(value),
            Class::Hex => self.draw_hex(value),
            Class::Email => self.draw_email(value),
            Class::Host => self.draw_host_keeping_tld(value),
            Class::K8s => self.draw_k8s(value),
            Class::Credential | Class::Word => invent_same_char_classes(&mut self.rng, value),
        }
    }

    fn draw_ipv4_keeping_subnet_membership(&mut self, value: &str) -> String {
        let octets: Vec<u8> = value
            .split('.')
            .filter_map(|p| p.parse::<u8>().ok())
            .collect();
        if octets.len() != 4 {
            return invent_same_char_classes(&mut self.rng, value);
        }
        let net = self.invented_subnet(Slash24([octets[0], octets[1], octets[2]]));
        let start = self.rng.random_range(1..=254u8);
        self.probe_free_host_octet(net, start)
    }

    fn invented_subnet(&mut self, input: Slash24) -> Invented10Net {
        if let Some(net) = self.invented_subnets.get(&input) {
            return *net;
        }
        let mut net = self.draw_10_net();
        for _ in 0..COLLISION_TOLERATED_AFTER {
            if !self.invented_subnets.values().any(|v| *v == net) {
                break;
            }
            net = self.draw_10_net();
        }
        self.invented_subnets.insert(input, net);
        net
    }

    fn draw_10_net(&mut self) -> Invented10Net {
        Invented10Net {
            second: self.rng.random::<u8>(),
            third: self.rng.random::<u8>(),
        }
    }

    fn probe_free_host_octet(&self, net: Invented10Net, start: u8) -> String {
        let mut host = start;
        loop {
            let candidate = format!("10.{}.{}.{host}", net.second, net.third);
            if !self.is_taken(&candidate) {
                return candidate;
            }
            host = if host >= 254 { 1 } else { host + 1 };
            if host == start {
                return candidate;
            }
        }
    }

    fn draw_ipv6_keeping_prefix_class(&mut self, value: &str) -> String {
        if is_non_identity_ipv6(value) {
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
                groups.push(format!(
                    "{kept}{}",
                    invent_hex_same_case(&mut self.rng, &group[2..])
                ));
            } else {
                groups.push(invent_hex_same_case(&mut self.rng, group));
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

    fn draw_ulid(&mut self, value: &str) -> String {
        let upper = !value.chars().any(|c| c.is_ascii_lowercase());
        let s: String = (0..ULID_LEN)
            .map(|_| CROCKFORD[self.rng.random_range(0..CROCKFORD.len())] as char)
            .collect();
        if upper { s } else { s.to_lowercase() }
    }

    fn draw_uuid(&mut self, value: &str) -> String {
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

    fn draw_hex(&mut self, value: &str) -> String {
        let (algorithm_prefix, digest) = split_algorithm_prefix(value);
        format!(
            "{algorithm_prefix}{}",
            invent_hex_same_case(&mut self.rng, digest)
        )
    }

    fn draw_email(&mut self, value: &str) -> String {
        let Some((local, domain)) = value.split_once('@') else {
            return invent_same_char_classes(&mut self.rng, value);
        };
        format!(
            "{}@{}",
            invent_same_char_classes(&mut self.rng, local),
            self.draw_host_keeping_tld(domain)
        )
    }

    fn draw_host_keeping_tld(&mut self, value: &str) -> String {
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
                    invent_same_char_classes(&mut self.rng, label)
                }
            })
            .collect::<Vec<_>>()
            .join(".")
    }

    fn draw_k8s(&mut self, value: &str) -> String {
        let parts: Vec<&str> = value.split('-').collect();
        let words_kept = parts.len() - generated_tail_segments(value).len();
        let joined_component_words = parts[..words_kept].join("-");
        let mut out = self.map_fragment(&joined_component_words);
        for segment in &parts[words_kept..] {
            out.push('-');
            let invented = if is_in_k8s_generator_alphabet(segment) {
                invent_in_k8s_generator_alphabet(&mut self.rng, segment)
            } else {
                invent_same_char_classes(&mut self.rng, segment)
            };
            out.push_str(&invented);
        }
        out
    }
}

impl SealedAnonymizer {
    pub fn vocabulary(&self) -> &[String] {
        self.0.vocabulary.lowercased_longest_first()
    }

    pub fn replaced_originals(&self) -> HashSet<String> {
        self.0.global_values.keys().cloned().collect()
    }

    pub fn rewrite(&mut self, text: &str) -> String {
        let mut edits: Vec<Edit> = Vec::new();
        self.0.positional_credential_edits(text, &mut edits);
        self.0.header_and_url_credential_edits(text, &mut edits);
        self.0.value_edits(text, &mut edits);
        self.0.word_edits(text, &mut edits);
        apply_edits_back_to_front(text, edits)
    }
}

fn header_credential_is_secret(len: usize) -> bool {
    len >= MIN_CREDENTIAL_VALUE
}

fn is_real_replacement(invention: &str, original: &str) -> bool {
    invention != original
}

fn split_algorithm_prefix(value: &str) -> (&str, &str) {
    let split = value.rfind(':').map_or(0, |i| i + 1);
    value.split_at(split)
}

fn is_generated_segment(segment: &str, is_last: bool) -> bool {
    let short_alphanumeric = !segment.is_empty()
        && segment.len() <= MAX_GENERATED_SEGMENT_LEN
        && segment.chars().all(|c| c.is_ascii_alphanumeric());
    let has_digit = segment.chars().any(|c| c.is_ascii_digit());
    let is_pod_suffix = is_last && segment.len() == POD_SUFFIX_LEN;
    short_alphanumeric && (has_digit || is_pod_suffix)
}

fn is_in_k8s_generator_alphabet(segment: &str) -> bool {
    segment.bytes().all(|b| K8S_RAND_ALPHABET.contains(&b))
}

fn invent_in_k8s_generator_alphabet(rng: &mut ChaCha8Rng, s: &str) -> String {
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

fn invent_same_char_classes(rng: &mut ChaCha8Rng, s: &str) -> String {
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

/// A credential the same-class draw cannot change (no ASCII letter or
/// digit) gets an ASCII letter for every character that is not ASCII
/// punctuation or whitespace, and for every character when none is.
fn invent_ascii_for_every_char(rng: &mut ChaCha8Rng, s: &str) -> String {
    let keep = |c: char| c.is_ascii_punctuation() || c.is_ascii_whitespace();
    let replace_all = s.chars().all(keep);
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                (b'0' + rng.random_range(0..10u8)) as char
            } else if c.is_ascii_uppercase() {
                (b'A' + rng.random_range(0..26u8)) as char
            } else if replace_all || !keep(c) {
                (b'a' + rng.random_range(0..26u8)) as char
            } else {
                c
            }
        })
        .collect();
    if out == s
        && let Some(first) = out.chars().next()
    {
        let other = if first == 'a' { "b" } else { "a" };
        out.replace_range(..first.len_utf8(), other);
    }
    out
}

fn invent_hex_same_case(rng: &mut ChaCha8Rng, s: &str) -> String {
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

pub fn at_token_boundary(text: &str, start: usize, end: usize) -> bool {
    let b = text.as_bytes();
    let left =
        start == 0 || !b[start - 1].is_ascii_alphanumeric() || percent_escape_ends_at(b, start);
    let right =
        end >= b.len() || !b[end].is_ascii_alphanumeric() || percent_escape_starts_at(b, end);
    left && right
}

fn percent_escape_ends_at(b: &[u8], pos: usize) -> bool {
    pos >= 3 && is_percent_escape(&b[pos - 3..pos])
}

fn percent_escape_starts_at(b: &[u8], pos: usize) -> bool {
    pos + 3 <= b.len() && is_percent_escape(&b[pos..pos + 3])
}

fn is_percent_escape(bytes: &[u8]) -> bool {
    bytes[0] == b'%' && bytes[1].is_ascii_hexdigit() && bytes[2].is_ascii_hexdigit()
}

fn overlaps(edits: &[Edit], start: usize, end: usize) -> bool {
    edits.iter().any(|(s, e, _)| start < *e && *s < end)
}

/// An edit that lies wholly inside `start..end` does not count: the wider
/// span replaces it.
fn overlaps_without_containing(edits: &[Edit], start: usize, end: usize) -> bool {
    edits
        .iter()
        .any(|(s, e, _)| start < *e && *s < end && !(start <= *s && *e <= end))
}

fn apply_edits_back_to_front(text: &str, mut edits: Vec<Edit>) -> String {
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    let mut out = text.to_string();
    for (start, end, invention) in edits {
        out.replace_range(start..end, &invention);
    }
    out
}

const MIN_ID_RUN_LEN: usize = 16;

fn is_id_run_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

fn is_id_run(run: &str) -> bool {
    run.len() >= MIN_ID_RUN_LEN && at_least_a_quarter_digits(run)
}

fn at_least_a_quarter_digits(run: &str) -> bool {
    run.bytes().filter(u8::is_ascii_digit).count() * 4 >= run.len()
}

fn shape_words(line: &str) -> impl Iterator<Item = &str> {
    let b = line.as_bytes();
    let mut i = 0;
    let mut quoted = false;
    let separates_words_or_json_fields = |c: u8, quoted: bool| {
        c.is_ascii_whitespace() || (!quoted && matches!(c, b',' | b'{' | b'}' | b'[' | b']'))
    };
    std::iter::from_fn(move || {
        while i < b.len() && separates_words_or_json_fields(b[i], quoted) {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        let start = i;
        while i < b.len() && !separates_words_or_json_fields(b[i], quoted) {
            if b[i] == b'"' && (i == 0 || b[i - 1] != b'\\') {
                quoted = !quoted;
            }
            i += 1;
        }
        Some(&line[start..i])
    })
}

pub fn literal_word_shape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for word in shape_words(line) {
        if !out.is_empty() {
            out.push(' ');
        }
        let mut rest = word;
        while !rest.is_empty() {
            let run_end = rest.find(|c| !is_id_run_char(c)).unwrap_or(rest.len());
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
    fn mac_rewrites_keep_notation_and_the_local_unicast_bits_on_every_seed_not_one_golden() {
        for (original, separator, alphabet) in [
            ("00:1a:2b:3c:4d:5e", ':', "0123456789abcdef"),
            ("00:1A:2B:3C:4D:5E", ':', "0123456789ABCDEF"),
            ("00-1a-2b-3c-4d-5e", '-', "0123456789abcdef"),
            ("00-1A-2B-3C-4D-5E", '-', "0123456789ABCDEF"),
        ] {
            for seed in 0..32 {
                let mut a = Anonymizer::new(seed, Vec::new());
                a.learn(&[Token::Mac(original.to_string())]);
                let mut a = a.seal();
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
                assert_eq!(
                    first & 1,
                    0,
                    "seed {seed}: invented addresses must be unicast: {out}"
                );
                assert_eq!(
                    first & 2,
                    2,
                    "seed {seed}: invented addresses must be local: {out}"
                );
            }
        }
    }
}

#[cfg(test)]
mod ipv4_tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn a_full_subnet_uses_every_usable_host_before_reusing_an_address() {
        let mut a = Anonymizer::new(1, Vec::new());
        let mut addresses = HashSet::new();
        let mut subnets = HashSet::new();
        for host in 1..=254 {
            let original = format!("203.0.113.{host}");
            let out = a.invent_value(Class::Ipv4, &original);
            let octets = out.parse::<Ipv4Addr>().unwrap().octets();
            assert_eq!(octets[0], 10);
            assert_ne!(octets[3], 0, "network address is not a usable host: {out}");
            assert_ne!(
                octets[3], 255,
                "broadcast address is not a usable host: {out}"
            );
            assert!(
                addresses.insert(out.clone()),
                "host reused too early: {out}"
            );
            subnets.insert([octets[0], octets[1], octets[2]]);
        }
        assert_eq!(subnets.len(), 1, "co-membership must survive a full subnet");
    }

    #[test]
    fn distinct_subnets_remain_distinct_when_invented_prefixes_collide() {
        let mut a = Anonymizer::new(1, Vec::new());
        let mut subnets = HashSet::new();
        let enough_networks_to_force_prefix_redraws = 0..1024;
        for network in enough_networks_to_force_prefix_redraws {
            let original = format!("198.{}.{}.17", network / 256, network % 256);
            let out = a.invent_value(Class::Ipv4, &original);
            let octets = out.parse::<Ipv4Addr>().unwrap().octets();
            assert_eq!(octets[0], 10);
            assert!(
                subnets.insert([octets[0], octets[1], octets[2]]),
                "distinct input subnet aliased by {out}"
            );
        }
    }
}

#[cfg(test)]
mod ipv6_tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn ipv6_preserves_address_class_compression_and_hex_group_widths() {
        for seed in 0..8 {
            let mut a = Anonymizer::new(seed, Vec::new());
            for (original, prefix) in [
                ("fe80::1a2b", "fe80:"),
                ("FE80::1A2B", "FE80:"),
                ("fd12:3456::abcd", "fd"),
                ("FC12:3456::ABCD", "FC"),
            ] {
                let out = a.draw_ipv6_keeping_prefix_class(original);
                assert!(out.parse::<Ipv6Addr>().is_ok(), "invalid IPv6: {out}");
                assert!(out.starts_with(prefix), "address class lost: {out}");
                assert_ne!(out, original, "the host identity must be invented");
                assert_eq!(
                    out.split(':').map(str::len).collect::<Vec<_>>(),
                    original.split(':').map(str::len).collect::<Vec<_>>(),
                    "compression and group widths must survive: {out}"
                );
            }
        }
    }

    #[test]
    fn ipv6_special_addresses_stay_but_prefix_like_host_groups_are_invented() {
        let mut a = Anonymizer::new(1, Vec::new());
        for original in ["::", "::1", "fe80::"] {
            assert_eq!(a.draw_ipv6_keeping_prefix_class(original), original);
        }

        let out = a.draw_ipv6_keeping_prefix_class("2001:db8:fe80:fd12:fc34::abcd");
        assert!(out.parse::<Ipv6Addr>().is_ok(), "invalid IPv6: {out}");
        let groups: Vec<&str> = out.split(':').collect();
        assert_ne!(groups[2], "fe80", "only the first group defines the class");
        assert_ne!(groups[3], "fd12", "host groups must be invented");
        assert_ne!(groups[4], "fc34", "host groups must be invented");
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    #[test]
    fn credentials_are_consistent_but_do_not_rewrite_the_same_word_in_prose() {
        let mut a = Anonymizer::new(1, Vec::new()).seal();
        let out = a.rewrite("前缀 token=Fable9Wren8 note=Fable9Wren8");
        let (invented, prose) = out
            .strip_prefix("前缀 token=")
            .unwrap()
            .split_once(" note=")
            .unwrap();
        assert_ne!(invented, "Fable9Wren8", "credential must be invented");
        assert_eq!(invented.len(), "Fable9Wren8".len());
        assert_eq!(
            prose, "Fable9Wren8",
            "positional matches must stay positional"
        );
        assert_eq!(
            a.rewrite("password=Fable9Wren8"),
            format!("password={invented}"),
            "one credential keeps the same invention across different keys"
        );
    }

    #[test]
    fn a_credential_that_is_also_a_known_address_reuses_its_address_invention() {
        let mut a = Anonymizer::new(1, Vec::new());
        a.learn(&[Token::IPv4("203.0.113.25".to_string())]);
        let mut a = a.seal();
        let invented = a.rewrite("203.0.113.25");
        assert_ne!(invented, "203.0.113.25");
        assert!(invented.parse::<std::net::Ipv4Addr>().is_ok());
        assert_eq!(
            a.rewrite("token=203.0.113.25 peer=203.0.113.25"),
            format!("token={invented} peer={invented}"),
            "overlapping credential and address matches must agree"
        );
    }

    #[test]
    fn a_quoted_credential_is_invented_whole_escapes_included() {
        let line = r#"{"level":"info","msg":"login","password":"ab\"cd-Rook9Tail ef-Moss4Tail"}"#;
        let spans = credential_spans(line);
        let value = r#""ab\"cd-Rook9Tail ef-Moss4Tail""#;
        let start = line.find(value).unwrap();
        assert_eq!(spans, vec![start..start + value.len()]);
        let mut a = Anonymizer::new(1, Vec::new()).seal();
        let out = a.rewrite(line);
        assert!(!out.contains("Rook9Tail"), "{out}");
        assert!(!out.contains("Moss4Tail"), "{out}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invention_never_carries_a_vocabulary_word() {
        let mut hits = 0;
        for seed in 0..200u64 {
            let mut a = Anonymizer::new(seed, vec!["g8".to_string(), "ab".to_string()]);
            a.learn(&[Token::Fqdn("lc.oppdiqfrhj.vyvmmxvn.k9.bolt".to_string())]);
            let mut a = a.seal();
            let out = a.rewrite("loading lc.oppdiqfrhj.vyvmmxvn.k9.bolt");
            for seg in out.split(|c: char| !c.is_ascii_alphanumeric()) {
                assert!(
                    seg != "g8" && seg != "ab",
                    "seed {seed}: an invented segment is a vocabulary word the run exists to remove, and the survived-word check would fail on it: {out}"
                );
            }
            hits += 1;
        }
        assert_eq!(hits, 200);
    }

    fn anon() -> Anonymizer {
        Anonymizer::new(1, Vec::new())
    }

    #[test]
    fn past_collision_tolerated_after_a_colliding_draw_is_accepted_and_the_length_kept() {
        let mut a = anon();
        let inventions: Vec<String> = (0..12).map(|_| a.draw_unique(Class::Word, "7")).collect();
        for invention in &inventions {
            assert_eq!(invention.len(), 1, "{inventions:?}");
            assert!(
                invention.chars().all(|c| c.is_ascii_digit()),
                "{inventions:?}"
            );
        }
        let distinct: HashSet<&String> = inventions.iter().collect();
        assert!(
            distinct.len() < inventions.len(),
            "twelve one-digit inventions from ten digits must reuse one: {inventions:?}"
        );
    }

    #[test]
    fn ipv4_stays_ipv4_in_ten_slash_eight() {
        let mut a = anon();
        let out = a.draw_ipv4_keeping_subnet_membership("203.0.113.9");
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

        let ulid = a.draw_ulid("01K5H2M4N6P8Q0R2S4T6V8W0X2");
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
    fn k8s_suffix_keeps_alphabet_length_and_digit_positions_and_leaves_the_words() {
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
        let orig = "9djm4";
        for (i, c) in orig.char_indices() {
            let inv = suffix.as_bytes()[i] as char;
            assert_eq!(
                c.is_ascii_digit(),
                inv.is_ascii_digit(),
                "position {i}: a digit of {orig} stays a digit and a letter a letter -> {suffix}"
            );
        }
        assert_ne!(out, "pushprox-kube-proxy-client-9djm4");
    }

    #[test]
    fn k8s_segment_outside_the_alphabet_falls_back_to_same_char_classes() {
        let mut a = anon();
        let out = a.draw_k8s("web-1a0e5f-abcde");
        let suffix = out.rsplit('-').next().unwrap();
        assert_eq!(suffix.len(), 5, "same length: {out}");
        assert!(
            suffix.chars().all(|c| c.is_ascii_lowercase()),
            "invent_same_char_classes keeps letter class: {suffix}"
        );
        assert_ne!(suffix, "abcde");
    }

    #[test]
    fn host_keeps_label_count_length_and_tld() {
        let mut a = anon();
        let out = a.draw_host_keeping_tld("db1.prod.example.com");
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
        let mut a = Anonymizer::new(1, vec!["acme".to_string()]).seal();
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
        a.learn(&[Token::SyslogHost("db".to_string())]);
        let mut a = a.seal();
        let out = a.rewrite("db dbus /var/db");
        assert!(out.contains("dbus"), "{out}");
        assert!(!out.starts_with("db "), "{out}");
    }

    #[test]
    fn a_host_seen_only_on_a_later_line_is_replaced_inside_an_earlier_compound_token() {
        let mut a = anon();
        a.learn(&[Token::VolumeName("zorvex-model-storage".to_string())]);
        a.learn(&[Token::SyslogHost("zorvex".to_string())]);
        let mut a = a.seal();
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
            "the mapping covers the whole log before a line is emitted, so the host from line 2 is replaced in line 1: {one} vs {invention}"
        );
    }

    #[test]
    fn a_vocabulary_word_is_replaced_inside_a_compound_token() {
        let mut a = Anonymizer::new(1, vec!["quorlin".to_string()]);
        a.learn(&[Token::PodName(
            "logical-backup-quorlin-postgres-cluster-1756425600".to_string(),
        )]);
        let mut a = a.seal();
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
            Token::SyslogHost("zorvex".to_string()),
        ]);
        let mut a = a.seal();
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
    fn a_line_differing_only_in_numbers_is_one_shape() {
        let a = "Aug 29 08:40:15 host1 sshd[123]: Failed password for root from 10.0.0.5";
        let b = "Aug 30 09:41:16 host1 sshd[456]: Failed password for root from 10.0.0.9";
        let c = "Aug 29 08:40:15 host1 sshd[123]: Accepted password for root from 10.0.0.5";
        assert_eq!(literal_word_shape(a), literal_word_shape(b));
        assert_ne!(literal_word_shape(a), literal_word_shape(c));
        assert_eq!(
            literal_word_shape(a),
            "Aug # #:#:# host# sshd # : Failed password for root from #.#.#.#"
        );
    }

    #[test]
    fn word_shape_splits_a_spaceless_json_record_into_fields() {
        assert_ne!(
            literal_word_shape(r#"{"action":"flomp","ms":12}"#),
            literal_word_shape(r#"{"action":"blorb","ms":12}"#),
            "without the field split both records shape to `#` and the distiller drops one event"
        );
    }

    #[test]
    fn word_shape_keeps_the_letters_around_a_digit() {
        assert_ne!(
            literal_word_shape("switch0.1045: Gained carrier"),
            literal_word_shape("eth0: Gained carrier")
        );
        assert_ne!(
            literal_word_shape("/soc/csr@40000"),
            literal_word_shape("/soc/cti@40000")
        );
        assert_ne!(
            literal_word_shape("  --frobnicate-cache-max='16384'"),
            literal_word_shape("  --frobnicate-queue-max='16384'")
        );
    }

    #[test]
    fn word_shape_folds_ids_stamps_and_pids() {
        assert_eq!(
            literal_word_shape("2026-08-29T08:40:15.123456Z pid=4021 job done"),
            literal_word_shape("2026-08-30T21:04:59.987654Z pid=77 job done")
        );
        assert_eq!(
            literal_word_shape("blob a3f5b8c9d0e1f2a3b4c5d6e7f8091a2b done"),
            literal_word_shape("blob 7c1d9e0f2a3b4c5d6e7f8091a2b3c4d5 done")
        );
    }

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
        let mut a = a.seal();
        let rewritten = a.rewrite(route_line);
        assert!(
            rewritten.contains("liveness"),
            "a plain word is not an id; inventing `route_id` would take `action` with it through the global rewrite: {rewritten}"
        );
        let rewritten_hex = a.rewrite(hex_line);
        assert!(
            !rewritten_hex.contains("a1b2c3d4"),
            "a real digit-bearing id is still invented: {rewritten_hex}"
        );
    }

    #[test]
    fn word_shape_folds_digits_and_keeps_words() {
        assert_eq!(literal_word_shape("a 1 b2 c"), "a # b# c");
        assert_eq!(literal_word_shape("   spaced   out  "), "spaced out");
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn a_value_behind_a_percent_escape_is_still_replaced() {
        let mut a = Anonymizer::new(1, Vec::new());
        a.learn(&[Token::Fqdn("rook-ceph.rbd.csi.ceph.com".to_string())]);
        let mut a = a.seal();
        let out = a.rewrite(
            "x%2Frook-ceph.rbd.csi.ceph.com-reg.sock and /rook-ceph.rbd.csi.ceph.com^0001",
        );
        assert!(!out.contains("rook-ceph.rbd.csi.ceph.com"), "{out}");
    }
}

#[cfg(test)]
mod whole_value_tests {
    use super::*;
    use crate::patterns::network::NetworkDetector;

    fn learn_tokens_then_text_and_rewrite(lines: &[&str]) -> Vec<String> {
        let mut a = Anonymizer::new(1, Vec::new());
        for line in lines {
            a.learn_line(
                &NetworkDetector::detect_and_replace(line, true, true, true).1,
                line,
            );
        }
        let mut a = a.seal();
        lines.iter().map(|line| a.rewrite(line)).collect()
    }

    #[test]
    fn an_address_with_any_port_is_tokenised() {
        let (normalized, tokens) = NetworkDetector::detect_and_replace(
            "peer 198.51.100.3:99999 dropped",
            true,
            true,
            true,
        );
        assert_eq!(normalized, "peer <IP>:99999 dropped");
        assert_eq!(tokens, vec![Token::IPv4("198.51.100.3".into())]);
        let (normalized, tokens) =
            NetworkDetector::detect_and_replace("peer [2001:db8::5]:70000 x", true, true, true);
        assert_eq!(normalized, "peer [<IP>]:70000 x");
        assert_eq!(tokens, vec![Token::IPv6("2001:db8::5".into())]);
        let (normalized, tokens) =
            NetworkDetector::detect_and_replace("peer 198.51.100.3:8443 ok", true, true, true);
        assert_eq!(normalized, "peer <IP>:<PORT> ok");
        assert_eq!(
            tokens,
            vec![Token::IPv4("198.51.100.3".into()), Token::Port(8443)]
        );
    }

    #[test]
    fn an_address_with_any_port_is_invented() {
        let out = learn_tokens_then_text_and_rewrite(&[
            "peer 198.51.100.3:99999 dropped",
            "peer [2001:db8::5]:70000 x",
        ]);
        assert!(
            !out[0].contains("198.51.100.3") && out[0].ends_with(":99999 dropped"),
            "{out:?}"
        );
        assert!(
            !out[1].contains("2001:db8::5") && out[1].ends_with("]:70000 x"),
            "{out:?}"
        );
    }

    #[test]
    fn values_are_learned_from_the_text_as_well_as_the_tokens() {
        let mut a = Anonymizer::new(1, Vec::new());
        let line = "GET http://203.0.113.44:8080/x for carol@example.com via [2001:db8::44]";
        a.learn_text(line);
        let mut a = a.seal();
        let out = a.rewrite(line);
        for original in ["203.0.113.44", "carol@example.com", "2001:db8::44"] {
            assert!(!out.contains(original), "{out}");
        }
    }

    #[test]
    fn header_and_url_credentials_are_invented() {
        let mut a = Anonymizer::new(1, Vec::new()).seal();
        let out = a.rewrite("Authorization: Bearer Zm9vYmFyYmF6cXV4");
        let token = out.strip_prefix("Authorization: Bearer ").unwrap();
        assert_ne!(token, "Zm9vYmFyYmF6cXV4");
        assert_eq!(token.len(), "Zm9vYmFyYmF6cXV4".len());
        let out = a.rewrite("dial postgres://app:Hunter2Secret@db:5432/x");
        assert!(!out.contains("Hunter2Secret"), "{out}");
        assert!(
            out.starts_with("dial postgres://app:") && out.ends_with("@db:5432/x"),
            "{out}"
        );
        assert_eq!(a.rewrite("Bearer token missing"), "Bearer token missing");
    }

    #[test]
    fn a_url_password_holding_a_provider_key_is_replaced_whole() {
        let mut a = Anonymizer::new(1, Vec::new()).seal();
        let out = a.rewrite("dial https://app:front.sk-qwertyuiop.back@db/x");
        assert!(
            out.starts_with("dial https://app:") && out.ends_with("@db/x"),
            "{out}"
        );
        assert!(
            !out.contains("front") && !out.contains("back@") && !out.contains("qwertyuiop"),
            "every part of the password is invented: {out}"
        );
    }

    #[test]
    fn a_credential_without_ascii_letters_or_digits_is_still_replaced() {
        for seed in 0..20u64 {
            let mut a = Anonymizer::new(seed, Vec::new()).seal();
            let out = a.rewrite("login password=密码密码 ok");
            assert!(!out.contains("密码"), "seed {seed}: {out}");
            assert!(
                out.starts_with("login password=") && out.ends_with(" ok"),
                "{out}"
            );
        }
        let mut a = Anonymizer::new(1, Vec::new()).seal();
        let out = a.rewrite("token=\"~~~~~~~~\"");
        assert_ne!(out, "token=\"~~~~~~~~\"", "{out}");
    }
}
