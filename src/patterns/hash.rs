use super::{HashType, Token};
use regex::Regex;
use std::sync::LazyLock;

const MD5_HEX_LEN: usize = 32;
const SHA1_HEX_LEN: usize = 40;
const SHA256_HEX_LEN: usize = 64;
const SHA512_HEX_LEN: usize = 128;
const GENERIC_HEX_WIDTHS: [usize; 4] = [16, 24, 48, 56];
const MIN_SHORT_HASH_LEN: usize = 7;
const MAX_SHORT_HASH_LEN: usize = SHA1_HEX_LEN - 1;
const MAX_DESIGNATOR_LEN: usize = 12;
const MIN_COLON_HEX_PAIRS: usize = 4;

fn hex_run(width: impl std::fmt::Display) -> Regex {
    Regex::new(&format!(r"\b[a-fA-F0-9]{{{width}}}\b")).unwrap()
}

static FIXED_HEX_WIDTHS_LONGEST_FIRST: LazyLock<Vec<(Regex, HashType)>> = LazyLock::new(|| {
    let mut widths = vec![
        (SHA512_HEX_LEN, HashType::SHA512),
        (SHA256_HEX_LEN, HashType::SHA256),
        (SHA1_HEX_LEN, HashType::SHA1),
        (MD5_HEX_LEN, HashType::MD5),
    ];
    widths.extend(
        GENERIC_HEX_WIDTHS
            .iter()
            .map(|&len| (len, HashType::Generic { len })),
    );
    widths.sort_by_key(|&(width, _)| std::cmp::Reverse(width));
    widths
        .into_iter()
        .map(|(width, kind)| (hex_run(width), kind))
        .collect()
});

static DEVICE_TREE_NODE_ADDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?P<addr>[0-9a-f]{8})(?P<node>\.[a-z])").unwrap());

static SHORT_HEX_RUN: LazyLock<Regex> =
    LazyLock::new(|| hex_run(format!("{MIN_SHORT_HASH_LEN},{MAX_SHORT_HASH_LEN}")));

static SSH_MD5_FINGERPRINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?P<pair_before>[a-fA-F0-9]{2}:)?(?:[a-fA-F0-9]{2}:){15}[a-fA-F0-9]{2}\b(?P<pair_after>:[a-fA-F0-9]{2})?",
    )
    .unwrap()
});

const SSH_SHA256_LABEL: &str = "SHA256:";

static SSH_SHA256_FINGERPRINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bSHA256:(?P<digest>[A-Za-z0-9+/]{43}=?)(?P<longer>[A-Za-z0-9+/=]?)").unwrap()
});

pub struct HashDetector;

impl HashDetector {
    fn looks_like_hash(s: &str) -> bool {
        let has_digit = s.bytes().any(|b| b.is_ascii_digit());
        let has_letter = s.bytes().any(|b| b.is_ascii_alphabetic());
        has_digit && has_letter && !Self::is_short_designator(s)
    }

    fn is_short_designator(s: &str) -> bool {
        s.len() < MAX_DESIGNATOR_LEN && super::is_designator(s)
    }

    fn is_number(s: &str) -> bool {
        s.bytes().all(|b| b.is_ascii_digit())
    }

    fn may_hold_hex_hash(text: &str) -> bool {
        let mut run = 0;
        for b in text.bytes() {
            if b.is_ascii_hexdigit() {
                run += 1;
                if run >= MIN_SHORT_HASH_LEN {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }

    fn has_colon_hex_chain(text: &str) -> bool {
        let b = text.as_bytes();
        let mut groups = 0;
        let mut i = 0;
        while i + 2 < b.len() {
            if b[i].is_ascii_hexdigit() && b[i + 1].is_ascii_hexdigit() && b[i + 2] == b':' {
                groups += 1;
                if groups >= MIN_COLON_HEX_PAIRS {
                    return true;
                }
                i += 3;
            } else {
                groups = 0;
                i += 1;
            }
        }
        false
    }

    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        if !Self::may_hold_hex_hash(text)
            && !Self::has_colon_hex_chain(text)
            && !text.contains(SSH_SHA256_LABEL)
        {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        super::fold_matches(&mut result, &mut tokens, &SSH_SHA256_FINGERPRINT, |caps| {
            caps["longer"].is_empty().then(|| {
                (
                    Token::Hash(HashType::SHA256, caps["digest"].to_string()),
                    format!("{SSH_SHA256_LABEL}<HASH>"),
                )
            })
        });

        let ssh_md5 = (&*SSH_MD5_FINGERPRINT, HashType::MD5);
        let fixed_widths = FIXED_HEX_WIDTHS_LONGEST_FIRST
            .iter()
            .map(|(r, k)| (r, k.clone()));
        for (regex, hash_type) in std::iter::once(ssh_md5).chain(fixed_widths) {
            super::fold_matches(&mut result, &mut tokens, regex, |caps| {
                let m = &caps[0];
                let longer_chain =
                    caps.name("pair_before").is_some() || caps.name("pair_after").is_some();
                (!longer_chain && !Self::is_number(m)).then(|| {
                    (
                        Token::Hash(hash_type.clone(), m.to_string()),
                        "<HASH>".to_string(),
                    )
                })
            });
        }

        super::fold_matches(&mut result, &mut tokens, &DEVICE_TREE_NODE_ADDR, |caps| {
            Some((
                Token::Number(caps["addr"].to_string()),
                format!("<ADDR>{}", &caps["node"]),
            ))
        });

        super::fold_matches(&mut result, &mut tokens, &SHORT_HEX_RUN, |caps| {
            let m = &caps[0];
            Self::looks_like_hash(m).then(|| {
                (
                    Token::Hash(HashType::Generic { len: m.len() }, m.to_string()),
                    "<HASH>".to_string(),
                )
            })
        });

        (result, tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_then_digits_is_a_designator_interleaved_is_a_hash() {
        assert!(!HashDetector::looks_like_hash("ED25519"));
        assert!(!HashDetector::looks_like_hash("AES128"));
        assert!(HashDetector::looks_like_hash("F9009C60"));
        assert!(
            HashDetector::looks_like_hash("c420064480"),
            "a Go pointer starts with one letter, so it is not a designator"
        );
        assert!(HashDetector::looks_like_hash("3d7d8da"));
        assert!(HashDetector::looks_like_hash(
            "CE6BAEEF29234910A836A8567DB18141"
        ));
        let (r, _) = HashDetector::detect_and_replace(
            "ssh2: ED25519 SHA256:Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE",
        );
        assert_eq!(r, "ssh2: ED25519 SHA256:<HASH>");
    }

    #[test]
    fn a_fingerprint_folds_only_when_it_is_the_whole_value() {
        let digest_43 = &"Ab3/".repeat(11)[..43];
        let sha_long = format!("key SHA256:{digest_43}XYZ");
        let (r, tokens) = HashDetector::detect_and_replace(&sha_long);
        assert!(!r.contains("SHA256:<HASH>"), "{r}");
        assert!(
            !tokens
                .iter()
                .any(|t| matches!(t, Token::Hash(HashType::SHA256, _)))
        );
        let (r, _) = HashDetector::detect_and_replace(&format!("key SHA256:{digest_43}= ok"));
        assert_eq!(r, "key SHA256:<HASH> ok");
        let sixteen = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";
        let (r, _) = HashDetector::detect_and_replace(&format!("key {sixteen} ok"));
        assert_eq!(r, "key <HASH> ok");
        for chain in [format!("{sixteen}:ab"), format!("ab:{sixteen}")] {
            let (r, tokens) = HashDetector::detect_and_replace(&format!("key {chain} ok"));
            assert!(!r.contains("<HASH>:") && !r.contains(":<HASH>"), "{r}");
            assert!(
                !tokens
                    .iter()
                    .any(|t| matches!(t, Token::Hash(HashType::MD5, _))),
                "{r}"
            );
        }
    }

    #[test]
    fn test_md5_detection() {
        let text = "File hash: 5d41402abc4b2a76b9719d911017c592";
        let (result, tokens) = HashDetector::detect_and_replace(text);
        assert_eq!(result, "File hash: <HASH>");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Hash(HashType::MD5, _)));
    }

    #[test]
    fn test_sha256_detection() {
        let text = "SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
        let (result, tokens) = HashDetector::detect_and_replace(text);
        assert_eq!(result, "SHA256: <HASH>");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Hash(HashType::SHA256, _)));
    }

    #[test]
    fn a_ulid_with_non_hex_letters_is_not_a_hash() {
        let text = "commit 01K5HWDZG06WAPM00HHKC1MYZ4 merged";
        let (result, tokens) = HashDetector::detect_and_replace(text);
        assert_eq!(result, "commit 01K5HWDZG06WAPM00HHKC1MYZ4 merged");
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn test_multiple_hashes() {
        let text =
            "MD5: 5d41402abc4b2a76b9719d911017c592 SHA1: 356a192b7913b04c54574d18c28d46e6395428ab";
        let (result, tokens) = HashDetector::detect_and_replace(text);
        assert_eq!(result, "MD5: <HASH> SHA1: <HASH>");
        assert_eq!(tokens.len(), 2);
        assert!(
            matches!(tokens[0], Token::Hash(HashType::SHA1, _)),
            "SHA1 (40) is folded before MD5 (32): {tokens:?}"
        );
        assert!(matches!(tokens[1], Token::Hash(HashType::MD5, _)));
    }

    #[test]
    fn test_not_a_hash() {
        let text = "Port 8080 is open";
        let (result, tokens) = HashDetector::detect_and_replace(text);
        assert_eq!(result, "Port 8080 is open");
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn detect_sha512_128_chars() {
        let hash = "a".repeat(128);
        let text = format!("hash: {hash}");
        let (result, tokens) = HashDetector::detect_and_replace(&text);
        assert!(
            result.contains("<HASH>"),
            "SHA512 should be detected: {result}"
        );
        assert!(matches!(&tokens[0], Token::Hash(HashType::SHA512, _)));
    }

    #[test]
    fn detect_generic_56_chars() {
        let hash = "a".repeat(56);
        let text = format!("hash: {hash}");
        let (result, tokens) = HashDetector::detect_and_replace(&text);
        assert!(result.contains("<HASH>"), "56-char hash: {result}");
        assert!(matches!(
            &tokens[0],
            Token::Hash(HashType::Generic { len: 56 }, _)
        ));
    }

    #[test]
    fn detect_generic_48_chars() {
        let hash = "a".repeat(48);
        let text = format!("hash: {hash}");
        let (result, tokens) = HashDetector::detect_and_replace(&text);
        assert!(result.contains("<HASH>"), "48-char hash: {result}");
        assert!(matches!(
            &tokens[0],
            Token::Hash(HashType::Generic { len: 48 }, _)
        ));
    }

    #[test]
    fn detect_generic_24_chars() {
        let hash = "a".repeat(24);
        let text = format!("hash: {hash}");
        let (result, tokens) = HashDetector::detect_and_replace(&text);
        assert!(result.contains("<HASH>"), "24-char hash: {result}");
        assert!(matches!(
            &tokens[0],
            Token::Hash(HashType::Generic { len: 24 }, _)
        ));
    }

    #[test]
    fn detect_generic_16_chars() {
        let hash = "a".repeat(16);
        let text = format!("hash: {hash}");
        let (result, tokens) = HashDetector::detect_and_replace(&text);
        assert!(result.contains("<HASH>"), "16-char hash: {result}");
        assert!(matches!(
            &tokens[0],
            Token::Hash(HashType::Generic { len: 16 }, _)
        ));
    }

    #[test]
    fn hex_run_6_chars_false() {
        assert!(!HashDetector::may_hold_hex_hash("abcdef"));
    }

    #[test]
    fn hex_run_7_chars_true() {
        assert!(HashDetector::may_hold_hex_hash("abcdef0"));
    }

    #[test]
    fn hex_run_broken_by_non_hex() {
        assert!(!HashDetector::may_hold_hex_hash("abc_def"));
    }

    #[test]
    fn hex_run_empty() {
        assert!(!HashDetector::may_hold_hex_hash(""));
    }

    #[test]
    fn generic_hash_requires_digit_and_letter() {
        for (line, reason) in [
            ("epoch 1727676930 done", "pure digits are a number"),
            ("word defaced here", "pure hex letters are a word"),
        ] {
            let (result, tokens) = HashDetector::detect_and_replace(line);
            assert_eq!(result, line, "{reason}");
            assert!(tokens.is_empty(), "{reason}: {tokens:?}");
        }
        let (result, tokens) = HashDetector::detect_and_replace("commit a3f8b2c deployed");
        assert_eq!(
            result, "commit <HASH> deployed",
            "a short commit hash mixes digits and letters"
        );
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn ssh_fingerprints_are_one_hash() {
        let (r, t) =
            HashDetector::detect_and_replace("RSA 01:67:32:d9:b3:20:5d:2d:5f:b4:35:c5:a5:8b:0a:5e");
        assert_eq!(r, "RSA <HASH>");
        assert!(matches!(t[0], Token::Hash(HashType::MD5, _)));
        let (r, t) = HashDetector::detect_and_replace(
            "host SHA256:Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE",
        );
        assert_eq!(r, "host SHA256:<HASH>");
        assert!(matches!(t[0], Token::Hash(HashType::SHA256, _)));
        let (r, _) = HashDetector::detect_and_replace("mac 00:11:22:33:44:55");
        assert_eq!(
            r, "mac 00:11:22:33:44:55",
            "a MAC is six groups, not sixteen"
        );
    }

    #[test]
    fn a_sha512_digest_is_one_hash() {
        let digest = "0123456789abcdef".repeat(SHA512_HEX_LEN / 16);
        let (r, t) = HashDetector::detect_and_replace(&format!("sum {digest} ok"));
        assert_eq!(r, "sum <HASH> ok");
        assert_eq!(t, vec![Token::Hash(HashType::SHA512, digest)]);
    }

    #[test]
    fn the_fixed_widths_run_longest_first() {
        let widths: Vec<usize> = FIXED_HEX_WIDTHS_LONGEST_FIRST
            .iter()
            .map(|(_, kind)| match kind {
                HashType::MD5 => MD5_HEX_LEN,
                HashType::SHA1 => SHA1_HEX_LEN,
                HashType::SHA256 => SHA256_HEX_LEN,
                HashType::SHA512 => SHA512_HEX_LEN,
                HashType::Generic { len } => *len,
            })
            .collect();
        assert_eq!(widths, [128, 64, 56, 48, 40, 32, 24, 16]);
    }

    #[test]
    fn the_short_run_reads_the_line_after_the_fixed_widths_and_addresses() {
        let md5 = "5d41402abc4b2a76b9719d911017c592";
        let (_, t) = HashDetector::detect_and_replace(&format!("file {md5}"));
        assert_eq!(
            t,
            vec![Token::Hash(HashType::MD5, md5.to_string())],
            "a 32-char run is an MD5, not a short run of 32"
        );
        let (r, t) = HashDetector::detect_and_replace("gpio 7e200000.gpio: ready");
        assert_eq!(r, "gpio <ADDR>.gpio: ready");
        assert_eq!(
            t,
            vec![Token::Number("7e200000".to_string())],
            "a device-tree address is an address before the short run sees it"
        );
    }
}

#[cfg(test)]
mod shapes_2026_08_29 {
    use super::*;

    #[test]
    fn a_device_tree_node_address_is_an_address() {
        let (r, t) = HashDetector::detect_and_replace(
            "bcm2835-mbox 3f00b880.mailbox: enabled; window base 0x3f200000",
        );
        assert_eq!(
            r,
            "bcm2835-mbox <ADDR>.mailbox: enabled; window base 0x3f200000"
        );
        assert!(matches!(t[0], Token::Number(_)));
        let (r, _) = HashDetector::detect_and_replace("commit 3f00b880 x");
        assert_eq!(r, "commit <HASH> x");
    }

    #[test]
    fn a_run_of_digits_alone_is_not_a_hash() {
        let (r, t) = HashDetector::detect_and_replace("time_micros 1787969018585092 job 22162");
        assert_eq!(r, "time_micros 1787969018585092 job 22162");
        assert!(t.is_empty());
    }
}

#[cfg(test)]
mod designator_and_colon_chain_boundaries {
    use super::*;

    #[test]
    fn a_designator_is_under_twelve_characters_and_letters_then_digits() {
        assert!(!HashDetector::looks_like_hash("ED25519"));
        assert!(!HashDetector::looks_like_hash("AES128"));
        assert!(HashDetector::looks_like_hash("F9009C60"));
        assert!(
            HashDetector::looks_like_hash("AB1234567890"),
            "twelve characters is not a designator"
        );
        assert!(!HashDetector::looks_like_hash("AB123456789"), "eleven is");
    }

    #[test]
    fn a_colon_hex_chain_is_four_pairs_each_followed_by_a_colon() {
        assert!(HashDetector::has_colon_hex_chain("aa:bb:cc:dd:ee:ff"));
        assert!(HashDetector::has_colon_hex_chain("x 01:23:45:67:89 y"));
        for no in [
            "no chain here",
            "aaaaaaaa",
            "a::::b",
            "ax:ax:ax:ax:",
            "aa:bb:cc",
            "aa-bb-cc-dd-ee",
        ] {
            assert!(!HashDetector::has_colon_hex_chain(no), "{no}");
        }
    }
}
