use super::{HashType, Token};
use regex::Regex;
use std::sync::LazyLock;

// MD5: 32 hex characters
static MD5_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap());

// SHA1: 40 hex characters
static SHA1_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap());

// SHA256: 64 hex characters
static SHA256_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap());

// SHA512: 128 hex characters
static SHA512_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[a-fA-F0-9]{128}\b").unwrap());

// A device-tree node address: eight hex digits glued to a dotted node
// name — `3f00b880.mailbox`, `3f200000.gpio` — the same value the kernel
// also prints as `0x3f200000`, and an address in both forms.
static DT_ADDR_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([0-9a-f]{8})(\.[a-z])").unwrap());

// Git commit hash: 7-40 hex characters (but not overlapping with above)
static GIT_HASH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[a-fA-F0-9]{7,39}\b").unwrap());

// Generic hex strings of notable lengths (avoid short ones that might be numbers)
static HEX_16_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[a-fA-F0-9]{16}\b").unwrap());
static HEX_24_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[a-fA-F0-9]{24}\b").unwrap());
static HEX_48_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[a-fA-F0-9]{48}\b").unwrap());
static HEX_56_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[a-fA-F0-9]{56}\b").unwrap());

// MD5 fingerprint as ssh prints it: 16 colon-separated hex pairs.
static MD5_COLON_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:[a-fA-F0-9]{2}:){15}[a-fA-F0-9]{2}\b").unwrap());

// SHA256 fingerprint as ssh prints it: the label and 43 base64 characters.
static SHA256_B64_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bSHA256:[A-Za-z0-9+/]{43}=?").unwrap());

pub struct HashDetector;

impl HashDetector {
    /// A variable-length hex run only counts as a hash when it mixes
    /// digits and letters — pure digits are numbers, pure letters are
    /// usually ordinary words.
    fn looks_like_hash(s: &str) -> bool {
        let has_digit = s.bytes().any(|b| b.is_ascii_digit());
        let has_letter = s.bytes().any(|b| b.is_ascii_alphabetic());
        // Letters then digits and nothing else — `ED25519`, `AES128` — is a
        // designator, not a hash; a hash interleaves them (`F9009C60`).
        let designator = s.len() < 12 && {
            let letters = s.bytes().take_while(u8::is_ascii_alphabetic).count();
            // two letters at least: `c420064480` is a Go pointer
            letters >= 2 && s.bytes().skip(letters).all(|b| b.is_ascii_digit())
        };
        has_digit && has_letter && !designator
    }

    /// Quick check: does the text contain a run of 7+ hex characters?
    /// If not, no hash/commit SHA can exist — skip all 9 regex scans.
    fn has_hex_run(text: &str) -> bool {
        let mut run = 0u32;
        for b in text.bytes() {
            if b.is_ascii_hexdigit() {
                run += 1;
                if run >= 7 {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }

    /// Four `hh:` groups in a row: a colon-separated fingerprint (or a MAC).
    fn has_colon_hex_chain(text: &str) -> bool {
        let b = text.as_bytes();
        let mut groups = 0;
        let mut i = 0;
        while i + 2 < b.len() {
            if b[i].is_ascii_hexdigit() && b[i + 1].is_ascii_hexdigit() && b[i + 2] == b':' {
                groups += 1;
                if groups >= 4 {
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
        if !Self::has_hex_run(text) && !Self::has_colon_hex_chain(text) && !text.contains("SHA256:")
        {
            return (text.to_string(), Vec::new());
        }

        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // ssh fingerprints: the label is the input's, the digest is the token.
        for found in SHA256_B64_REGEX.find_iter(&result) {
            tokens.push(Token::Hash(
                HashType::SHA256,
                found.as_str()["SHA256:".len()..].to_string(),
            ));
        }
        result = SHA256_B64_REGEX
            .replace_all(&result, "SHA256:<HASH>")
            .to_string();

        // Fixed-width hex runs, longest first so a SHA-512 is not eaten as
        // eight 16-char generics. Each regex scans for tokens, then folds its
        // own matches away before the next, shorter one runs.
        for (regex, hash_type) in [
            (&*MD5_COLON_REGEX, HashType::MD5),
            (&*SHA512_REGEX, HashType::SHA512),
            (&*SHA256_REGEX, HashType::SHA256),
            (&*HEX_56_REGEX, HashType::Generic(56)),
            (&*HEX_48_REGEX, HashType::Generic(48)),
            (&*SHA1_REGEX, HashType::SHA1),
            (&*MD5_REGEX, HashType::MD5),
            (&*HEX_24_REGEX, HashType::Generic(24)),
            (&*HEX_16_REGEX, HashType::Generic(16)),
        ] {
            // A run of the right width made of digits alone is a number —
            // `time_micros: 1787969018585092` is an epoch, not a hash.
            let is_number = |m: &str| m.bytes().all(|b| b.is_ascii_digit());
            for found in regex.find_iter(&result) {
                if !is_number(found.as_str()) {
                    tokens.push(Token::Hash(hash_type.clone(), found.as_str().to_string()));
                }
            }
            result = regex
                .replace_all(&result, |caps: &regex::Captures| {
                    let m = caps.get(0).unwrap().as_str();
                    if is_number(m) {
                        m.to_string()
                    } else {
                        "<HASH>".to_string()
                    }
                })
                .to_string();
        }

        for cap in DT_ADDR_REGEX.captures_iter(&result) {
            tokens.push(Token::Number(cap[1].to_string()));
        }
        result = DT_ADDR_REGEX.replace_all(&result, "<ADDR>${2}").to_string();

        // Git commit hashes (7-39 chars, after longer ones are processed).
        // Require both a digit and a letter: pure digits are numbers
        // (epoch timestamps, counters — left for the number detector) and
        // pure letters are usually words that happen to be hex (defaced,
        // beefed). The gate applies to token AND replacement.
        for cap in GIT_HASH_REGEX.find_iter(&result) {
            let hash_str = cap.as_str();
            if Self::looks_like_hash(hash_str) {
                tokens.push(Token::Hash(
                    HashType::Generic(hash_str.len()),
                    hash_str.to_string(),
                ));
            }
        }
        result = GIT_HASH_REGEX
            .replace_all(&result, |caps: &regex::Captures| {
                let m = caps.get(0).unwrap().as_str();
                if Self::looks_like_hash(m) {
                    "<HASH>".to_string()
                } else {
                    m.to_string()
                }
            })
            .to_string();

        (result, tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Letters followed by digits is a designator (ED25519), not a short sha;
    /// an interleaved run (F9009C60, an LSN) still is one.
    #[test]
    fn upper_case_short_hex_is_a_word() {
        assert!(!HashDetector::looks_like_hash("ED25519"));
        assert!(!HashDetector::looks_like_hash("AES128"));
        assert!(HashDetector::looks_like_hash("F9009C60"));
        assert!(HashDetector::looks_like_hash("c420064480"));
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
    fn test_git_commit_detection() {
        // 01K5HWDZG06WAPM00HHKC1MYZ4 contains non-hex chars (K, W, Z, P, M, Y) so
        // it is not detected as a hash by any hex regex
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
        // SHA1 (40 chars) is processed before MD5 (32 chars) in the detection order
        assert!(matches!(tokens[0], Token::Hash(HashType::SHA1, _)));
        assert!(matches!(tokens[1], Token::Hash(HashType::MD5, _)));
    }

    #[test]
    fn test_not_a_hash() {
        let text = "Port 8080 is open";
        let (result, tokens) = HashDetector::detect_and_replace(text);
        assert_eq!(result, "Port 8080 is open");
        assert_eq!(tokens.len(), 0);
    }

    // ---- Coverage: untested hash lengths ----

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
        assert!(matches!(&tokens[0], Token::Hash(HashType::Generic(56), _)));
    }

    #[test]
    fn detect_generic_48_chars() {
        let hash = "a".repeat(48);
        let text = format!("hash: {hash}");
        let (result, tokens) = HashDetector::detect_and_replace(&text);
        assert!(result.contains("<HASH>"), "48-char hash: {result}");
        assert!(matches!(&tokens[0], Token::Hash(HashType::Generic(48), _)));
    }

    #[test]
    fn detect_generic_24_chars() {
        let hash = "a".repeat(24);
        let text = format!("hash: {hash}");
        let (result, tokens) = HashDetector::detect_and_replace(&text);
        assert!(result.contains("<HASH>"), "24-char hash: {result}");
        assert!(matches!(&tokens[0], Token::Hash(HashType::Generic(24), _)));
    }

    #[test]
    fn detect_generic_16_chars() {
        let hash = "a".repeat(16);
        let text = format!("hash: {hash}");
        let (result, tokens) = HashDetector::detect_and_replace(&text);
        assert!(result.contains("<HASH>"), "16-char hash: {result}");
        assert!(matches!(&tokens[0], Token::Hash(HashType::Generic(16), _)));
    }

    // ---- has_hex_run: boundary tests ----

    #[test]
    fn hex_run_6_chars_false() {
        assert!(!HashDetector::has_hex_run("abcdef"));
    }

    #[test]
    fn hex_run_7_chars_true() {
        assert!(HashDetector::has_hex_run("abcdef0"));
    }

    #[test]
    fn hex_run_broken_by_non_hex() {
        assert!(!HashDetector::has_hex_run("abc_def"));
    }

    #[test]
    fn hex_run_empty() {
        assert!(!HashDetector::has_hex_run(""));
    }

    #[test]
    fn generic_hash_requires_digit_and_letter() {
        // Pure digits (epoch timestamps, counters) and pure-alpha hex
        // words must pass through untouched.
        for line in ["epoch 1727676930 done", "word defaced here"] {
            let (result, tokens) = HashDetector::detect_and_replace(line);
            assert_eq!(result, line);
            assert!(
                tokens.is_empty(),
                "no hash expected in {line:?}: {tokens:?}"
            );
        }
        // A real short commit hash mixes both.
        let (result, tokens) = HashDetector::detect_and_replace("commit a3f8b2c deployed");
        assert_eq!(result, "commit <HASH> deployed");
        assert_eq!(tokens.len(), 1);
    }

    /// An ssh fingerprint is one digest, whichever way ssh prints it.
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
        // a MAC is six groups, not sixteen
        let (r, _) = HashDetector::detect_and_replace("mac 00:11:22:33:44:55");
        assert_eq!(r, "mac 00:11:22:33:44:55");
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

/// Boundaries of the hash-shape and colon-chain checks (lessence-e8v
/// survivors 58, 85-89).
#[cfg(test)]
mod e8v_shapes_2026_09_18 {
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
