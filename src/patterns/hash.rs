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

pub struct HashDetector;

impl HashDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // Process in order of specificity (longest first to avoid conflicts)

        // SHA512 (128 chars)
        for cap in SHA512_REGEX.find_iter(text) {
            let hash_str = cap.as_str();
            tokens.push(Token::Hash(HashType::SHA512, hash_str.to_string()));
        }
        result = SHA512_REGEX.replace_all(&result, "<HASH>").to_string();

        // SHA256 (64 chars)
        for cap in SHA256_REGEX.find_iter(&result) {
            let hash_str = cap.as_str();
            tokens.push(Token::Hash(HashType::SHA256, hash_str.to_string()));
        }
        result = SHA256_REGEX.replace_all(&result, "<HASH>").to_string();

        // Generic 56-char hex
        for cap in HEX_56_REGEX.find_iter(&result) {
            let hash_str = cap.as_str();
            tokens.push(Token::Hash(HashType::Generic(56), hash_str.to_string()));
        }
        result = HEX_56_REGEX.replace_all(&result, "<HASH>").to_string();

        // Generic 48-char hex
        for cap in HEX_48_REGEX.find_iter(&result) {
            let hash_str = cap.as_str();
            tokens.push(Token::Hash(HashType::Generic(48), hash_str.to_string()));
        }
        result = HEX_48_REGEX.replace_all(&result, "<HASH>").to_string();

        // SHA1 (40 chars)
        for cap in SHA1_REGEX.find_iter(&result) {
            let hash_str = cap.as_str();
            tokens.push(Token::Hash(HashType::SHA1, hash_str.to_string()));
        }
        result = SHA1_REGEX.replace_all(&result, "<HASH>").to_string();

        // MD5 (32 chars)
        for cap in MD5_REGEX.find_iter(&result) {
            let hash_str = cap.as_str();
            tokens.push(Token::Hash(HashType::MD5, hash_str.to_string()));
        }
        result = MD5_REGEX.replace_all(&result, "<HASH>").to_string();

        // Generic 24-char hex
        for cap in HEX_24_REGEX.find_iter(&result) {
            let hash_str = cap.as_str();
            tokens.push(Token::Hash(HashType::Generic(24), hash_str.to_string()));
        }
        result = HEX_24_REGEX.replace_all(&result, "<HASH>").to_string();

        // Generic 16-char hex
        for cap in HEX_16_REGEX.find_iter(&result) {
            let hash_str = cap.as_str();
            tokens.push(Token::Hash(HashType::Generic(16), hash_str.to_string()));
        }
        result = HEX_16_REGEX.replace_all(&result, "<HASH>").to_string();

        // Git commit hashes (7-39 chars, after longer ones are processed)
        for cap in GIT_HASH_REGEX.find_iter(&result) {
            let hash_str = cap.as_str();
            tokens.push(Token::Hash(
                HashType::Generic(hash_str.len()),
                hash_str.to_string(),
            ));
        }
        result = GIT_HASH_REGEX.replace_all(&result, "<HASH>").to_string();

        (result, tokens)
    }

    #[allow(dead_code)]
    pub fn is_likely_hash(text: &str) -> bool {
        if text.len() < 7 {
            return false;
        }

        // Check if it's all hex characters
        text.chars().all(|c| c.is_ascii_hexdigit())
    }

    #[allow(dead_code)]
    pub fn classify_hash_type(length: usize) -> HashType {
        match length {
            32 => HashType::MD5,
            40 => HashType::SHA1,
            64 => HashType::SHA256,
            128 => HashType::SHA512,
            _ => HashType::Generic(length),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
