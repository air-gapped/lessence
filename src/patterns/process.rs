use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// PID patterns: [12345], pid=12345, (12345)
static PID_BRACKET_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[pid=(\d+)\]|\[(\d+)\]").unwrap());
static PID_EQUALS_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bpid=(\d+)\b").unwrap());
static PID_PAREN_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\((\d+)\)").unwrap());

// Thread ID patterns
static THREAD_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bThread-(\d+)\b").unwrap());
static TID_HEX_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\btid=(0x[a-fA-F0-9]+)\b").unwrap());
static THREAD_NAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[thread:([a-zA-Z0-9_-]+)\]").unwrap());

// Generic numeric ID in various contexts
static NUMERIC_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bid=(\d+)\b").unwrap());

pub struct ProcessDetector;

impl ProcessDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        // PID in brackets like [pid=12345] or [12345]
        for cap in PID_BRACKET_REGEX.captures_iter(text) {
            if let Some(pid_match) = cap.get(1).or_else(|| cap.get(2)) {
                let pid_str = pid_match.as_str();
                if let Ok(pid) = pid_str.parse::<u32>()
                    && Self::is_likely_pid(pid)
                {
                    tokens.push(Token::Pid(pid));
                }
            }
        }
        result = PID_BRACKET_REGEX
            .replace_all(&result, "[pid=<PID>]")
            .to_string();

        // PID with equals like pid=12345
        for cap in PID_EQUALS_REGEX.captures_iter(&result) {
            let pid_str = cap.get(1).unwrap().as_str();
            if let Ok(pid) = pid_str.parse::<u32>()
                && Self::is_likely_pid(pid)
                && !tokens
                    .iter()
                    .any(|t| matches!(t, Token::Pid(p) if *p == pid))
            {
                tokens.push(Token::Pid(pid));
            }
        }
        result = PID_EQUALS_REGEX
            .replace_all(&result, "pid=<PID>")
            .to_string();

        // Thread-specific patterns
        for cap in THREAD_ID_REGEX.captures_iter(&result) {
            let thread_str = cap.get(1).unwrap().as_str();
            tokens.push(Token::ThreadID(format!("Thread-{thread_str}")));
        }
        result = THREAD_ID_REGEX
            .replace_all(&result, "Thread-<TID>")
            .to_string();

        for cap in TID_HEX_REGEX.captures_iter(&result) {
            let tid_str = cap.get(1).unwrap().as_str();
            tokens.push(Token::ThreadID(tid_str.to_string()));
        }
        result = TID_HEX_REGEX.replace_all(&result, "tid=<TID>").to_string();

        for cap in THREAD_NAME_REGEX.captures_iter(&result) {
            let thread_name = cap.get(1).unwrap().as_str();
            tokens.push(Token::ThreadID(thread_name.to_string()));
        }
        result = THREAD_NAME_REGEX
            .replace_all(&result, "[thread:<TID>]")
            .to_string();

        // Generic numeric IDs
        for cap in NUMERIC_ID_REGEX.captures_iter(&result) {
            let id_str = cap.get(1).unwrap().as_str();
            if let Ok(id) = id_str.parse::<u32>()
                && Self::is_likely_pid(id)
                && !tokens
                    .iter()
                    .any(|t| matches!(t, Token::Pid(p) if *p == id))
            {
                tokens.push(Token::Pid(id));
            }
        }
        result = NUMERIC_ID_REGEX
            .replace_all(&result, "id=<PID>")
            .to_string();

        // Handle PIDs in parentheses (but be careful not to match ports or other numbers)
        for cap in PID_PAREN_REGEX.captures_iter(&result) {
            let pid_str = cap.get(1).unwrap().as_str();
            if let Ok(pid) = pid_str.parse::<u32>()
                && Self::is_likely_pid(pid)
                && !tokens
                    .iter()
                    .any(|t| matches!(t, Token::Pid(p) if *p == pid))
            {
                tokens.push(Token::Pid(pid));
            }
        }
        result = PID_PAREN_REGEX.replace_all(&result, "(<PID>)").to_string();

        (result, tokens)
    }

    fn is_likely_pid(pid: u32) -> bool {
        // PIDs are typically in a reasonable range
        // Avoid very small numbers that are likely not PIDs
        // and very large numbers that exceed typical OS limits
        (1..=4_194_304).contains(&pid) // 2^22, typical Linux max PID
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_bracket_detection() {
        let text = "[pid=12345] Process started";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(result, "[pid=<PID>] Process started");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Pid(12345)));
    }

    #[test]
    fn test_pid_simple_bracket_detection() {
        let text = "[12345] Error occurred";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(result, "[pid=<PID>] Error occurred");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Pid(12345)));
    }

    #[test]
    fn test_thread_id_detection() {
        let text = "Thread-42 started execution";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(result, "Thread-<TID> started execution");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::ThreadID(_)));
    }

    #[test]
    fn test_tid_hex_detection() {
        let text = "tid=0x7f8a9c001700 mutex acquired";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(result, "tid=<TID> mutex acquired");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::ThreadID(_)));
    }

    #[test]
    fn test_invalid_pid_ranges() {
        let text = "Error code: 0";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(result, "Error code: 0"); // Should not replace 0 as PID
        assert_eq!(tokens.len(), 0);
    }

    // ---- is_likely_pid: boundary tests ----

    #[test]
    fn pid_zero_rejected() {
        assert!(!ProcessDetector::is_likely_pid(0));
    }

    #[test]
    fn pid_one_accepted() {
        assert!(ProcessDetector::is_likely_pid(1));
    }

    #[test]
    fn pid_max_accepted() {
        assert!(ProcessDetector::is_likely_pid(4_194_304));
    }

    #[test]
    fn pid_over_max_rejected() {
        assert!(!ProcessDetector::is_likely_pid(4_194_305));
    }
}
