use super::Token;
use regex::Regex;
use std::sync::LazyLock;

// A pid in brackets: the syslog tag `sshd[1234]:`, a line-leading `[1234]`,
// or an explicit `[pid=1234]`. Any other `word[N]` — `slot[2]`, `sta_cnt[5]`,
// `GENPLL[5]`, `round[1]`, `disk[0]`, `Total BSS[35]`, `FWLOG: [119464107]`
// — is an index or a count and stays what it is.
static PID_TAG_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z0-9_./-])\[(\d+)\]:").unwrap());
static PID_LEADING_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\[(\d+)\]").unwrap());
static PID_FIELD_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[pid=(\d+)\]").unwrap());
static PID_EQUALS_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bpid=(\d+)\b").unwrap());
// Requires a process name attached to the parens — sshd(1234), nginx(42) —
// so free-standing counts like "retry attempt (3)" are left alone.
static PID_PAREN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([a-zA-Z][a-zA-Z0-9_.-]*)\((\d+)\)").unwrap());

// Thread ID patterns
static THREAD_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bThread-(\d+)\b").unwrap());
static TID_HEX_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\btid=(0x[a-fA-F0-9]+)\b").unwrap());
static THREAD_NAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[thread:([a-zA-Z0-9_-]+)\]").unwrap());

// The klog header's pid column: `E0910 00:02:39.914326       1 status.go:71]`.
// By the time this runs the timestamp and the call site are placeholders;
// the number between them is a pid whatever its digit count (`1` in a
// container, `114343` on a node), so the slot says so. `\0K<index>\0`
// is the normalizer's protected klog call-site sentinel; it carries the
// same grammar while the original site is kept for visible rendering.
static KLOG_PID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(<TIMESTAMP>\s+)(\d+)( (?:[A-Za-z0-9_]+\.go:<LINE>|\x00K\d+\x00)\])").unwrap()
});

pub struct ProcessDetector;

impl ProcessDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        if result.contains(".go:<LINE>]") || result.contains("\0K") {
            super::fold_matches(&mut result, &mut tokens, &KLOG_PID_REGEX, |caps| {
                Some((
                    Token::Pid(caps[2].parse().unwrap_or(0)),
                    format!("{}<PID>{}", &caps[1], &caps[3]),
                ))
            });
        }

        // A placeholder replaces the number and nothing else: `sshd[1234]:`
        // becomes `sshd[<PID>]:`; only an input that said `pid=` keeps it.
        for (regex, group, form) in [
            (&*PID_TAG_REGEX, 2, "${1}[<PID>]:"),
            (&*PID_LEADING_REGEX, 1, "[<PID>]"),
            (&*PID_FIELD_REGEX, 1, "[pid=<PID>]"),
        ] {
            for cap in regex.captures_iter(&result) {
                if let Ok(pid) = cap[group].parse::<u32>()
                    && Self::is_likely_pid(pid)
                {
                    tokens.push(Token::Pid(pid));
                }
            }
            result = regex.replace_all(&result, form).to_string();
        }

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

        // Handle process(1234)-style PIDs. The token push and the text
        // replacement share the is_likely_pid gate, so a rejected match is
        // left untouched instead of being rewritten anyway.
        for cap in PID_PAREN_REGEX.captures_iter(&result) {
            let pid_str = cap.get(2).unwrap().as_str();
            if let Ok(pid) = pid_str.parse::<u32>()
                && Self::is_likely_pid(pid)
                && !tokens
                    .iter()
                    .any(|t| matches!(t, Token::Pid(p) if *p == pid))
            {
                tokens.push(Token::Pid(pid));
            }
        }
        result = PID_PAREN_REGEX
            .replace_all(&result, |caps: &regex::Captures| {
                match caps[2].parse::<u32>() {
                    Ok(pid) if Self::is_likely_pid(pid) => format!("{}(<PID>)", &caps[1]),
                    _ => caps[0].to_string(),
                }
            })
            .to_string();

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

    /// The klog pid column is a pid whether it reads `1` or `114343`.
    #[test]
    fn klog_pid_column_is_a_pid_whatever_its_digits() {
        for n in ["1", "114343"] {
            let (r, t) = ProcessDetector::detect_and_replace(&format!(
                "<TIMESTAMP>       {n} status.go:<LINE>] \"Unhandled Error\""
            ));
            assert_eq!(
                r,
                "<TIMESTAMP>       <PID> status.go:<LINE>] \"Unhandled Error\""
            );
            assert!(t.iter().any(|t| matches!(t, Token::Pid(_))));
        }
        let (r, _) = ProcessDetector::detect_and_replace("<TIMESTAMP> 1 status.go:<LINE>] x 1 y");
        assert_eq!(r, "<TIMESTAMP> <PID> status.go:<LINE>] x 1 y");
    }

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
        assert_eq!(result, "[<PID>] Error occurred");
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

    // ---- Mutant-killing: dedup checks (delete ! on lines 49, 88, 104) ----

    #[test]
    fn pid_dedup_no_duplicate_tokens() {
        // Kills mutant: `!tokens.iter().any(...)` → `tokens.iter().any(...)`
        // Input has pid=12345 appearing in BOTH bracket and equals forms.
        // The dedup check should prevent the same PID from being added twice.
        let text = "[pid=12345] restart with pid=12345 active";
        let (_result, tokens) = ProcessDetector::detect_and_replace(text);
        let pid_count = tokens
            .iter()
            .filter(|t| matches!(t, Token::Pid(12345)))
            .count();
        assert_eq!(
            pid_count, 1,
            "PID 12345 should appear exactly once (dedup), got {pid_count}"
        );
    }

    #[test]
    fn numeric_id_dedup_no_duplicate_tokens() {
        // The generic numeric ID pattern (id=NNN) should not duplicate PIDs
        // that were already found by the bracket or equals patterns.
        let text = "[pid=12345] and id=12345 duplicate";
        let (_result, tokens) = ProcessDetector::detect_and_replace(text);
        let pid_count = tokens
            .iter()
            .filter(|t| matches!(t, Token::Pid(12345)))
            .count();
        assert_eq!(
            pid_count, 1,
            "PID 12345 should appear exactly once across patterns, got {pid_count}"
        );
    }

    #[test]
    fn paren_pid_dedup_no_duplicate_tokens() {
        // The parentheses PID pattern (NNN) should not duplicate PIDs.
        let text = "pid=12345 process (12345) running";
        let (_result, tokens) = ProcessDetector::detect_and_replace(text);
        let pid_count = tokens
            .iter()
            .filter(|t| matches!(t, Token::Pid(12345)))
            .count();
        assert_eq!(
            pid_count, 1,
            "PID 12345 should appear exactly once (paren dedup), got {pid_count}"
        );
    }

    #[test]
    fn paren_pid_requires_attached_process_name() {
        let text = "sshd(8423) accepted connection";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(result, "sshd(<PID>) accepted connection");
        assert!(tokens.iter().any(|t| matches!(t, Token::Pid(8423))));
    }

    #[test]
    fn paren_numbers_in_prose_left_alone() {
        // Free-standing parenthesized numbers are counts, not PIDs.
        let text = "retry attempt (3) failed, exiting with code (137) after (1024) bytes";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(result, text);
        assert!(tokens.is_empty(), "no PID tokens expected, got {tokens:?}");
    }

    #[test]
    fn paren_pid_out_of_range_left_alone() {
        // 0 and > 2^22 fail is_likely_pid — text must stay untouched too.
        let text = "worker(0) and worker(9999999) idle";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(result, text);
        assert!(tokens.is_empty(), "no PID tokens expected, got {tokens:?}");
    }
}

#[cfg(test)]
mod shapes_2026_08_29 {
    use super::*;

    #[test]
    fn a_pid_is_a_tag_a_leading_bracket_or_a_field_and_nothing_else() {
        let (r, t) = ProcessDetector::detect_and_replace(
            "cfgmtd[1591]: cfgmtd_do_write(): Write new cfg to slot[2] as BACKUP",
        );
        assert_eq!(
            r,
            "cfgmtd[<PID>]: cfgmtd_do_write(): Write new cfg to slot[2] as BACKUP"
        );
        assert_eq!(t.len(), 1);
        for line in [
            "rai0: total mc2uc sta_cnt[5] pending[0] unknown_free[0] accu[0] !",
            "GENPLL[5] mdiv=40",
            "got SATA disk[0]",
            "FWLOG: [119464107] WAL_DBGID_DEV_RESET",
            "IPVS: Creating netns size=2104 id=0",
            "MASTER MODE enabled (user request from 'id=10 addr=x')",
        ] {
            let (r, t) = ProcessDetector::detect_and_replace(line);
            assert_eq!(r, line, "{line}");
            assert!(t.is_empty(), "{line}");
        }
        let (r, _) = ProcessDetector::detect_and_replace("[12345] Error occurred");
        assert_eq!(r, "[<PID>] Error occurred");
        let (r, _) = ProcessDetector::detect_and_replace("x [pid=12345] y");
        assert_eq!(r, "x [pid=<PID>] y");
    }
}
