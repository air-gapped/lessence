use super::{AnchorSentinel, Token};
use regex::Regex;
use std::sync::LazyLock;

const MAX_LINUX_PID: u32 = 4_194_304;

static SYSLOG_PID_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?P<tag>[A-Za-z0-9_./-])\[(?P<pid>\d+)\]:").unwrap());
static LEADING_PID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\[(?P<pid>\d+)\]").unwrap());
static PID_FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[pid=(?P<pid>\d+)\]").unwrap());
static PID_EQUALS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bpid=(?P<pid>\d+)\b").unwrap());
static PROCESS_NAME_PAREN_PID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?P<process>[a-zA-Z][a-zA-Z0-9_.-]*)\((?P<pid>\d+)\)").unwrap()
});

static THREAD_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bThread-(\d+)\b").unwrap());
static TID_HEX_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\btid=(0x[a-fA-F0-9]+)\b").unwrap());
static THREAD_NAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[thread:([a-zA-Z0-9_-]+)\]").unwrap());

const KLOG_GO_CALL_SITE: &str = r"[A-Za-z0-9_]+\.go:<LINE>";
const FOLDED_KLOG_CALL_SITE_END: &str = ".go:<LINE>]";

static KLOG_PID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?P<timestamp><TIMESTAMP>\s+)(?P<pid>\d+)(?P<call_site> (?:{KLOG_GO_CALL_SITE}|{}\d+\x00)\])",
        regex::escape(AnchorSentinel::KlogCallSiteVisibleToPid.start())
    ))
    .unwrap()
});

pub struct ProcessDetector;

impl ProcessDetector {
    pub fn detect_and_replace(text: &str) -> (String, Vec<Token>) {
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        if result.contains(FOLDED_KLOG_CALL_SITE_END)
            || result.contains(AnchorSentinel::KlogCallSiteVisibleToPid.start())
        {
            super::fold_matches(&mut result, &mut tokens, &KLOG_PID_REGEX, |caps| {
                Some((
                    Token::Pid(caps["pid"].parse().unwrap_or(0)),
                    format!("{}<PID>{}", &caps["timestamp"], &caps["call_site"]),
                ))
            });
        }

        for (regex, form) in [
            (&*SYSLOG_PID_TAG, "${tag}[<PID>]:"),
            (&*LEADING_PID, "[<PID>]"),
            (&*PID_FIELD, "[pid=<PID>]"),
        ] {
            super::fold_matches(&mut result, &mut tokens, regex, |caps| {
                let pid = Self::likely_pid(&caps["pid"])?;
                let mut replacement = String::new();
                caps.expand(form, &mut replacement);
                Some((Token::Pid(pid), replacement))
            });
        }

        Self::fold_pids_once(&mut result, &mut tokens, &PID_EQUALS_REGEX, |_| {
            "pid=<PID>".to_string()
        });

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

        Self::fold_pids_once(&mut result, &mut tokens, &PROCESS_NAME_PAREN_PID, |caps| {
            format!("{}(<PID>)", &caps["process"])
        });

        (result, tokens)
    }

    fn fold_pids_once(
        text: &mut String,
        tokens: &mut Vec<Token>,
        regex: &Regex,
        replacement: impl Fn(&regex::Captures) -> String,
    ) {
        let mut found = Vec::new();
        super::fold_matches(text, &mut found, regex, |caps| {
            let pid = Self::likely_pid(&caps["pid"])?;
            Some((Token::Pid(pid), replacement(caps)))
        });
        for token in found {
            if !tokens.contains(&token) {
                tokens.push(token);
            }
        }
    }

    fn likely_pid(digits: &str) -> Option<u32> {
        digits.parse().ok().filter(|&pid| Self::is_likely_pid(pid))
    }

    fn is_likely_pid(pid: u32) -> bool {
        (1..=MAX_LINUX_PID).contains(&pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn the_klog_pid_column_needs_the_timestamp_and_call_site_already_folded() {
        for (line, missing) in [
            (
                "I1102 09:10:00.000004    3310 mounter.go:<LINE>] done",
                "timestamp",
            ),
            ("<TIMESTAMP>    3310 mounter.go:51] done", "call site"),
        ] {
            let (r, t) = ProcessDetector::detect_and_replace(line);
            assert_eq!(r, line, "no folded {missing}");
            assert!(t.is_empty(), "no folded {missing}: {t:?}");
        }
    }

    #[test]
    fn only_a_klog_call_site_sentinel_reads_as_a_call_site() {
        let line = |sentinel: AnchorSentinel| {
            ProcessDetector::detect_and_replace(&format!(
                "<TIMESTAMP>    3310 {}] done",
                sentinel.text(4)
            ))
            .0
        };
        assert_eq!(
            line(AnchorSentinel::KlogCallSiteVisibleToPid),
            format!(
                "<TIMESTAMP>    <PID> {}] done",
                AnchorSentinel::KlogCallSiteVisibleToPid.text(4)
            )
        );
        assert_eq!(
            line(AnchorSentinel::OpaqueToDetectors),
            format!(
                "<TIMESTAMP>    3310 {}] done",
                AnchorSentinel::OpaqueToDetectors.text(4)
            )
        );
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
    fn zero_is_not_a_pid() {
        let text = "Error code: 0";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(result, "Error code: 0");
        assert_eq!(tokens.len(), 0);
    }

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
        assert_eq!(MAX_LINUX_PID, 1 << 22);
        assert!(ProcessDetector::is_likely_pid(MAX_LINUX_PID));
    }

    #[test]
    fn pid_over_max_rejected() {
        assert!(!ProcessDetector::is_likely_pid(MAX_LINUX_PID + 1));
    }

    #[test]
    fn pid_dedup_no_duplicate_tokens() {
        let text = "[pid=12345] restart with pid=12345 active";
        let (_result, tokens) = ProcessDetector::detect_and_replace(text);
        let pid_count = tokens
            .iter()
            .filter(|t| matches!(t, Token::Pid(12345)))
            .count();
        assert_eq!(
            pid_count, 1,
            "one pid in bracket and equals forms gives one token, got {pid_count}"
        );
    }

    #[test]
    fn an_id_field_is_not_a_pid() {
        let text = "[pid=12345] and id=12345 duplicate";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(result, "[pid=<PID>] and id=12345 duplicate");
        assert_eq!(
            tokens,
            vec![Token::Pid(12345)],
            "only the pid field is a pid; id= stays"
        );
    }

    #[test]
    fn paren_pid_dedup_no_duplicate_tokens() {
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
        let text = "retry attempt (3) failed, exiting with code (137) after (1024) bytes";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(
            result, text,
            "a number in parentheses with no name attached is a count"
        );
        assert!(tokens.is_empty(), "no PID tokens expected, got {tokens:?}");
    }

    #[test]
    fn paren_pid_out_of_range_left_alone() {
        let text = "worker(0) and worker(9999999) idle";
        let (result, tokens) = ProcessDetector::detect_and_replace(text);
        assert_eq!(
            result, text,
            "0 and anything over 2^22 fail is_likely_pid, and the text stays"
        );
        assert!(tokens.is_empty(), "no PID tokens expected, got {tokens:?}");
    }

    #[test]
    fn every_pid_shape_leaves_a_non_pid_alone() {
        for text in [
            "worker[0]: queue drained",
            "[0] boot",
            "probe [pid=0] gone",
            "job pid=0 exited",
            "worker[9999999]: busy",
        ] {
            let (result, tokens) = ProcessDetector::detect_and_replace(text);
            assert_eq!(result, text);
            assert!(tokens.is_empty(), "{text}: {tokens:?}");
        }
        let (result, tokens) =
            ProcessDetector::detect_and_replace("sshd[1234]: [77] [pid=88] pid=99 x");
        assert_eq!(result, "sshd[<PID>]: [77] [pid=<PID>] pid=<PID> x");
        assert_eq!(
            tokens.len(),
            result.matches("<PID>").count(),
            "every <PID> has a token behind it: {tokens:?}"
        );
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
