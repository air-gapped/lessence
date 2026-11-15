#[test]
fn test_help_text_contains_lessence_branding() {
    let output = crate::common::lessence()
        .arg("--help")
        .output()
        .expect("lessence binary should exist");

    assert!(
        output.status.success(),
        "lessence --help should execute successfully"
    );

    let help_text = String::from_utf8_lossy(&output.stdout);

    assert!(
        help_text.to_lowercase().contains("lessence"),
        "Help text should contain 'lessence' branding, got: {help_text}"
    );

    assert!(
        !help_text.to_lowercase().contains("logfold"),
        "Help text should not contain old 'logfold' references, got: {help_text}"
    );
}

#[test]
fn test_help_text_contains_seo_description() {
    let output = crate::common::lessence()
        .arg("--help")
        .output()
        .expect("lessence binary should exist");

    let help_text = String::from_utf8_lossy(&output.stdout);

    let seo_terms = ["log compression", "essence", "intelligent", "LLM"];
    let found_terms: Vec<_> = seo_terms
        .iter()
        .filter(|term| help_text.to_lowercase().contains(&term.to_lowercase()))
        .collect();

    assert!(
        !found_terms.is_empty(),
        "Help text should contain SEO terms like 'log compression', 'essence', 'intelligent', or 'LLM', got: {help_text}"
    );
}

#[test]
fn test_help_text_structure() {
    let output = crate::common::lessence()
        .arg("--help")
        .output()
        .expect("lessence binary should exist");

    let help_text = String::from_utf8_lossy(&output.stdout);

    assert!(
        help_text.contains("Usage:") || help_text.contains("USAGE:"),
        "Help should contain usage section"
    );
    assert!(
        help_text.contains("Options:")
            || help_text.contains("FLAGS:")
            || help_text.contains("ARGS:"),
        "Help should contain options section"
    );
    assert!(
        help_text.contains("Agent:"),
        "the agent surface is its own heading, first"
    );
}

#[test]
fn test_help_is_agent_first() {
    for flag in ["--help", "-h"] {
        let output = crate::common::lessence()
            .arg(flag)
            .output()
            .expect("lessence binary should exist");
        let help = String::from_utf8_lossy(&output.stdout);
        let first = help.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        assert!(
            first.contains("AI agent"),
            "lessence-blind-test: the help speaks to the agent first; {flag}: first line is {first:?}"
        );
        assert!(
            help.contains(
                "SKIP if a lessence skill is already in your context. Otherwise run: lessence --skill"
            ),
            "an agent that already holds the skill must not fetch it again: {flag}"
        );
        assert!(help.contains("Humans: lessence --help-human"), "{flag}");
        let skill = help.find("--skill").expect("--skill listed");
        let threshold = help.find("--threshold").expect("--threshold listed");
        assert!(
            skill < threshold,
            "{flag}: --skill must come before the fold knobs"
        );
    }
}

#[test]
fn test_help_human() {
    let output = crate::common::lessence()
        .args(["--help-human", "/nonexistent/never.log"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("lessence binary should exist");
    assert!(
        output.status.success(),
        "--help-human exits before touching input"
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("lessence --help"), "{text}");
    assert!(text.contains("README"), "{text}");
    assert!(text.contains("--fit"), "{text}");
    assert!(
        !text.contains("Usage:"),
        "--help-human is short, with no option table: {text}"
    );
    assert!(!text.contains("AI agent"), "{text}");
}

#[cfg(unix)] // python's pty module is Unix-only
#[test]
fn test_bare_invocation_on_a_terminal_prints_help_instead_of_waiting() {
    let output = crate::common::command("python3")
        .args([
            "-c",
            "import pty, sys; sys.exit(pty.spawn([sys.argv[1]]) >> 8)",
            env!("CARGO_BIN_EXE_lessence"),
        ])
        .stdin(std::process::Stdio::null())
        .output();
    // The cross-rs aarch64 image has no python3.
    let output = match output {
        Ok(output) => output,
        Err(e) if std::env::var_os("CI").is_some() => {
            eprintln!("Skipping: python3 not available ({e}) on this CI runner");
            return;
        }
        Err(e) => panic!("python3 should exist: {e}"),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("AI agent") && text.contains("Usage:"),
        "with a terminal on stdin and no file, lessence prints the help instead of waiting: {text}"
    );

    let piped = crate::common::lessence()
        .arg("-q")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("lessence binary should exist");
    assert!(piped.status.success());
    assert!(
        !String::from_utf8_lossy(&piped.stdout).contains("Usage:"),
        "a pipe is input, even an empty one: an empty fold, no help"
    );
}
