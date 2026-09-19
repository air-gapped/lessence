use std::process::Command;

#[test]
fn test_help_text_contains_lessence_branding() {
    // T006: CLI contract test for help text branding
    // Verifies that help text contains proper lessence branding

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--help")
        .output()
        .expect("lessence binary should exist");

    assert!(
        output.status.success(),
        "lessence --help should execute successfully"
    );

    let help_text = String::from_utf8_lossy(&output.stdout);

    // Check for "lessence" branding in help text
    assert!(
        help_text.to_lowercase().contains("lessence"),
        "Help text should contain 'lessence' branding, got: {help_text}"
    );

    // Ensure no old "lessence" references remain
    assert!(
        !help_text.to_lowercase().contains("logfold"),
        "Help text should not contain old 'logfold' references, got: {help_text}"
    );
}

#[test]
fn test_help_text_contains_seo_description() {
    // Verify SEO-optimized description appears in help
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--help")
        .output()
        .expect("lessence binary should exist");

    let help_text = String::from_utf8_lossy(&output.stdout);

    // Should contain key SEO terms
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
    // Verify help text has proper structure
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("--help")
        .output()
        .expect("lessence binary should exist");

    let help_text = String::from_utf8_lossy(&output.stdout);

    // Should contain standard help sections
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

/// The help speaks to the agent reading it before anything else, the way
/// herdr's does: an agent that already holds the skill must not fetch it
/// again, and --skill comes before every folding knob (lessence-blind-test).
#[test]
fn test_help_is_agent_first() {
    for flag in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
            .arg(flag)
            .output()
            .expect("lessence binary should exist");
        let help = String::from_utf8_lossy(&output.stdout);
        let first = help.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        assert!(
            first.contains("AI agent"),
            "{flag}: first line is {first:?}"
        );
        assert!(
            help.contains(
                "SKIP if a lessence skill is already in your context. Otherwise run: lessence --skill"
            ),
            "{flag}"
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

/// --help-human is for a person: short, no option table, and it exits
/// before touching input.
#[test]
fn test_help_human() {
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--help-human", "/nonexistent/never.log"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("lessence binary should exist");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("lessence --help"), "{text}");
    assert!(text.contains("README"), "{text}");
    assert!(text.contains("--fit"), "{text}");
    assert!(!text.contains("Usage:"), "{text}");
    assert!(!text.contains("AI agent"), "{text}");
}

/// `lessence` with nothing to read must not sit waiting on a terminal: a
/// person sees a hang, an agent hangs its session. With a terminal on stdin
/// and no file it prints the help and exits 0; a pipe still folds.
#[test]
fn test_bare_invocation_on_a_terminal_prints_help_instead_of_waiting() {
    // python's pty module lends the child a pseudo-terminal on stdin; the
    // parent's stdin is /dev/null so nothing ever arrives on it.
    let output = Command::new("python3")
        .args([
            "-c",
            "import pty, sys; sys.exit(pty.spawn([sys.argv[1]]) >> 8)",
            env!("CARGO_BIN_EXE_lessence"),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("python3 should exist");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("AI agent") && text.contains("Usage:"),
        "{text}"
    );

    // a pipe is input, even an empty one: no help, an empty fold
    let piped = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .arg("-q")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("lessence binary should exist");
    assert!(piped.status.success());
    assert!(!String::from_utf8_lossy(&piped.stdout).contains("Usage:"));
}
