use std::io::Write;
use std::process::Stdio;
use tempfile::NamedTempFile;

fn run_lessence_file(temp_file: &NamedTempFile) -> String {
    let file = std::fs::File::open(temp_file.path()).expect("Failed to open temp file");
    let output = crate::common::lessence()
        .args(["--no-stats", "--no-report"])
        .stdin(file)
        .output()
        .expect("Failed to execute lessence");
    String::from_utf8(output.stdout).unwrap()
}

const FLAGS_WHOSE_RUN_SAVES_NO_REPORT: &[&str] = &[
    "--format",
    "--json",
    "--summary",
    "--top",
    "--fit",
    "--preflight",
    "--explain",
];

fn run_lessence_stdin(args: &[&str], input: &str) -> String {
    let mut args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    if !args
        .iter()
        .any(|a| FLAGS_WHOSE_RUN_SAVES_NO_REPORT.contains(&a.as_str()))
    {
        args.push("--no-report".to_string());
    }
    let mut child = crate::common::lessence()
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn lessence");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child
        .wait_with_output()
        .expect("Failed to wait for lessence");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn test_basic_email_detection() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(
        temp_file,
        "2025-09-26T10:15:00Z User alice@company.com successfully authenticated"
    )
    .unwrap();
    writeln!(
        temp_file,
        "2025-09-26T10:15:01Z User bob@company.com successfully authenticated"
    )
    .unwrap();
    writeln!(
        temp_file,
        "2025-09-26T10:15:02Z User charlie@company.com successfully authenticated"
    )
    .unwrap();

    let stdout = run_lessence_file(&temp_file);

    assert!(
        stdout.contains("similar"),
        "Should contain folded output: {stdout}"
    );
    assert!(
        stdout.contains("email"),
        "Should indicate email variation: {stdout}"
    );

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2, "Should have at least 2 lines of output");
}

#[test]
fn test_email_with_mixed_patterns() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(
        temp_file,
        "2025-09-26T10:15:00Z User john@company.com logged in from 192.168.1.100"
    )
    .unwrap();
    writeln!(
        temp_file,
        "2025-09-26T10:15:01Z User jane@company.com logged in from 192.168.1.101"
    )
    .unwrap();
    writeln!(
        temp_file,
        "2025-09-26T10:15:02Z User admin@company.com logged in from 10.0.0.50"
    )
    .unwrap();
    writeln!(
        temp_file,
        "2025-09-26T10:15:03Z User support@company.com logged in from 172.16.0.25"
    )
    .unwrap();

    let stdout = run_lessence_file(&temp_file);

    assert!(
        stdout.contains("similar"),
        "Should contain folded output: {stdout}"
    );
    assert!(
        stdout.contains("email"),
        "Should indicate email variation: {stdout}"
    );

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() < 4,
        "Should compress to fewer than 4 lines of output"
    );
}

#[test]
fn test_email_pattern_disabled() {
    let input = "2025-09-26T10:15:00Z User alice@company.com successfully authenticated\n\
                 2025-09-26T10:15:01Z User bob@company.com successfully authenticated\n\
                 2025-09-26T10:15:02Z User charlie@company.com successfully authenticated\n";

    let stdout = run_lessence_stdin(&["--disable-patterns", "email", "--no-stats"], input);

    assert!(
        stdout.contains("alice@company.com") || stdout.contains("charlie@company.com"),
        "Should preserve at least some original emails when email pattern is disabled"
    );
}

#[test]
fn test_email_validation_no_false_positives() {
    let input = "2025-09-26T10:15:00Z Error: missing @ symbol in userexample.com\n\
                 2025-09-26T10:15:01Z Error: invalid domain user@.com detected\n\
                 2025-09-26T10:15:02Z Error: multiple @ symbols in user@@domain.com\n\
                 2025-09-26T10:15:03Z Valid email: support@company.com processed\n";

    let stdout = run_lessence_stdin(&["--no-stats"], input);

    assert!(
        stdout.contains("userexample.com"),
        "Should NOT detect 'userexample.com' as email"
    );

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() <= 4,
        "Should not produce more output than input"
    );
}

#[test]
fn test_email_url_pattern_order() {
    let input = "2025-09-26T10:15:00Z Click mailto:support@company.com for help\n\
                 2025-09-26T10:15:01Z Visit https://company.com/contact?email=info@company.com\n\
                 2025-09-26T10:15:02Z Send to: feedback@company.com or call support\n";

    let stdout = run_lessence_stdin(&["--no-stats"], input);

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() <= 3,
        "Should not produce more output than input"
    );
    assert!(!stdout.is_empty(), "Should produce some output");
}

#[test]
fn test_email_performance_impact() {
    let mut input = String::new();

    for i in 0..1000 {
        input.push_str(&format!(
            "2025-09-26T10:15:{:02}Z User user{}@company.com performed action {}\n",
            i % 60,
            i,
            i
        ));
        input.push_str(&format!(
            "2025-09-26T10:15:{:02}Z System event {} completed successfully\n",
            i % 60,
            i
        ));
    }

    let start = std::time::Instant::now();
    let stdout = run_lessence_stdin(&["--no-stats"], &input);
    let duration = start.elapsed();

    assert!(
        duration.as_secs() < 10,
        "Should complete within 10 seconds for 2000 lines"
    );

    let output_lines: Vec<&str> = stdout.lines().collect();

    assert!(
        output_lines.len() < 100,
        "Should compress 2000 lines to less than 100: the 1-2 digit counters stay literal, \
         so these 6-token lines fold only while the default threshold admits one differing \
         token (LCS 5/6 = 83.3%); a threshold of 84 or more fails this bound"
    );
}

#[test]
fn test_complex_email_formats() {
    let input = "User first.last@subdomain.example.org logged in\n\
                 User admin+tag@company-name.co.uk logged in\n\
                 User test_user@sub.domain.com logged in\n\
                 User user123@domain123.net logged in\n";

    let stdout = run_lessence_stdin(&["--no-stats"], input);

    assert!(stdout.contains("similar"), "Should contain folded output");
    assert!(stdout.contains("email"), "Should indicate email variation");

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() < 4, "Should compress complex email patterns");
}

#[test]
fn test_integration_with_existing_patterns() {
    let input = "2025-09-26T10:15:00.123Z [INFO] User alice@company.com authenticated from 192.168.1.100 with session abc123def456\n\
                 2025-09-26T10:15:01.124Z [INFO] User bob@company.com authenticated from 192.168.1.101 with session def456ghi789\n\
                 2025-09-26T10:15:02.125Z [INFO] User charlie@company.com authenticated from 192.168.1.102 with session ghi789jkl012\n";

    let stdout = run_lessence_stdin(&["--no-stats"], input);

    assert!(stdout.contains("similar"), "Should contain folded output");

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() <= 3, "Should compress to at most 3 lines");

    let folded_line = stdout
        .lines()
        .find(|line| line.contains("similar"))
        .unwrap();
    let varying_count = folded_line.matches(',').count();
    assert!(
        varying_count >= 2,
        "Should indicate multiple varying pattern types"
    );
}
