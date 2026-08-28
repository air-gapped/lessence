use std::process::Command;
use std::str;

#[test]
fn test_nginx_compression_improvement() {
    // Test compression on nginx_sample.log
    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    // Read original file to get input line count
    let original_content = std::fs::read_to_string("tests/fixtures/nginx_sample.log")
        .expect("Failed to read nginx_sample.log");
    let input_lines = original_content.lines().count();

    // Calculate compression ratio
    let compression_ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Nginx compression test:");
    println!("  Input lines: {input_lines}");
    println!("  Output lines: {output_lines}");
    println!("  Compression ratio: {compression_ratio:.1}%");

    // This asserted `>= 75%` from the days when a ratio was the only way
    // to see a regression. A ratio cannot tell a lost fold from a found
    // event: two distinct user agents ("Go 1.1 package http", "urlgrabber
    // yum") used to vanish inside the APT group behind one opaque
    // <QUOTED_STRING>; keeping the sentence's words (lessence-7lj) surfaces
    // them as their own lines, and the ratio drops by exactly that. The
    // real guarantee is that the repetitive bulk still folds hard and the
    // status classes stay apart.
    assert!(
        compression_ratio >= 70.0,
        "Nginx compression collapsed: {compression_ratio:.1}% — the APT client \
         flood is no longer folding"
    );
    let biggest = compressed_output
        .lines()
        .filter_map(|l| {
            l.strip_prefix("[+")?
                .split(' ')
                .next()?
                .parse::<usize>()
                .ok()
        })
        .max()
        .unwrap_or(0);
    assert!(
        biggest >= 30,
        "the 34-line 304/APT group must fold as one; largest fold marker was +{biggest}"
    );
}

#[test]
fn test_nginx_baseline_without_new_patterns() {
    // This test documents the baseline before new patterns
    // Used for comparison to validate improvement

    let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
        .args(["--no-stats"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    // Document current baseline for comparison
    println!("Nginx baseline test (before HttpStatusClass pattern):");
    println!("  Output lines: {output_lines}");

    // Ensure we're not regressing from current baseline
    // Based on testing: 50 → 14 lines (72% compression)
    assert!(
        output_lines <= 20,
        "Baseline regression detected: {output_lines} > 20 lines"
    );
}
