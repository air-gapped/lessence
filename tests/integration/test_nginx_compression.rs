use std::str;

#[test]
fn test_nginx_compression_improvement() {
    let output = crate::common::lessence()
        .args(["--no-stats", "--no-report"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    let original_content = std::fs::read_to_string("tests/fixtures/nginx_sample.log")
        .expect("Failed to read nginx_sample.log");
    let input_lines = original_content.lines().count();

    let compression_ratio = ((input_lines - output_lines) as f64 / input_lines as f64) * 100.0;

    println!("Nginx compression test:");
    println!("  Input lines: {input_lines}");
    println!("  Output lines: {output_lines}");
    println!("  Compression ratio: {compression_ratio:.1}%");

    assert!(
        compression_ratio >= 70.0,
        "Nginx compression collapsed: {compression_ratio:.1}% — the APT client \
         flood is no longer folding (lessence-7lj: distinct user agents are their \
         own lines, so the ratio only guards that the repetitive bulk still folds)"
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
    let output = crate::common::lessence()
        .args(["--no-stats", "--no-report"])
        .stdin(
            std::fs::File::open("tests/fixtures/nginx_sample.log")
                .expect("nginx_sample.log not found"),
        )
        .output()
        .expect("Failed to execute lessence");

    assert!(output.status.success(), "lessence execution failed");

    let compressed_output = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    let output_lines = compressed_output.lines().count();

    println!("Nginx baseline test (before HttpStatusClass pattern):");
    println!("  Output lines: {output_lines}");

    assert!(
        output_lines <= 20,
        "Baseline regression detected: {output_lines} > 20 lines"
    );
}
