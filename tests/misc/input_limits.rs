use lessence::config::Config;
use lessence::ingest::{Event, IngestReport, Ingestor, InputReader};

/// Run text through the real ingestion path and collect the delivered lines.
fn ingest_lines(config: &Config, text: String) -> (Vec<String>, IngestReport) {
    let ingestor = Ingestor::from_config(config).expect("valid config");
    let readers = vec![InputReader {
        source: None,
        reader: Box::new(std::io::Cursor::new(text.into_bytes())),
    }];
    let mut delivered = Vec::new();
    let report = ingestor
        .run(readers, |event| {
            if let Event::Line { text, .. } = event {
                delivered.push(text.to_string());
            }
            Ok(())
        })
        .expect("ingestion succeeds");
    (delivered, report)
}

#[test]
fn test_line_length_limit_enforcement() {
    let config = Config {
        max_line_length: Some(1024 * 1024), // 1MB
        ..Default::default()
    };

    let huge_line = "A".repeat(2 * 1024 * 1024); // 2MB
    let normal_line = "User admin logged in";

    let (delivered, report) = ingest_lines(&config, format!("{huge_line}\n{normal_line}\n"));

    assert_eq!(
        delivered,
        vec![normal_line.to_string()],
        "Line exceeding max_line_length should be skipped, normal line delivered"
    );
    assert_eq!(report.overlong_lines_skipped, 1);
}

#[test]
fn test_line_count_limit_enforcement() {
    let config = Config {
        max_lines: Some(100),
        ..Default::default()
    };

    let mut text = String::new();
    for i in 0..150 {
        text.push_str(&format!("line {i}\n"));
    }
    let (delivered, report) = ingest_lines(&config, text);

    assert_eq!(
        delivered.len(),
        100,
        "Should process exactly max_lines (100)"
    );
    assert!(report.max_lines_reached, "Cutoff must be reported");
}

#[test]
fn test_size_suffix_parsing() {
    assert_eq!(
        lessence::config::parse_size_suffix("10K").unwrap(),
        10 * 1024
    );
    assert_eq!(
        lessence::config::parse_size_suffix("1M").unwrap(),
        1024 * 1024
    );
    assert_eq!(
        lessence::config::parse_size_suffix("1G").unwrap(),
        1024 * 1024 * 1024
    );
    assert_eq!(lessence::config::parse_size_suffix("512").unwrap(), 512);

    assert_eq!(
        lessence::config::parse_size_suffix("10k").unwrap(),
        10 * 1024
    );
    assert_eq!(
        lessence::config::parse_size_suffix("1m").unwrap(),
        1024 * 1024
    );
    assert_eq!(
        lessence::config::parse_size_suffix("1g").unwrap(),
        1024 * 1024 * 1024
    );
}

#[test]
fn test_invalid_size_suffix_parsing() {
    assert!(lessence::config::parse_size_suffix("10X").is_err());
    assert!(lessence::config::parse_size_suffix("invalid").is_err());
    assert!(lessence::config::parse_size_suffix("").is_err());
}

#[test]
fn test_no_limit_allows_all_lines() {
    let config = Config {
        max_line_length: None,
        max_lines: None,
        ..Default::default()
    };

    let huge_line = "A".repeat(10 * 1024 * 1024); // 10MB

    let (delivered, report) = ingest_lines(&config, format!("{huge_line}\n"));
    assert_eq!(
        delivered,
        vec![huge_line],
        "Without max_line_length, all lines should be processed"
    );
    assert_eq!(report.overlong_lines_skipped, 0);
}
