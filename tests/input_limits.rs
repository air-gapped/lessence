use lessence::config::Config;

#[test]
fn test_line_length_limit_enforcement() {
    let config = Config {
        max_line_length: Some(1024 * 1024), // 1MB
        ..Default::default()
    };
    
    let huge_line = "A".repeat(2 * 1024 * 1024); // 2MB
    let normal_line = "User admin@example.com logged in";
    
    let huge_result = lessence::should_process_line(&huge_line, &config);
    let normal_result = lessence::should_process_line(normal_line, &config);
    
    assert!(!huge_result, "Line exceeding max_line_length should be skipped");
    assert!(normal_result, "Normal line should be processed");
}

#[test]
fn test_line_count_limit_enforcement() {
    let config = Config {
        max_lines: Some(100),
        ..Default::default()
    };
    
    let mut lines_processed = 0;
    
    for i in 0..150 {
        if lessence::should_process_line_count(i, &config) {
            lines_processed += 1;
        }
    }
    
    assert_eq!(
        lines_processed, 100,
        "Should process exactly max_lines (100), processed {}",
        lines_processed
    );
}

#[test]
fn test_size_suffix_parsing() {
    assert_eq!(lessence::config::parse_size_suffix("10K").unwrap(), 10 * 1024);
    assert_eq!(lessence::config::parse_size_suffix("1M").unwrap(), 1024 * 1024);
    assert_eq!(lessence::config::parse_size_suffix("1G").unwrap(), 1024 * 1024 * 1024);
    assert_eq!(lessence::config::parse_size_suffix("512").unwrap(), 512);
    
    assert_eq!(lessence::config::parse_size_suffix("10k").unwrap(), 10 * 1024);
    assert_eq!(lessence::config::parse_size_suffix("1m").unwrap(), 1024 * 1024);
    assert_eq!(lessence::config::parse_size_suffix("1g").unwrap(), 1024 * 1024 * 1024);
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
    
    assert!(
        lessence::should_process_line(&huge_line, &config),
        "Without max_line_length, all lines should be processed"
    );
}

#[test]
fn test_input_limit_performance_is_o1() {
    use std::time::Instant;
    
    let config = Config {
        max_line_length: Some(1024 * 1024),
        ..Default::default()
    };
    
    let line_1kb = "A".repeat(1024);
    let line_1mb = "A".repeat(1024 * 1024);
    let line_10mb = "A".repeat(10 * 1024 * 1024);
    
    let iterations = 10000;
    
    let start = Instant::now();
    for _ in 0..iterations {
        lessence::should_process_line(&line_1kb, &config);
    }
    let time_1kb = start.elapsed();
    
    let start = Instant::now();
    for _ in 0..iterations {
        lessence::should_process_line(&line_1mb, &config);
    }
    let time_1mb = start.elapsed();
    
    let start = Instant::now();
    for _ in 0..iterations {
        lessence::should_process_line(&line_10mb, &config);
    }
    let time_10mb = start.elapsed();
    
    let ratio_1mb_to_1kb = time_1mb.as_nanos() as f64 / time_1kb.as_nanos().max(1) as f64;
    let ratio_10mb_to_1mb = time_10mb.as_nanos() as f64 / time_1mb.as_nanos().max(1) as f64;
    
    assert!(
        ratio_1mb_to_1kb < 5.0,
        "Length check should be O(1), 1MB took {}x longer than 1KB",
        ratio_1mb_to_1kb
    );
    assert!(
        ratio_10mb_to_1mb < 5.0,
        "Length check should be O(1), 10MB took {}x longer than 1MB",
        ratio_10mb_to_1mb
    );
}
