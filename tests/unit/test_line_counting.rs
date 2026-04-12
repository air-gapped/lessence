// Unit tests for output line counting and compression stats

use lessence::config::Config;
use lessence::folder::{FoldingStats, PatternFolder};

#[test]
fn test_output_lines_field_exists() {
    let stats = FoldingStats::default();
    assert_eq!(stats.output_lines, 0, "output_lines should initialize to 0");
}

#[test]
fn test_output_lines_after_finish() {
    let config = Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    };
    let mut folder = PatternFolder::new(config);

    folder.process_line("Line 1 unique 10.0.0.1").unwrap();
    folder.process_line("Line 2 different 10.0.0.2").unwrap();
    let _output = folder.finish().unwrap();

    let stats = folder.get_stats();
    assert_eq!(stats.total_lines, 2);
    assert!(stats.output_lines > 0, "finish should count output lines");
}

#[test]
fn test_collapsed_group_counts() {
    let config = Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    };
    let mut folder = PatternFolder::new(config);

    for _ in 0..5 {
        folder
            .process_line("2024-01-01 ERROR timeout from 10.0.0.1")
            .unwrap();
    }
    let _output = folder.finish().unwrap();

    let stats = folder.get_stats();
    assert_eq!(stats.total_lines, 5);
    assert_eq!(stats.collapsed_groups, 1);
    assert!(stats.lines_saved > 0, "collapsing 5 lines should save some");
}

#[test]
fn test_print_stats_does_not_change_output_lines() {
    let config = Config {
        thread_count: Some(1),
        min_collapse: 3,
        ..Config::default()
    };
    let mut folder = PatternFolder::new(config);
    folder.process_line("hello 10.0.0.1").unwrap();
    let _output = folder.finish().unwrap();

    let before = folder.get_stats().output_lines;
    let mut buf = Vec::new();
    folder.print_stats(&mut buf).unwrap();
    let after = folder.get_stats().output_lines;

    assert_eq!(before, after, "print_stats should not change output_lines");
}

#[test]
fn test_compression_ratio_calculation() {
    let mut stats = FoldingStats::default();
    stats.total_lines = 100;
    stats.output_lines = 25;
    stats.lines_saved = 75;

    let compression_ratio = if stats.total_lines > 0 {
        (stats.lines_saved as f64 / stats.total_lines as f64) * 100.0
    } else {
        0.0
    };

    assert!((compression_ratio - 75.0).abs() < 0.01, "Expected 75% compression");
}
