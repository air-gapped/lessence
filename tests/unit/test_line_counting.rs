// Contract Test: Output Line Counting Logic
// MUST FAIL before fix, MUST PASS after fix

// This is a unit test for FoldingStats - would be in tests/unit/test_line_counting.rs

#[cfg(test)]
mod line_counting_tests {
    use lessence::folder::{FoldingStats, PatternFolder};
    use lessence::config::Config;
    
    #[test]
    fn test_output_lines_field_exists() {
        // Given: FoldingStats struct
        // Then: Must have output_lines field
        
        let stats = FoldingStats::default();
        
        // This test will fail until output_lines field is added
        assert_eq!(stats.output_lines, 0, "output_lines should initialize to 0");
    }
    
    #[test]
    fn test_output_lines_increments_on_individual_output() {
        // Given: PatternFolder with individual lines (no folding)
        // When: Process lines that don't meet collapse threshold
        // Then: output_lines should increment for each output line
        
        let config = Config::default();
        let mut folder = PatternFolder::new(config);
        
        // Process 3 unique lines (won't collapse)
        folder.process_line("Line 1 unique content");
        folder.process_line("Line 2 different content");
        folder.process_line("Line 3 another content");
        
        let stats = folder.get_stats();
        
        assert_eq!(stats.total_lines, 3, "Should count 3 input lines");
        assert_eq!(stats.output_lines, 3, "Should count 3 output lines (no compression)");
        assert_eq!(stats.lines_saved, 0, "Should save 0 lines (no compression)");
    }
    
    #[test]
    fn test_output_lines_increments_on_collapsed_group() {
        // Given: PatternFolder with repetitive lines
        // When: Process 4+ similar lines (meets collapse threshold)
        // Then: output_lines should increment once for the collapsed group
        
        let mut config = Config::default();
        config.min_collapse = 3; // Collapse at 3+ similar lines
        let mut folder = PatternFolder::new(config);
        
        // Process 4 identical lines (will collapse)
        folder.process_line("ERROR: Connection timeout");
        folder.process_line("ERROR: Connection timeout");
        folder.process_line("ERROR: Connection timeout");
        folder.process_line("ERROR: Connection timeout");
        folder.finalize(); // Force flush
        
        let stats = folder.get_stats();
        
        assert_eq!(stats.total_lines, 4, "Should count 4 input lines");
        assert_eq!(stats.output_lines, 1, "Should output 1 collapsed line");
        assert_eq!(stats.lines_saved, 3, "Should save 3 lines (4-1)");
        assert_eq!(stats.collapsed_groups, 1, "Should have 1 collapsed group");
    }
    
    #[test]
    fn test_summary_lines_excluded_from_count() {
        // Given: PatternFolder after processing
        // When: Generate summary statistics with print_stats()
        // Then: output_lines should NOT increment (summary excluded)
        
        let config = Config::default();
        let mut folder = PatternFolder::new(config);
        
        // Process some lines
        folder.process_line("Line 1");
        folder.process_line("Line 2");
        folder.finalize();
        
        let stats_before = folder.get_stats().clone();
        
        // Generate summary report
        let mut summary_buffer = Vec::new();
        folder.print_stats(&mut summary_buffer).unwrap();
        
        let stats_after = folder.get_stats();
        
        // output_lines should NOT change after print_stats()
        assert_eq!(
            stats_before.output_lines,
            stats_after.output_lines,
            "output_lines should not increment during print_stats() call"
        );
    }
    
    #[test]
    fn test_statistics_conservation_law() {
        // Given: Processed log with compression
        // Then: total_lines = output_lines + lines_saved
        
        let mut config = Config::default();
        config.min_collapse = 3;
        let mut folder = PatternFolder::new(config);
        
        // Process mix: some collapse, some don't
        // Group 1: 4 identical (will collapse to 1)
        folder.process_line("ERROR: Failed");
        folder.process_line("ERROR: Failed");
        folder.process_line("ERROR: Failed");
        folder.process_line("ERROR: Failed");
        
        // Group 2: 3 unique (won't collapse)
        folder.process_line("INFO: Started");
        folder.process_line("WARN: Slow");
        folder.process_line("DEBUG: Query");
        
        folder.finalize();
        
        let stats = folder.get_stats();
        
        // Conservation law: input = output + saved
        assert_eq!(
            stats.total_lines,
            stats.output_lines + stats.lines_saved,
            "Conservation law: total = output + saved"
        );
        
        // Expected: 7 input, 4 output (1 collapsed + 3 individual), 3 saved
        assert_eq!(stats.total_lines, 7);
        assert_eq!(stats.output_lines, 4);
        assert_eq!(stats.lines_saved, 3);
    }
    
    #[test]
    fn test_compression_ratio_calculation() {
        // Given: Stats with known values
        // Then: Compression ratio should be calculated correctly
        
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
        
        // Verify conservation
        assert_eq!(stats.output_lines + stats.lines_saved, stats.total_lines);
    }
}
