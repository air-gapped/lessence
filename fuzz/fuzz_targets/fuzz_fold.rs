//! Fuzz target for the full folding pipeline.
//!
//! Feeds multiple lines through PatternFolder::process_line() + finish().
//! Catches panics in grouping, rollup computation, and output formatting.
//!
//! Run: cargo +nightly fuzz run fuzz_fold
#![no_main]
use libfuzzer_sys::fuzz_target;
use lessence::{Config, PatternFolder};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let config = Config {
            thread_count: Some(1),
            ..Default::default()
        };
        let mut folder = PatternFolder::new(config);
        for line in s.lines().take(200) {
            let _ = folder.process_line(line);
        }
        let _ = folder.finish();
    }
});
