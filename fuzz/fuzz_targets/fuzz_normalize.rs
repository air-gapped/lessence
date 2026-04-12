//! Fuzz target for the normalization pipeline.
//!
//! Feeds arbitrary bytes as a single log line through all 16 pattern
//! detectors. Catches panics, ReDoS hangs, and stack overflows that
//! the hand-crafted evil-pattern tests don't cover.
//!
//! Run: cargo +nightly fuzz run fuzz_normalize
#![no_main]
use libfuzzer_sys::fuzz_target;
use lessence::normalize::Normalizer;
use lessence::Config;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let normalizer = Normalizer::new(Config::default());
        let _ = normalizer.normalize_line(s.to_string());
    }
});
