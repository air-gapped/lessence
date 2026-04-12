// Barrel file: consolidates remaining tests (input limits, PII, email,
// detection performance, property tests, snapshots) into one binary.

mod common;

mod misc {
    mod input_limits;
    mod integration_email_compression;
    mod pii_sanitization;
    mod test_detection_performance;
    mod test_email_statistics;
    mod test_normalizer_properties;
    mod test_output_snapshots;
    mod test_sanitize_pii;
}
