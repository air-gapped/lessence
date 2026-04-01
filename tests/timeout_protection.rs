use std::time::{Duration, Instant};
use lessence::patterns::email::EmailPatternDetector;
use lessence::patterns::network::NetworkDetector;
use lessence::patterns::timestamp::TimestampDetector;

#[test]
fn test_email_timeout_protection() {
    let evil_email = format!("{}@{}.com!!!", "a".repeat(50), "b".repeat(50));
    
    let detector = EmailPatternDetector::new().unwrap();
    let start = Instant::now();
    let _ = detector.detect_and_replace(&evil_email);
    let elapsed = start.elapsed();
    
    assert!(
        elapsed < Duration::from_millis(100),
        "Email pattern detection took {:?}, must complete in <100ms",
        elapsed
    );
}

#[test]
fn test_ipv6_timeout_protection() {
    let evil_ipv6 = "1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f::invalid";
    
    let start = Instant::now();
    let _ = NetworkDetector::detect_and_replace(evil_ipv6, true, true, true);
    let elapsed = start.elapsed();
    
    assert!(
        elapsed < Duration::from_millis(100),
        "IPv6 pattern detection took {:?}, must complete in <100ms",
        elapsed
    );
}

#[test]
fn test_timestamp_timeout_protection() {
    let evil_timestamp = format!("2024-01-01T12:00:00.{}UTCX", "0".repeat(100));
    
    let start = Instant::now();
    let _ = TimestampDetector::detect_and_replace(&evil_timestamp);
    let elapsed = start.elapsed();
    
    assert!(
        elapsed < Duration::from_millis(200),
        "Timestamp pattern detection took {:?}, must complete in <500ms",
        elapsed
    );
}

#[test]
fn test_combined_patterns_timeout() {
    let evil_line = format!(
        "2024-01-01T12:00:00.{}UTCX User {}@{}.com!!! from {}::invalid logged in",
        "0".repeat(50),
        "a".repeat(50),
        "b".repeat(50),
        "1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8"
    );
    
    let config = lessence::config::Config::default();
    let normalizer = lessence::normalize::Normalizer::new(config);
    let start = Instant::now();
    let _ = normalizer.normalize_line(evil_line);
    let elapsed = start.elapsed();
    
    assert!(
        elapsed < Duration::from_millis(300),
        "Combined pattern detection took {:?}, must complete in <300ms (3 patterns × 100ms)",
        elapsed
    );
}

#[test]
fn test_timeout_does_not_cause_panic() {
    let evil_inputs = vec![
        format!("{}@{}.com!!!", "a".repeat(1000), "b".repeat(1000)),
        "1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8::invalid".to_string(),
        format!("2024-01-01T12:00:00.{}Z!!!", "9".repeat(500)),
    ];
    
    let config = lessence::config::Config::default();
    
    for input in evil_inputs {
        let start = Instant::now();
        let normalizer = lessence::normalize::Normalizer::new(config.clone());
        let result = std::panic::catch_unwind(|| {
            normalizer.normalize_line(input)
        });
        let elapsed = start.elapsed();
        
        assert!(result.is_ok(), "Pattern detection panicked on evil input");
        assert!(
            elapsed < Duration::from_millis(200),
            "Pattern detection took {:?} on evil input",
            elapsed
        );
    }
}
