// Contract Test: IPv6 Pattern ReDoS Resistance
// This test validates IPv6 pattern detector against evil inputs

use std::time::{Duration, Instant};

#[test]
fn test_ipv6_redos_resistance_repeated_groups() {
    // Given: Malicious IPv6-like pattern with excessive colons
    let evil_ipv6 = "1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f::invalid";
    
    // When: IPv6 pattern detector processes the malicious input
    use lessence::patterns::network::NetworkDetector;
    let start = Instant::now();
    let (_normalized, _tokens) = NetworkDetector::detect_and_replace(evil_ipv6, true, false, false);
    let elapsed = start.elapsed();
    
    // Then: Processing completes in <100ms
    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected: IPv6 pattern took {:?} for input length {}",
        elapsed,
        evil_ipv6.len()
    );
}

#[test]
fn test_ipv6_redos_resistance_double_colon_abuse() {
    // Given: Pattern with multiple :: (invalid IPv6)
    let evil_ipv6 = "1::2::3::4::5::6::7::8::9::a::b::c::invalid";
    
    // When: Processing invalid IPv6 with multiple compressions
    use lessence::patterns::network::NetworkDetector;
    let start = Instant::now();
    let (_normalized, _tokens) = NetworkDetector::detect_and_replace(evil_ipv6, true, false, false);
    let elapsed = start.elapsed();
    
    // Then: Completes in <100ms despite malformed input
    assert!(
        elapsed < Duration::from_millis(100),
        "ReDoS detected on malformed IPv6: took {:?}",
        elapsed
    );
}

#[test]
fn test_ipv6_valid_addresses_still_detected() {
    // Given: Valid IPv6 addresses (regression check)
    let valid_ipv6 = vec![
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::1",
        "::1",
        "fe80::1",
    ];
    
    // When/Then: All valid IPv6 addresses still detected
    use lessence::patterns::network::NetworkDetector;
    for ipv6 in valid_ipv6 {
        let input = format!("Address: {}", ipv6);
        let (normalized, tokens) = NetworkDetector::detect_and_replace(&input, true, false, false);
        
        assert!(normalized.contains("<IP>"), "Failed to detect IPv6: {}", ipv6);
        assert!(!tokens.is_empty(), "No tokens for valid IPv6: {}", ipv6);
    }
}

#[test]
fn test_ipv6_long_pattern_resistance() {
    // Given: Extremely long IPv6-like pattern
    let evil_ipv6 = (0..50).map(|i| format!("{:x}", i)).collect::<Vec<_>>().join(":");
    
    // When: Processing long colon-separated pattern
    use lessence::patterns::network::NetworkDetector;
    let start = Instant::now();
    let (_normalized, _tokens) = NetworkDetector::detect_and_replace(&evil_ipv6, true, false, false);
    let elapsed = start.elapsed();
    
    // Then: Completes quickly despite length
    assert!(
        elapsed < Duration::from_millis(100),
        "Long pattern took {:?} for {} chars",
        elapsed,
        evil_ipv6.len()
    );
}
