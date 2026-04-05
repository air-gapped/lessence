---
name: testing
description: >-
  Testing patterns for lessence — unit tests, integration tests, security/ReDoS
  testing, evil patterns, PII sanitization tests. Covers running tests, adding
  tests, and verifying security properties.
---

# Testing lessence

## Running Tests

```bash
cargo test --lib                    # Unit tests (in src/)
cargo test --tests                  # Integration tests (in tests/)
cargo test                          # All tests
cargo nextest run --release         # What CI runs (cargo-nextest, release mode)
```

## Test Organization

```
tests/
  unit/              # Pattern detector unit tests
  integration/       # CLI and end-to-end tests
  contract/          # API contract tests (CLI validation)
  security/          # ReDoS and evil pattern tests
  property/          # Property-based tests
  snapshot/          # Output snapshot tests
  performance/       # Performance regression tests
  benchmarks/        # Microbenchmarks
  validation/        # Input validation tests
  fixtures/          # Test data (log samples)
```

Tests in subdirectories need `[[test]]` entries in `Cargo.toml`:

```toml
[[test]]
name = "test_my_feature"
path = "tests/integration/test_my_feature.rs"
```

## Security Testing

### ReDoS Protection

All regex patterns must resist catastrophic backtracking:

```bash
cargo test test_ipv6_evil_patterns          # IPv6 ReDoS
cargo test test_email_redos_protection      # Email ReDoS
cargo test test_timestamp_redos_protection  # Timestamp ReDoS
```

### Evil Pattern Test

Must complete in <100ms:

```bash
cat << 'EOF' | ./target/release/lessence
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.com!!!
1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:a:b:c::
2024-01-01 12:00:00.........................................................UTCX
EOF
```

### PII Sanitization

```bash
cargo test test_email_sanitization
cargo test test_pii_redaction
echo "user@example.com logged in" | ./target/release/lessence --sanitize-pii
# Should show <EMAIL> instead of the address
```

## Writing Tests

### Folding Tests

Use 4+ similar lines to verify compression (min-collapse default is 3):

```bash
cat << 'EOF' | ./target/release/lessence
2025-01-20 10:15:01 Connection failed to 192.168.1.100:8080
2025-01-20 10:15:02 Connection failed to 192.168.1.101:8081
2025-01-20 10:15:03 Connection failed to 192.168.1.102:8082
2025-01-20 10:15:04 Connection failed to 192.168.1.103:8083
EOF
```

### Compression Math

- 2 lines -> 3 output = WORSE (don't fold)
- 3 lines -> 3 output = BREAK-EVEN
- 4+ lines -> 3 output = COMPRESSION (this is the goal)

### Essence Mode Tests

```bash
cat << 'EOF' | ./target/release/lessence --essence
2025-09-26T10:15:00Z ERROR: Database connection failed
2025-09-26T10:15:01Z ERROR: Database connection failed
EOF
# Timestamps should be replaced with <TIMESTAMP>
```

## Performance Testing

Always use release builds:

```bash
time ./target/release/lessence < examples/kubelet.log
time ./target/release/lessence --threads 1 < examples/kubelet.log
# Parallel should be faster on multi-core systems
```
