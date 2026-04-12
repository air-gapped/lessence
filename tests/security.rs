// Barrel file: consolidates all security and ReDoS tests into one binary.

mod security {
    mod email_redos;
    mod ipv6_redos;
    mod security_compliance;
    mod test_ipv6_evil_patterns;
    mod timeout_protection;
    mod timestamp_redos;
}
