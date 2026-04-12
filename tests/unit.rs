// Barrel file: consolidates all external unit tests into one binary.
// Allow warnings in legacy test code — these files predate the barrel consolidation.
#![allow(clippy::all, unused_variables, unused_comparisons)]

mod unit {
    mod test_bracket_context_pattern;
    mod test_http_status_pattern;
    mod test_key_value_pattern;
    mod test_line_counting;
    mod test_log_module_pattern;
    mod test_markdown_output;
    mod test_pii_sanitization;
    mod test_priority_assignment;
    mod test_structured_message_pattern;
    mod test_text_output;
}
