// Barrel file: consolidates all integration tests into one binary.
// Each test file is a submodule — one link step instead of 23.
#![allow(clippy::all, unused_comparisons)]

mod common;

mod integration {
    mod test_basic_scenarios;
    mod test_binary_name;
    mod test_cargo_validation;
    mod test_cli_formats;
    mod test_constitutional_compliance;
    mod test_documentation;
    mod test_edge_cases;
    mod test_essence_integration;
    mod test_fail_on_pattern;
    mod test_file_input;
    mod test_fit;
    mod test_format_json;
    mod test_format_json_rollups;
    mod test_help_text;
    mod test_microservices_compression;
    mod test_nginx_compression;
    mod test_normalization_integration;
    mod test_performance;
    mod test_stats_json;
    mod test_thread_safety;
    mod test_top_n;
    mod test_validation_errors;
    mod test_version_display;
}
