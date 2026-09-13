use std::fs::File;
use std::process::Command;

#[test]
fn json_output_has_one_stats_surface_even_when_stats_json_is_requested() {
    let input = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(input.path(), "worker finished\n").unwrap();
    for extra in [vec![], vec!["--top", "1"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_lessence"))
            .args(["--format", "json", "--stats-json", "--threads", "1"])
            .args(&extra)
            .stdin(File::open(input.path()).unwrap())
            .output()
            .unwrap();
        assert!(output.status.success(), "{extra:?}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let records: Vec<serde_json::Value> = stdout
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2, "one group plus one summary: {stdout}");
        assert_eq!(records[0]["type"], "group");
        assert_eq!(records[1]["type"], "summary");

        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            stderr.matches("--stats-json ignored in JSON mode").count(),
            1,
            "the ignored flag must be explained once: {stderr}"
        );
        assert!(
            stderr
                .lines()
                .all(|line| serde_json::from_str::<serde_json::Value>(line).is_err()),
            "stderr must not contain a duplicate stats object: {stderr}"
        );
    }
}
