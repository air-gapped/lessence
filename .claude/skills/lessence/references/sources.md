# Sources — lessence skill

The authoritative source for every claim in this skill is the repo itself:
the binary's `--help`, the JSON schema doc, and direct execution of
`./target/release/lessence`. Re-verify after user-facing `feat:`/`fix:`
commits (they change behavior this skill documents).

| Claim | Source | Last verified |
|---|---|---|
| Flag set, defaults, `--format text\|markdown\|json` | `lessence --help` (v0.4.3) | 2026-06-09 |
| `--summary` default cap of 30 patterns | `src/folder/mod.rs` `DEFAULT_SUMMARY_CAP` | 2026-06-09 |
| JSONL group/summary record fields, `variation` rollup, `samples` ≤7, `capped` at 64, determinism modulo `elapsed_ms` | `docs/format-json-schema.md` + live run | 2026-06-09 |
| `--fail-on-pattern` exit 1 on match, exit 2 on invalid regex | `lessence --help` + `src/main.rs` | 2026-06-09 |
| Missing input file → exit 1 (other files still processed) | live run (fixed 2026-06-09) | 2026-06-09 |
| Stats footer goes to stderr; stdout carries only log output | live run (fixed 2026-06-09) | 2026-06-09 |
| Valid `--disable-patterns` names (15) | `lessence --help` | 2026-06-09 |
| All five Agent Triage Pipeline jq recipes (field names `variation.IPV4`, `K8S_POD.samples`, `time_range.first_seen`, `capped`, summary fields) | live run against `examples/kubelet.log` | 2026-06-09 |
| `--min-collapse` floor of 3 (binary rejects 2) | live run | 2026-06-09 |
| `--max-line-length` default 1MB (`main.rs` `.or(Some(1024*1024))`; help text corrected 2026-06-09) | code + live run | 2026-06-09 |
