# Sources — lessence skill

The authoritative source for every claim in this skill is the repo itself:
the binary's `--help`, the JSON schema doc, and direct execution of
`./target/release/lessence`. Re-verify after user-facing `feat:`/`fix:`
commits (they change behavior this skill documents).

verified-at: 975a2aca07b5a89eda1fcafe0c5151dcf70d0fb5

`verified-at` is the main commit this skill was last verified against. The
release gate blocks the release PR if any `feat:`/`fix:`/`perf:` commit
touching `src/` postdates it.

| Claim | Source | Last verified |
|---|---|---|
| Flag set, defaults, `--format text\|markdown\|json` | `lessence --help` (build at verified-at) | 2026-09-18 |
| `--summary` default cap of 30 patterns | `src/folder/mod.rs` `DEFAULT_SUMMARY_CAP` (2815) | 2026-09-18 |
| JSONL group/summary record fields (group: count, first, last, normalized, time_range, token_types, variation; summary carries `briefing` and `completeness`), `samples` ≤7 (`ROLLUP_K`), `capped` at 64 (`ROLLUP_DISTINCT_CAP`), determinism modulo `elapsed_ms` | `docs/format-json-schema.md` + live run on `examples/distilled/kubelet.log` | 2026-09-18 |
| `--fail-on-pattern` exit 1 on match, exit 2 on invalid regex | `lessence --help` + `src/main.rs` | 2026-09-18 |
| Missing input file → exit 1 (other files still processed) | live run (fixed 2026-06-09) | 2026-09-18 |
| Stats footer goes to stderr; stdout carries only log output | live run (fixed 2026-06-09) | 2026-09-18 |
| Valid `--disable-patterns` names (15) | `lessence --help` | 2026-09-18 |
| All five Agent Triage Pipeline jq recipes (field names `variation.IPV4`, `K8S_POD.samples`, `time_range.first_seen`, `capped`, summary fields) | live run against `examples/distilled/kubelet.log` | 2026-09-18 |
| `--min-collapse` floor of 3 (binary rejects 2 with exit 2) | live run | 2026-09-18 |
| `--max-line-length` default 1MB (help text: `default: 1M`) | code + live run | 2026-09-18 |
| `--threshold` token-LCS semantics, stronger folding (`examples/distilled/kubelet.log`, 4,092 lines, folds to 733 lines at default threshold) | src/normalize.rs similarity_score + live run (shipped in 0.4.4) | 2026-09-18 |
| `variation` FQDN key for hostnames (was IPV4); positional syslog host under `HOST` | src/patterns/mod.rs `Token::Fqdn` facts + docs/format-json-schema.md (shipped in 0.4.4) | 2026-09-18 |
| Stats footer reports line counts (`input_lines`/`output_lines`); time ranges are per folded group, not in the footer; the briefing precedes the folded output on stderr and `-q` silences it | live run (`--stats-json` keys, default run) | 2026-09-18 |
| `--frame-continuations` folds a stack trace as one event; `--sanitize ENTITY[:ACTION]` (email, credential, host, ip; redact or pseudonym, HMAC-SHA256 keyed per run or by `LESSENCE_SANITIZE_KEY`); `--diff LESSENCE` dev mode, exit 1 when groups moved | `lessence --help` + `references/flags.md` | 2026-09-18 |
| Briefing sample in SKILL.md (4,092 lines, 273 templates, 733 folded lines) | live run on `examples/distilled/kubelet.log` at verified-at | 2026-09-18 |
| `--skill [skill\|flags]` prints the embedded SKILL.md (frontmatter at byte 0, provenance note after it) or references/flags.md and exits 0 before any input is opened; unknown topic exits 2; `--json` equals `--format json` and conflicts with an explicit `--format` and with `--distill`; the `gen:flags` block in flags.md is the binary's own list | tests/integration/test_skill.rs + tests/doc_contract.rs `skill_flags_block` + live run of the build at verified-at | 2026-09-19 |
| Additive JSON/preflight schema_version, version, input_hash and degraded; raw ordered-source identity, exact failed-source counts and explicit unavailable reasons | docs/format-json-schema.md + tests/integration/test_run_metadata.rs + src/ingest.rs hash vectors; `make ci` passed on the e2f implementation | 2026-09-19 |
| `--help` and `-h` open with the agent block (skip if a lessence skill is already in context, otherwise `lessence --skill`; `--skill flags`; the JSON surface) with `--skill` listed before every fold knob under an `Agent` heading; `--help-human` prints the short human help and exits before opening input | tests/integration/test_help_text.rs (`test_help_is_agent_first`, `test_help_human`) + live run of the build at verified-at | 2026-09-19 |
