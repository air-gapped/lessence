# Sources — lessence skill

Freshened: 2026-11-10

The authoritative source for every claim in this skill is the repo itself:
the binary's `--help`, the JSON schema doc, and direct execution of
`./target/release/lessence`. Re-verify after user-facing `feat:`/`fix:`
commits (they change behavior this skill documents).

verified-at: ad8416db92cb641bc3ea35bdcd2ee961f073f159

`verified-at` is the main commit this skill was last verified against. The
release gate blocks the release PR if any `feat:`/`fix:`/`perf:` commit
touching `src/` postdates it.

| Claim | Source | Last verified |
|---|---|---|
| Flag set, defaults, `--format text\|markdown\|json` | `lessence --help` (build at verified-at) | 2026-11-10 |
| `--summary` default cap of 30 patterns | `src/config.rs` `DEFAULT_SUMMARY_CAP` + live run (`30 of 224 patterns`) | 2026-11-10 |
| JSONL group/summary record fields (group: count, first, last, normalized, time_range, token_types, variation; summary carries `briefing` and `completeness`), `samples` ≤7 (`ROLLUP_K`), `capped` at 64 (`ROLLUP_DISTINCT_CAP`), determinism modulo `elapsed_ms` | `docs/format-json-schema.md` + live run on `examples/distilled/kubelet.log` | 2026-11-10 |
| `--fail-on-pattern` exit 1 on match, exit 2 on invalid regex | `lessence --help` + `src/main.rs` | 2026-11-10 |
| Missing input file → exit 1 (other files still processed) | live run (fixed 2026-06-09) | 2026-11-10 |
| Stats footer goes to stderr; stdout carries only log output | live run (fixed 2026-06-09) | 2026-11-10 |
| Valid `--disable-patterns` names (15) | `lessence --help` | 2026-11-10 |
| All five Agent Triage Pipeline jq recipes (field names `variation.IPV4`, `K8S_POD.samples`, `time_range.first_seen`, `capped`, summary fields) | live run against `examples/distilled/kubelet.log` | 2026-11-10 |
| `--min-collapse` floor of 3 (binary rejects 2 with exit 2) | live run | 2026-11-10 |
| `--max-line-length` default 1MB (help text: `default: 1M`) | code + live run | 2026-11-10 |
| `--threshold` token-LCS semantics, stronger folding (`examples/distilled/kubelet.log`, 749 lines, folds to 608 output lines at default threshold) | src/normalize.rs similarity_score + live run (shipped in 0.4.4) | 2026-11-10 |
| `variation` FQDN key for hostnames (was IPV4); positional syslog host under `HOST` | src/patterns/mod.rs `Token::Fqdn` facts + docs/format-json-schema.md (shipped in 0.4.4) | 2026-11-10 |
| Stats footer reports line counts (`input_lines`/`output_lines`); time ranges are per folded group, not in the footer; under `--no-report` the briefing is a stderr footer after the folded output and `-q` silences it | live run (`--stats-json` keys, default run) | 2026-11-10 |
| `--frame-continuations` folds a stack trace as one event; `--sanitize ENTITY[:ACTION]` (email, credential, host, ip; redact or pseudonym, HMAC-SHA256 keyed per run or by `LESSENCE_SANITIZE_KEY`); `--diff LESSENCE` dev mode, exit 1 when groups moved | `lessence --help` + `references/flags.md` | 2026-11-10 |
| Briefing sample in SKILL.md (749 lines, 224 templates) | live run on `examples/distilled/kubelet.log` at verified-at | 2026-11-10 |
| `--skill [skill\|flags]` prints the embedded SKILL.md (frontmatter at byte 0, provenance note after it) or references/flags.md and exits 0 before any input is opened; unknown topic exits 2; `--json` equals `--format json` and conflicts with an explicit `--format` and with `--distill`; the `gen:flags` block in flags.md is the binary's own list | tests/integration/test_skill.rs + tests/doc_contract.rs `skill_flags_block` + live run of the build at verified-at | 2026-11-10 |
| Additive JSON/preflight schema_version, version, input_hash and degraded; raw ordered-source identity, exact failed-source counts and explicit unavailable reasons | docs/format-json-schema.md + tests/integration/test_run_metadata.rs + src/ingest.rs hash vectors; `make ci` passed on the e2f implementation | 2026-11-10 |
| `--help` and `-h` open with the agent block (skip if a lessence skill is already in context, otherwise `lessence --skill`; `--skill flags`; the JSON surface) with `--skill` listed before every fold knob under an `Agent` heading; `--help-human` prints the short human help and exits before opening input | tests/integration/test_help_text.rs (`test_help_is_agent_first`, `test_help_human`) + live run of the build at verified-at | 2026-11-10 |
| A default run saves the complete folded report (`report.jsonl`) to a fresh `run-<date>-<hex>` dir and prints a byte-bounded overview with a head/tail locator line, `printed < selected` meaning the byte budget cut entries (not the report), the four jq recipes, and `--overview all`/`--overview 0`/`--no-report`; a memory-backed (tmpfs/ramfs) `--report-dir` is refused (exit 1, empty stdout, `report: not written`) unless `--report-max-bytes N` accepts it; `--no-report` with `--report-dir` is a usage error | src/report.rs (`MEMORY_BACKED`) + live run on `examples/distilled/uap_messages.log` at verified-at | 2026-11-10 |
| The `--stats-json` bucket for bare numbers is `numbers` (was `percentages` before 15e00e3); the skill names neither, so no claim in it changed | `git show 15e00e3` + grep of the skill + live briefing on `examples/distilled/kubelet.log` | 2026-11-10 |
| The overview indexes records as the report is written and checks the file's size before printing; a damaged report still prints `overview: unavailable (…)` with the locator and recipes, which is all the skill says about it | f3b9d5a + tests/integration/test_report.rs `a_damaged_report_leaves_the_file_in_place_and_says_the_overview_is_unavailable` | 2026-11-10 |
| Platform fixes after 0.8.0 (macOS build, Windows directory sync and CRLF skill, overlayfs accepted for reports) change nothing the skill states about platforms (not re-run: no macOS or Windows host here; the skill now names tmpfs only for the report refusal, verified on Linux) | `git log ac4b13d..HEAD` + grep of the skill | 2026-09-23 |
| Text-mode marker: first member, marker, last member; inline value list up to 3 distinct values; count-only classes (port, duration, pid, …) never list; `varies×N {word×count}`; `hash×64+` at the cap; time range in the log's own stamp format | live runs on invented inputs | 2026-11-10 |
| Variation entries carry `distinct_count_kind`, `samples_complete`, `omitted_sample_values`; `nearest` is `{group_line_no, score, anchor_mismatch, first_diff:{ours,theirs,at}}` | live `--format json` / `--explain` runs + `src/folder/mod.rs` (`anchor_mismatch`) | 2026-11-10 |
| `compression_ratio` equal for the default run and `--summary`, different under `--top N` below the group count | live `--stats-json` runs on `examples/distilled/kubelet.log` (18.83 / 18.83 / 9.61 at `--top 2`) | 2026-11-10 |
| `--disable-patterns` reaches inside quoted strings; `<EVENT_OBJECT>` covers only `ObjectMeta:{…}` | live run on an invented input; `examples/distilled/kubelet.golden` | 2026-11-10 |
| Group timeline (`time_range.buckets`, `bunched`, the `98% in …` clause, one date for a run inside a day), one `varies×` per `<VARIES>` slot in template order, a generated name keeping its component, a route after `url=` staying literal | `tests/integration/test_group_timeline.rs`, `test_varies_slots.rs`, the `##CASE` blocks for these in `tests/fixtures/fold_regressions.log` + live run of the build at verified-at | 2026-11-12 |
