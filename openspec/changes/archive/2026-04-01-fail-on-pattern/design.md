## Context

lessence processes logs line-by-line during ingestion. The match check can happen inline with minimal overhead — just one regex test per line, setting a boolean flag.

## Goals / Non-Goals

**Goals:**
- `--fail-on-pattern "ERROR|FATAL"` exits 1 when matched, 0 when clean
- Output is always produced (compressed logs appear on stdout regardless)
- Works with all modes (normal, summary, top-N, preflight)

**Non-Goals:**
- No `--fail-on-level` (needs log level awareness, deferred)
- No multiple patterns (use regex alternation: `ERROR|FATAL|PANIC`)
- No match count reporting (keep it simple — matched or not)

## Decisions

**1. Scan raw lines before normalization**

The pattern should match against the original log text, not the normalized version. Users write patterns like `ERROR|FATAL`, not `<TIMESTAMP> ERROR`.

**2. Exit codes follow trivy/hadolint convention**

- 0: clean (no matches)
- 1: pattern matched
- 2: tool error (bad regex, I/O error)

This is compatible with `set -e` in CI scripts.

**3. Compile regex once, test per line**

Compile the regex at startup (fail fast on invalid regex with exit 2). Test each raw line with `is_match()` — O(1) amortized per line.

**4. Set a flag, check after output completes**

Don't exit early on match — the user wants the compressed output for diagnosis. Set `pattern_matched = true` on first match, check it after all output is flushed.

## Risks / Trade-offs

- [Regex complexity] User could pass a pathological regex. Mitigated by existing ReDoS protections and max-line-length limits.
