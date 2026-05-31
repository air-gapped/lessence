# Threat Model: lessence

> **Remediation status (2026-05-31, commit `da1800b`).** A follow-on
> vuln-scan → triage → patch pass landed fixes for several threats below:
> **T5** (terminal-escape injection) and **T8** (markdown injection) are now
> `mitigated`; instances of **T9** (the `--summary` multibyte panic) and **T6**
> (the timestamp O(M²) blowup) were also fixed. One algorithmic-DoS instance
> (key-value O(N²)) remains open as bead `lessence-lsu` — its candidate patch
> was rejected in review for over-folding unique lines (an A2 violation).
> Beads `lessence-m2p`/`ino`/`7ga`/`ui0`/`pow` are closed.

## 1. System context

lessence is a single-binary command-line log-compression filter written in Rust
(edition 2024, MIT, ~96 source files / ~2k symbols, v0.4.2). It reads log text
from stdin or file arguments, normalizes variable tokens (timestamps, IPs,
UUIDs, paths, emails, …) with 16 regex-based pattern detectors, clusters similar
lines, folds repetitive groups into a representative line plus a count, and
writes the result to stdout (statistics to stderr). It is a **transparent,
content-preserving Unix filter** in the same family as `cat`, `grep`, `less`,
and `kubectl logs`: non-destructive, no network, no persistence beyond its
output stream, no privilege, runs entirely as the invoking user.

It is a **general-purpose tool**: any kind of log can be piped through it, from
any source, so the model assumes the input may be hostile (no "trusted input"
assumption). In practice the maintainer and other users run it most often to
condense logs that are then **fed to coding agents assisting with system
administration** (`kubectl logs … | lessence | claude -p`), and also for plain
terminal viewing. It is distributed as a statically-linked binary via crates.io
(`cargo install`), cargo-binstall (GitHub Release artifacts), and direct
download, for Linux (x86_64/aarch64), macOS (Intel/Apple Silicon), and Windows.

Two scope boundaries are explicit design decisions by the owner, not gaps:
**secret/PII redaction is not lessence's responsibility** (it offers only an
opt-in email mask as a convenience; scrubbing secrets belongs upstream or to the
consumer), and **neutralizing prompt-injection in log content is not lessence's
responsibility either** (a transparent filter must not mangle content, and the
consuming agent harness owns the "treat tool output as untrusted" boundary —
just as `cat` does not sanitize what it prints). Security posture is otherwise
deliberate: `#![forbid(unsafe_code)]`, `panic = "abort"`, the linear-time
`regex` crate (no catastrophic backtracking), `cargo deny check` in CI,
cargo-fuzz + proptest, default ANSI stripping, OIDC Trusted Publishing, and
SHA-pinned, owner-gated GitHub Actions. The project has **no CVE or advisory
history**, so this model is forward-looking (STRIDE-derived).

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| A1 confidentiality of log content | Secrets, tokens, credentials, and PII embedded in the logs that pass through lessence. lessence does **not** take responsibility for protecting this (redaction is out of scope by design), but it remains a real asset because output is routinely redistributed (fed to LLM/agent APIs, terminals). | high |
| A2 output integrity ("zero data loss") | The guarantee that 100% of unique information survives folding — a unique line silently dropped or misattributed is an integrity failure and breaks the core trust contract. This is the constraint that *forbids* content-mangling defenses (redaction/injection-stripping). | medium |
| A3 host/session & downstream-agent integrity | The invoking environment: the operator's terminal emulator and, critically for the primary workflow, the downstream coding agent consuming lessence output. | medium |
| A4 release & build-chain integrity | The pipeline that compiles, publishes (crates.io), and uploads release binaries — a compromise ships to every downstream user via `cargo install` / `cargo binstall`. **The owner's stated top concern.** | high |
| A5 maintainer PII | The maintainer's personal domains/usernames in the local, gitignored `.blocklist`. | low |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| stdin / file input | Untrusted log content read line-by-line from stdin or `FILE` arguments (`open_inputs` in `src/main.rs`). The primary runtime surface; assumed hostile (any log, any source). | untrusted log content → process memory + regex engine | A2, A3 |
| CLI flags & arguments | clap-parsed flags (`--threshold`, `--threads`, `--max-line-length`, `--fail-on-pattern REGEX`, file paths). Operator-controlled; attacker-influenced only when lessence is embedded in a pipeline that interpolates untrusted data into its argv. | operator (mostly trusted) → process config | A3 |
| stdout / stderr output | Process output rendered into a downstream context: a terminal emulator, a JSON parser, a markdown renderer, or — primarily — an LLM/coding agent. Untrusted content from `stdin / file input` crosses *out* here into a rendering/execution context. | process → terminal / parser / agent | A1, A3 |
| dependency supply chain | Cargo dependencies (regex, clap, chrono, serde, rayon, ahash, rand/rand_chacha, mimalloc) + transitive deps + `Cargo.lock`. | third-party code → build output / shipped binary | A4 |
| release & distribution channel | crates.io publish, GitHub Release artifacts, cargo-binstall `pkg-url`, README install instructions. | maintainer infra → end-user machines | A4 |
| GitHub Actions automation | Workflows triggered by PR/issue/comment events that hold tokens: `@claude` bot, claude-code-review, release-build (crates.io publish + binary upload). | external GitHub user event → CI runner with tokens | A4 |

## 4. Threats

Rows are sorted by (impact, likelihood) descending. IDs are retained from the
bootstrap pass for traceability, so they are not sequential in row order.
`risk_accepted` rows record a deliberate owner decision (rationale in the
`controls` cell), not an oversight. **Status changes from the `da1800b`
remediation are marked in bold in the `controls` cell.**

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Backdoored release shipped to all users via tampered crates.io publish or GitHub Release binary | supply_chain | release & distribution channel | A4 | critical | rare | partially_mitigated | OIDC Trusted Publishing (no stored registry token), SHA-pinned actions, SHA256 checksums on binaries. Residual (no cryptographic build provenance) **accepted by owner: OIDC + checksums deemed sufficient.** | |
| T2 | Secrets and PII in logs disclosed to unintended recipients (LLM API, terminal) because output is unredacted | remote_unauth | stdin / file input → stdout / stderr output | A1 | high | likely | risk_accepted | **Owner: redaction is not lessence's job — it's the consumer's/upstream's responsibility; lessence offers only opt-in `--sanitize-pii` email masking as a convenience.** `.blocklist` is a personal file, not a wired-in control. | |
| T3 | Malicious dependency version pulled into the build before an advisory exists (registry takeover, typosquat) | supply_chain | dependency supply chain | A4 | high | possible | partially_mitigated | `cargo deny check` runs every CI build → known advisories + licenses + bans gated; `Cargo.lock` committed; Renovate+Dependabot grouped & 0.10-major-pinned; weekly cargo-machete + outdated check. **Residual: no dependency cooldown/min-release-age — `deny` only catches *known* RUSTSEC advisories.** | |
| T7 | Prompt-injection payload in log content reaches a downstream coding agent with sysadmin/shell powers | remote_unauth | stdin / file input → stdout / stderr output | A3, A1 | high | possible | risk_accepted | **Owner: not lessence's responsibility — it is a transparent filter like `cat`/`grep`/`kubectl logs` and must not mangle content (would violate A2 zero-data-loss). The consuming agent harness owns the "treat tool output as untrusted" boundary.** | |
| T4 | Token/secret exposure or unauthorized bot action via PR/issue-triggered workflow | remote_unauth | GitHub Actions automation | A4 | high | rare | mitigated | `claude.yml` uses `permissions: {}` + `github.actor == 'wthrbtn'` owner-gate + SHA-pinned actions; review workflow skips Dependabot; no `pull_request_target`. Residual = token-bearing release-build path. | |
| T5 | Terminal control-sequence injection / output spoofing from crafted log content | remote_unauth | stdin / file input → stdout / stderr output | A3 | medium | likely | mitigated | **Fixed in `da1800b` (bead `lessence-m2p`):** the default strip now removes the full escape set — CSI, OSC (BEL- and ST-terminated, incl. window-title and OSC 8 hyperlinks), DCS/APC/PM/SOS, lone ESC, and bare C0 controls (CR/BS/VT/FF) — via one shared `analyzer::strip_terminal_escapes` (the two duplicate copies were merged). **Residual:** `--preserve-color` still disables stripping entirely — a deliberate opt-in by the user (the "refuse a TTY unless forced" hardening was not implemented). | |
| T6 | Denial of service via memory/CPU exhaustion on adversarial input | remote_unauth | stdin / file input, CLI flags & arguments | A3 | medium | possible | risk_accepted | **Owner: single-run crash/OOM is irrelevant for a one-shot CLI — just re-run.** Technical note: `BufRead::lines()` materializes a full line before the 1 MB `max_line_length` check, so a newline-free multi-GB run OOMs regardless of the cap; per-line regex cost is linear (bounded). **Update (`da1800b`):** the timestamp-overlap O(M²) instance was fixed (`lessence-pow`, now O(M log M)); the key-value O(N²) instance remains open (`lessence-lsu`). The unbounded-line read remains an accepted volumetric concern. | |
| T8 | Output-format injection into a downstream parser/renderer (markdown fence breakout) | remote_unauth | stdin / file input → stdout / stderr output | A3 | low | possible | mitigated | JSON output escapes correctly via serde_json. **Fixed in `da1800b` (bead `lessence-ino`):** `--format markdown` now wraps untrusted content in a dynamically-sized code fence (a backtick run one longer than any run in the content), closing both code-fence breakout and the previously-unfenced non-folded path. | |
| T9 | Process crash (DoS) via a panic on crafted input | remote_unauth | stdin / file input | A3 | low | rare | risk_accepted | **Owner: DoS irrelevant (see T6).** Underlying robustness controls remain: cargo-fuzz targets on normalize + fold, proptest, `#![forbid(unsafe_code)]` (a panic is a clean abort, never memory corruption), `panic = "abort"`. **Update (`da1800b`):** the specific `--summary`/`--fit` multibyte-UTF-8 truncation panic was fixed (`lessence-7ga`, byte-index slice now snaps to a char boundary). | |

## 5. Deprioritized

These threat *classes* were considered and ruled out as not applicable to this
system. (Threats the owner consciously accepted but that remain technically real
— T2, T6, T7, T9, and the T1 residual — are kept in section 4 with status
`risk_accepted` so the threat table stays complete and downstream scorers see
their true impact.)

| threat | reason |
|---|---|
| ReDoS / catastrophic regex backtracking | The `regex` crate is linear-time by construction and exposes no backtracking primitives; no input (including the operator-supplied `--fail-on-pattern` regex) can cause superlinear blowup. This is the realized form of the project's "patterns resist ReDoS" principle. |
| Memory-corruption RCE (buffer overflow, UAF, OOB) | `#![forbid(unsafe_code)]` on the crate; the only `unsafe` is in mimalloc (musl-only, widely audited). Out of reach for the crate's own code. |
| Path traversal / arbitrary file read | File paths are operator-supplied (local user inside the trust boundary); no path crosses an untrusted boundary, and `-` denotes stdin. |
| Repudiation / audit tampering | lessence is a stateless filter with no accounts, logs, or persisted actions to repudiate. |
| Tampering at rest | No state is written anywhere except the stdout/stderr stream; nothing at rest to tamper with. |
| Host privilege escalation | No setuid/setgid, no privilege boundary; runs entirely as the invoking user. |
| Network attack surface | lessence opens no sockets and makes no network connections; not network-reachable. |
| Integer overflow in `parse_size_suffix` (`--max-line-length`) | Triage false-positive (scan F-012, exclusion rule 8): the vector is the operator-set `--max-line-length` flag value, not attacker-controlled content. A `checked_mul` is a reasonable code-quality hardening but not a security finding. |
| Unbounded line read before the `max_line_length` cap | Triage false-positive (scan F-013, exclusion rule 1): a newline-free giant line is materialized before the cap skips it — volumetric resource-exhaustion, the same class as T6 and accepted on the same grounds (one-shot CLI). |
| Per-match substring scans in structured-log classifiers | Triage false-positive (scan F-014): bounded by captured-component length, not full line length — not a real super-linear blowup, no action needed. |

## 6. Open questions

Owner-stated decisions that drive a score, with how to keep them honest:

- [Owner-states] DoS (crash/OOM) is irrelevant — one-shot CLI, re-run on failure. **Affects:** T6/T9 status (`risk_accepted`). **Verify by:** confirming lessence is never embedded as a long-lived service or on a shared multi-tenant host where one input degrades others.
- [Owner-states] Secret/PII redaction is out of scope — consumer's/upstream's responsibility; only opt-in email masking is offered. **Affects:** T2 status (`risk_accepted`). **Verify by:** ensuring README/SKILL.md set this expectation explicitly so users don't assume lessence scrubs secrets before output reaches an LLM API.
- [Owner-states] Prompt-injection neutralization is not lessence's job — it's a transparent filter; the consuming agent must treat output as untrusted. **Affects:** T7 status (`risk_accepted`). **Verify by:** confirming the agent harness/SKILL.md that consumes lessence output actually treats it as untrusted tool output (the boundary lessence is delegating to).
- [Owner-states] OIDC Trusted Publishing + SHA256 checksums are sufficient release trust; signed provenance declined. **Affects:** T1 residual (`risk_accepted`). **Verify by:** revisiting if lessence gains broad downstream adoption or a consumer requires SLSA/attestation.
- [Code-verified] `cargo deny check` runs on every CI build, so known-advisory gating is present. The only residual on T3 is the absence of a release-age cooldown.
- Open: given supply chain is the priority, is a Renovate `minimumReleaseAge`/cooldown acceptable despite the small delay it adds to legitimate updates?
- Open: should the key-value O(N²) blowup (`lessence-lsu`) be fixed by hoisting the per-line context decisions to the top of each `apply_*` pass (preserving the cross-pass mutation semantics the rejected patch broke)?

## 7. Provenance

- mode: bootstrap-then-interview
- date: 2026-05-31
- model target: `/home/jorgen/projects/lessence` @ `cf05e82`
- remediation: commit `da1800b` (branch `fix/security-triage-findings`) fixed T5, T8, and instances of T6/T9 — see the Remediation note at the top
- inputs: seed THREAT_MODEL.md (bootstrap pass); no design-doc; no --vulns; GitHub Security Advisories queried (none published)
- owner: present (Jörgen)

## 8. Recommended mitigations

Declined by the owner and intentionally **not** listed here: default-on secret
redaction / wiring `.blocklist` (T2 — out of scope), signed build provenance
(T1 — checksums + OIDC deemed sufficient), and read-time allocation caps (T6 —
DoS accepted).

| mitigation | threat_ids | closes_class | effort | status |
|---|---|---|---|---|
| Strip the full terminal control-sequence set by default (OSC, DCS, C1, lone ESC, all CSI finals — not just `ESC [ … alpha`); dedup the two `strip_ansi_codes` copies into one hardened helper | T5 | yes | S | **done (`da1800b`)** — the `--preserve-color`-refuses-a-TTY sub-part was left out |
| Context-encode untrusted content for `--format markdown`: escape markdown control chars and verify code-fence containment (JSON already safe via serde_json) | T8 | yes | S | **done (`da1800b`)** |
| Adopt a Renovate `minimumReleaseAge`/dependency cooldown so a freshly-published malicious version isn't pulled before a RUSTSEC advisory catches it (`cargo deny check` already gates *known* advisories in CI) — **owner's stated priority area** | T3 | partial | S | open |
| Keep OIDC Trusted Publishing, the `@claude` owner-gate, SHA-pinned actions, and least-privilege workflow tokens; avoid `pull_request_target` | T1,T4 | partial | S | ongoing (in place) |
| Document (README + bundled SKILL.md) that folded output is untrusted tool output and that injection-neutralization is the consuming agent's responsibility — informs the boundary lessence delegates to, without mangling content | T7 | partial | S | open |
| Keep `#![forbid(unsafe_code)]` + `panic = "abort"` and run the cargo-fuzz targets on a schedule (cheap upkeep even though single-run DoS is accepted) | T6,T9 | partial | S | ongoing (in place); `--summary` panic + timestamp-blowup instances additionally fixed in `da1800b` |
