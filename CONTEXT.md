# CONTEXT.md — what to know before changing lessence

Orientation for an agent arriving cold. Everything here is what the code does
*not* say: vocabulary, what the gates actually prove, what is on disk but not in
git. Commands and architecture are in `CLAUDE.md`; the design principles and who
the tool is for are in `CLAUDE.local.md`; gate mechanics in `docs/verification.md`;
the dev flags in `docs/distill.md`. This file does not restate them.

Numbers below were measured on 2026-08-30 at commit `d3fdf21`. They are facts
with a shelf life — re-measure rather than cite.

## Vocabulary

Two words that are easy to blur, and are not the same property:

**Distilled** — a *fidelity* property. Every distinct shape of the original is
present and every value is invented. `--distill --anonymize` guarantees it and
the self-checks enforce it: same templates as the original, every word shape
present, no surviving real value. A distillate can be three lines per group —
shape-complete and proportionless.

**Miniature** — a *proportion* property. The file still reads like a log:
relative frequencies survive (members are kept log-scaled, so a big group keeps
more lines than a small one), original order intact. This is what makes a fold
visibly a fold and a perf number mean anything. The selection rule itself is a
spec and lives in `docs/distill.md`, "Member selection" — it has changed once
already, so it is not repeated here.

They fail independently. Until `a0ffc6d` the corpora were distilled but not
miniatures: a 12,000-line group and a 3-line group both showed three lines, so
nothing demonstrated folding. A file can equally be proportional and missing a
rare shape, which is worse — a gate then passes by absence.

**The self-checks enforce fidelity. Nothing enforces the miniature property.**
That is an open gap, not a decision.

Other terms as this repo uses them:

- **corpus** — one log under `examples/`. `originals/` is raw material, studied
  once and never read by a gate; `distilled/` is what every gate runs on.
- **golden** — `examples/distilled/<name>.golden`, every template of that corpus
  with its count. See the next section for what it does and does not prove.
- **group** — a cluster of lines the folder considers one event.
- **template** — the single line shown for a group. It is a *claim*: every
  literal word and every placeholder must hold for every member.
- **anchor** — a field matched for equality, never scored, so lines that differ
  there can never join. See below.
- **over-fold** — two distinct events shown as one. The worst failure: the
  reader trusts the summary and never learns the hidden event existed.
- **under-fold** — one event shown as several. Costs tokens, hides nothing.
  When in doubt, split.

## What the gates prove — and what they do not

`scripts/gate.sh` sets its verdict to FAIL on exactly three conditions:

1. a newly added `##CASE` that is **vacuous** — it passes on the baseline
   binary, so it could never have caught anything;
2. a **perf regression** over +1% (`instructions:u` on distilled kubelet);
3. `--explain` and `--format json` **disagreeing on a corpus where the
   baseline agreed exactly** (the `modes` line; see below).

**A golden change never fails the gate.** Changed goldens are printed for a
human or agent to read and judge. So this line:

```
golden: 80 corpora, 0 changed
```

immediately after `BLESS=1 make distill` proves only that the goldens were just
written from the current build. It is not evidence of correctness, and reporting
it as such is a mistake that has been made in this repo.

The golden is a **change detector, not an oracle**. The oracles are:

- a `##CASE` in `tests/fixtures/fold_regressions.log` that demonstrably fails on
  the previous binary (the gate checks this for you);
- an owned-shape test such as those in
  `tests/integration/test_constitutional_compliance.rs`, which assert a property
  rather than a recorded output and so cannot be laundered by a re-bless.

Corollary worth internalising: if a defect is recorded into the goldens by a
re-bless, every later gate run agrees with the defect. That is how a 606-group
explosion in `k8s_traefik` passed green for a day.

**The golden is blind to the mode users get.** It is taken from
`--explain --threads 1`, and `should_flush` returns false whenever `summary`,
`top_n` or `explain` is set — so the golden has never exercised eviction. The
default text output and `--format json` are the only modes that evict, and
neither has golden coverage.

That is not a theoretical gap. `lessence-940` emitted a recurring event as
several records with its count split across them — 210 duplicated templates in
2,214 on the distilled epyc journal — and the gate said `golden: 80 corpora, 0
changed` both while the defect was live and after it was fixed. It could
neither catch it nor confirm the repair; a hand-written reproduction had to do
both.

Since `lessence-xoq` the gate covers this without a second golden: for every
corpus it runs both modes on both binaries and counts the inventory rows
(`count<TAB>template`) the two modes do not share. The two modes must report
the same events with the same counts; where they do not, one of them is wrong.
A corpus on which the baseline binary agrees exactly **must still agree
exactly** and a new disagreement there is a FAIL: that is the shape of
`lessence-940`, an eviction defect that reaches every corpus large enough to
evict. A corpus that already disagrees on the baseline has its count printed
for reading, not judged, because any normalization change moves it by a few
rows either way. The history of that count is the history of the streaming
path: the `lessence-682` merge took the epyc journal from 516 to 481, and
`lessence-3ck` — indexed similarity matching against retained founders in
their original order — took the three journal corpora (481, 142, 43) to zero,
so today all 80 agree. Counts for newly varying slots are accumulated from
prior literals; unequal-length member shapes are kept under the existing
distinct cap and aligned against the final template. If that shape cap is
exceeded, VARIES counts are explicitly unavailable rather than presented as
exact; see `docs/format-json-schema.md`.

## The corpora

`examples/` is gitignored, so **nothing in git records which corpora exist**.
That absence caused a confident claim that no JSON access-log corpus existed
while `k8s_traefik` had been present all along. Check before claiming:

```bash
ls examples/distilled/*.log | wc -l
/usr/bin/grep -l '^\[pod/' examples/distilled/*.log | wc -l
```

As of 2026-08-30: **80 corpora, 85,606 distilled lines.** By shape:

| shape | count |
|---|---:|
| text | 26 |
| timestamped text | 16 |
| kubectl-prefixed text | 12 |
| kubectl-prefixed klog | 8 |
| kubectl-prefixed JSON per line | 7 |
| syslog / journal | 5 |
| JSON per line | 4 |
| klog | 2 |

Largest: `k8s_rook_ceph` 14,920 · `epyc_7days_journalctl` 8,654 ·
`host_fedora_journal` 5,771 · `openssh_brute_force` 4,100 · `kubelet` 3,951.

Two facts that matter when judging a diff:

- **27 corpora carry the `[pod/<pod>/<container>]` kubectl prefix** on 100% of
  their lines — every `k8s_*.log`. A change touching that prefix moves 27
  goldens and no others.
- **`kubelet.log` carries no `[pod/` prefix**, and it is the perf corpus. Its
  golden moving during a prefix-only change means the change leaked outside its
  class — a bug to chase, not to bless.

## Anchors: the invariant

`anchor_hash` (`src/normalize.rs`) reads 14 classes of field from the raw line
and folds their hash into the line hash, so two lines whose anchor values differ
can never join one group — matched, never scored. A 200 and a 500 for the same
route are two events however alike the rest of the line reads.

**The invariant: an anchor that separates groups must be visible on the shown
line.** Otherwise the split is real but invisible — many groups print
byte-identical templates, the reader cannot tell them apart, and the output is
worse than either folding or splitting honestly would have been.

Enforcement lives in `tests/integration/test_constitutional_compliance.rs`:

- `a_route_split_is_visible`, `a_pod_prefix_split_is_visible`, and
  `an_http_status_class_split_is_visible` gate the closed route, pod-prefix,
  and HTTP-status classes;
- `call_site_traceback_and_program_splits_are_visible` gates the call-site,
  Python-frame, and program-field classes on their affected corpora;
- `invisible_anchor_splits` (`#[ignore]`, reports but does not gate) catalogues
  the rest. Run it with:
  `cargo test --release --test integration invisible_anchor_splits -- --ignored --nocapture`

Status identity is shown in place as `<STATUS_2XX>` in structured fields and
`<HTTP_STATUS_2XX>` in quoted HTTP responses, using the same match for hashing
and rendering. Generic fields also cover process exit codes; they retain
their numeric facts without being labelled HTTP. Codes within a class still
agree. A status field inside a protected route query is retained
as a class marker beside the route skeleton. The status gate checks every
distilled corpus containing an HTTP status anchor; the route gate no longer
excludes status-class differences. The historical table below predates this
fix (`lessence-a8t.1`) and the completed streaming fixes.

Exact call-site, Python-frame and program-field identities now stay literal
in the template (`lessence-a8t.2`): a frame keeps its file, line and function,
and `exe=`/`"binary":` fields keep the program path. The hasher and renderer
read the same capture spans. An ordinary path outside these anchored
grammars still becomes `<PATH>`.

Open classes as of 2026-08-30 — **237 templates / 411 redundant groups across 17
corpora** (down from 370 / 653 / 24 before the kubectl-prefix class was closed):

| class | templates | groups |
|---|---:|---:|
| not anchor debt — streaming eviction (`lessence-940`) | 104 | 129 |
| PCI address | 75 | 204 |
| HTTP status class | 30 | 32 |
| systemd unit | 18 | 32 |
| program field (`exe=`, `"binary":`) | 4 | 4 |
| klog call site | 3 | 4 |
| request target (residual) | 3 | 6 |

Notes on that table:

- The **unexplained** bucket is not anchor debt. Their sharing groups have
  identical anchor values on both sides: this is `lessence-940`, streaming
  eviction re-forming a group under a key it already used, already measured and
  awaiting an owner decision on the streaming tradeoff. `nearest.anchor_mismatch`
  is therefore not a reliable per-pair signal — `nearest` may point at a third
  group entirely.
- The **request-target residual** is not an unfixed erasure. The route *is*
  rendered, then `<VARIES>` overwrites it: `"GET /route HTTP/<DECIMAL>"` is one
  unit (a quoted run of ≤3 words) and the HTTP verb differs between members, so
  the whole unit varies. The access-log anchor hashes target and status class
  but not the method.

When closing a class, follow the shape of the two already closed: render the
anchor's identity as text, from a helper the hasher and the renderer **share**,
so what is grouped on and what is shown cannot drift.

## The binary archive

`make install` keeps a copy of every binary it puts on PATH, under
`~/.local/share/lessence/installed/`, named `lessence-<version>-<short-sha>`
(plus `-dirty`). This exists because a regression was once bisected only after
restoring a binary from a restic snapshot: the installed build was 51 commits
behind and nothing recorded which commit it was.

Use it to check that a new `##CASE` actually fails on the previous build, and to
compare before/after on a real corpus without guessing what was running.

## Why this file exists

Written after a session in which four confident claims were wrong and each was
overturned by a measurement that took under a minute: two root causes inferred
from a commit message rather than measured, the corpus inventory above, and a
rendering edge case defended in argument that occurs in zero of 120 anchor
identities.

The facts were all in the repo. The failure was asserting from memory instead of
reading, so the useful habit is narrow: **before claiming what a corpus contains,
what a gate proved, or why a fold split, run the command.** The commands are in
this file for that reason.
