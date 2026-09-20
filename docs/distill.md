# `--distill`, `--anonymize` (development tooling)

Hidden flags; not on `--help`, not in README or the skill. Code:
`src/distill.rs`, `src/anonymize.rs`; tests: `tests/integration/test_distill.rs`.

```
lessence --distill [--members N] [--anonymize] [--anonymize-words FILE] [--seed N] [FILE]
lessence --anonymize [--anonymize-words FILE] [--seed N] [FILE]
```

Conflicts (usage error naming both flags): `--distill` with `--format`,
`--summary`, `--fit`, `--top`, `--explain`, `--diff`, `--preflight`.
`--anonymize-words` implies `--anonymize`. Other input controls
(`--threads`, `--threshold`, `--min-collapse`, `--disable-patterns`) apply.

## Output contract

Stdout is a log: a subset of the input lines, original order, one line per
input line selected, no headers. Lines are byte-identical to the input
unless `--anonymize`. Exit 0 only when every self-check below passed; a
failed check prints what was lost and exits 1.

## What a distillation has to prove

`--distill` writes the smallest log that still proves everything the input
proved — minimum subject to sufficiency, not minimum, and not one line per
event either. A corpus holding one event in a hundred literal spellings
proves what two of them prove, and the difference between those two numbers
is the whole size of the file.

What may not be lost, and is checked before exit 0:

- **Every token-type structure.** The sorted token types of a group's
  representative line. Tetragon's 133 groups are twelve structures.
- **Every token type that fires**, anywhere, including one that appears on
  a single late member of one group.
- **Both kinds of split.** A *literal* split is two groups that agree for a
  long way and then say a different word — the pair a widened template
  would swallow first. An *anchor* split is two groups the folder promises
  never to merge whatever they look like, `success=yes` against
  `success=no`.
- **A group that still folds**, with at least `--min-collapse` members:
  below three, no variation is computed at all, so a file of singletons
  proves a template and nothing under it.
- **A `<VARIES>` slot.**
- **A capped rollup**, where the corpus can afford one (see below).

Proportion is deliberately *not* carried. A group of 200 000 occurrences
and a group of six prove the same shapes, so the distilled file shows the
shapes and drops the multiplicity. Counts live in the golden inventory,
which is taken from the original.

## Selection (`--distill`)

Per group formed by the folder (a group re-founded after a flush window is
its own group):

1. every member whose arrival changed the group's template (replay of
   `mark_varying_words`, uncapped — the set cannot outgrow the template's
   own words);
2. one member per distinct normalised form, up to `DISTILL_FORMS` (6);
3. one member per token type the members above do not already carry;
4. the earliest remaining members until `--members` (default 3) is reached;
5. every line of a group below `--min-collapse` (unfolded lines) as is.

Then across groups, one bucket per structure. Each bucket keeps the busiest
group, the group nearest it by shared template prefix, and one group per
distinct anchor value — all of the anchor values where the lines are small
(mean under `DISTILL_CHEAP_LINE_BYTES`, 512), one of them where they are
not, because proving an anchor costs another copy of the event and that is
nothing on a syslog line and megabytes on a 23 KB Kubernetes event. The
same threshold decides which group may carry the extra members that push a
rollup past `ROLLUP_DISTINCT_CAP`; at most one group per input carries them.

With `--anonymize`, selection runs on the anonymised log.

### Why the selection folds its own output

A distilled corpus is what every later gate reads as correct, so it may
never itself demonstrate an over-fold. Whether two groups stay apart cannot
be predicted — the input often keeps them apart only because thousands of
lines sat between them, and once those are gone they may merge. So the
selection folds its result and checks. Where a chosen pair merged, the
bucket picks its most *distant* group instead, and if that merges too it
keeps its primary alone and claims no split there.

Merging two *spellings* of one event is allowed; merging two events is not.
The literal words decide: everything outside a `<PLACEHOLDER>`. Two
templates with the same literal words differ only in what sits between the
words, so folding them widens a placeholder and loses nothing. Different
literal words are different events, and folding them is the failure the
whole tool exists to avoid.

## `--anonymize`

Same original value → same invented value for the whole run; two originals
never share an invention. Mapping is in memory only. `--seed N` makes a run
reproducible; default seed is random.

| Class | Invention |
|---|---|
| IPv4 | random in `10.0.0.0/8`; inputs sharing a /24 share one |
| IPv6 | prefix class kept (`fe80::`, `fd..`); `::1` and `::` unchanged |
| MAC | random, locally-administered bit set |
| UUID / ULID | random of the same kind |
| hex id, hash, `sha256:` digest | random hex, same length and case |
| email | invented local part and domain, TLD kept |
| FQDN, `<HOST>`, hostname labels | invented labels, same count and length class, TLD kept |
| k8s generated tails (template hash, `-x2k9p`, digitless five-char tails, ordinals) | random, same alphabet and length; component words kept; a name of pure words unchanged |
| credential values (`password=`, `token=`, `-p …`, JWTs — `folder::credential_spans`) | random, same length and charset; a value under 6 characters, or a key reached through a `/` (a URL path segment), is prose and is left alone |
| `--anonymize-words FILE` entries (one per line, case-insensitive) | invented word of the same length; matched at word and `%XX` boundaries |
| everything else (timestamps, numbers, paths, program names, levels, prose) | unchanged |

Replacement is boundary-aware: `db` is not rewritten inside `dbus`; `%XX`
counts as a boundary.

## Self-checks (all run before exit 0)

1. Coverage: every structure, every token type, every kept group's own
   template, and the folded / `<VARIES>` / capped states of the
   (anonymised) input are still present after folding the output. Whatever
   is missing is printed. Not template *equality* — the output's template
   set is a subset by design.
2. Survivors: no value of an invented class from the input remains in the
   output (boundary-aware; classes the table leaves unchanged are not
   checked). Survivors printed.
3. Vocabulary: no `--anonymize-words` entry remains — an entry of 6 or more
   characters is checked case-insensitively as a substring anywhere; a
   shorter entry is checked case-insensitively only at token boundaries
   (the same rule `at_token_boundary` uses: whitespace, quotes, brackets,
   `- _ . / : , = %XX`, not inside a run of letters/digits). A long word
   glued to other letters (`epycd`) is not replaced and fails here — add
   the glued form to the file.

## Measured (2026-09-20, `--distill --anonymize --seed 1`, release build)

The eighty corpora of `examples/originals/` together: 86 057 → 11 463
lines, 57.6 MB → 4.14 MB. `k8s_tetragon.log` 1 629 → 64 lines (37.9 MB →
0.98 MB); it holds 133 groups of twelve structures, and the distillation
keeps the structures. `kubelet.log` 70 548 → 720 lines.

Folding the whole distilled set costs 0.89 s in one process, against 4.25 s
for the same work as eighty subprocesses — which is why the corpus sweeps
in the test suite are bounded-parallel rather than serial.

## Where it is used

`make distill` (`scripts/distill.sh`, `docs/verification.md`): every
original in `examples/originals/` → `examples/distilled/<name>.log`; golden
inventory and acceptance rules there. The gate reads only the distilled set.
A raw log from a device is distilled and anonymised in one step and the raw
file deleted.
