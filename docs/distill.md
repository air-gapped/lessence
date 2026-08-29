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

## Member selection (`--distill`)

Per group formed by the folder (a group re-founded after a flush window is
its own group):

1. every member whose arrival changed the group's template (replay of
   `mark_varying_words`, uncapped);
2. one member per distinct normalised form, up to `ROLLUP_DISTINCT_CAP`;
3. the earliest remaining members until `--members` (default 3) is reached;
4. then `3 + ⌊log2 n⌋` members (at most 16) spread evenly over the group's n
   occurrences, index round(i·(n−1)/(t−1)) for i in 0..t, unioned with the
   members above;
5. every line of a group below `--min-collapse` (unfolded lines) as is.

Then, over the whole output: the earliest line of every input word shape not
yet present is added. Word shape (`anonymize::word_shape`): words split on
whitespace and on `,{}[]` outside quotes; inside a word, every maximal digit
run → `#`, and a run of `[A-Za-z0-9._-]` that is 16 or more characters and at
least a quarter digits (an id, hash, UUID or stamp) → `#` whole; letters and
punctuation verbatim. Two lines that differ only in digits are one shape —
`switch0.1044:` and `switch0.1045:`, `-ipv4` and `-ipv6` — and the distilled
file keeps one of them: the same claim lessence makes with `<NUMBER>`, and
the known limit of the distillation. With `--anonymize`, selection runs on
the anonymised log.

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

1. Template set: `--explain` templates of the (anonymised) input equal
   those of the output. Missing / extra templates printed.
2. Word-shape coverage: every word shape of the (anonymised) input occurs
   in the output. Missing shapes printed.
3. Survivors: no value of an invented class from the input remains in the
   output (boundary-aware; classes the table leaves unchanged are not
   checked). Survivors printed.
4. Vocabulary: no `--anonymize-words` entry remains — an entry of 6 or more
   characters is checked case-insensitively as a substring anywhere; a
   shorter entry is checked case-insensitively only at token boundaries
   (the same rule `at_token_boundary` uses: whitespace, quotes, brackets,
   `- _ . / : , = %XX`, not inside a run of letters/digits). A long word
   glued to other letters (`epycd`) is not replaced and fails here — add
   the glued form to the file.

## Measured (2026-08-29, `--distill --anonymize --seed 1`, release build)

`examples/originals/kubelet.log` 70 548 → 2 987 lines, 2.3 s. `examples/originals/usw_messages.log`
1 283 → 512 lines, 0.1 s. `tests/fixtures/kubelet_2k.log` 2 000 → 216 lines
(bound 3×56 groups + 22 unfolded + one per distinct word shape).

## Where it is used

`make distill` (`scripts/distill.sh`, `docs/verification.md`): every
original in `examples/originals/` → `examples/distilled/<name>.log`; golden
inventory and acceptance rules there. The gate reads only the distilled set.
A raw log from a device is distilled and anonymised in one step and the raw
file deleted.
