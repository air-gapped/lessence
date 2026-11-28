# Roadmap

Each stage ends on what an agent can do, with the check that decides it.
The product-manager skill keeps this file true.

lessence is the map of a log: every distinct event with its count, so an
agent knows what is in a log before it searches it. It is the start of an
investigation, never the end. Folding makes the map short; omission never
does.

## Stage 1 (current): the map is complete and true

An agent running lessence first and then searching the raw log learns more
than an agent that only searches. Check: make value-eval, group S (lessence
plus skill plus grep) beats group R (grep alone) on score and has no more
false claims (2026-11-28: tie, 22 of 24 each, S 6 false claims to R's 2).

## Stage 2: templates are claims

Every word of every shown line holds for every member. Check:
assert_claim_holds on all corpora, and value-eval false claims from a
misread template are 0.

## Stage 3: right by default

An agent that never reads --help gets the full map and the way back to the
raw lines. Check: value-eval with the Haiku pass shows the same S over R
gain as Sonnet.
