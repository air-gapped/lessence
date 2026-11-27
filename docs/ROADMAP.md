# Roadmap

Each stage ends on what an agent can do, with the check that decides it.
The product-manager skill keeps this file true. Draft: stages are set by the
first product-manager run.

## Stage 1 (current): nothing hidden

An agent given any distilled corpus finds every distinct event from
`--explain` alone. Check: no open over-fold bug bead; a persona agent asked
"what happened in this log" on three corpora names every event a referee
finds by shell.

## Stage 2: templates are claims

Every word of every shown line holds for every member. Check:
`assert_claim_holds` on all corpora, and a referee finds no false premise in
a persona's answer.

## Stage 3: right by default, bounded but honest

An agent that never reads `--help` gets output that fits its context, with
every omission declared in `completeness`. Check: the size baseline in
`make gate`, and a persona answers correctly with the default command only.
