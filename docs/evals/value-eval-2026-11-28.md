# Value eval, 2026-11-28

Question: does lessence help an agent understand a log it cannot read in full?
Measured per release by `make value-eval`, which writes `target/gate/value.json`.

## Method

| Part | What |
|---|---|
| Bank | `examples/value-eval/<log>/` (gitignored): `questions.md` (six questions), `key.md` (answers with the shell commands that prove them). Logs: `examples/originals/<log>.log`. Working bank: kubelet, k8s_etcd, k8s_tetragon, openssh_brute_force. |
| Group R | The raw log, with Read/Grep/Glob and the shell tools grep, awk, sort, uniq, wc, head, tail, sed, jq, cut, ls. |
| Group S | R plus `./lessence` (the binary under test) and the text of `lessence --skill` in the prompt. Otherwise the same prompt. |
| Solver | `claude -p --model claude-sonnet-5-5 --effort medium`, two runs per group per log. `RELEASE=1` adds `claude-haiku-5-5 --effort low` and the full bank. |
| Scorer | `claude -p --model claude-opus-5-5`, one per log and solver model. Sees the raw log, the key, the questions and the answers as shuffled sets A/B/C/D; never a group name. Settles disputes by shell; scores Q1-Q6 (0, 0.5, 1), Q1 and Q3 recall, false claims; reports key errors, which the run lists. |
| Bar | S beats R on score; S has no more false claims per run than R; S is not below the previous `value.json` for the same model and bank. |

## Blindness

- A solver's working directory is a fresh temporary directory holding only the log, and for S the lessence binary.
- `key.md` and the set-to-group map are never in a solver's directory; the map stays in the script's memory.
- Prompts never name a group; scorer prompts say "set A/B/C/D" in a shuffled order.

## Isolation

Each call runs as the claude-code-ci-harness method does: `env -i` with a fresh HOME and an
empty `CLAUDE_CONFIG_DIR`, `--safe-mode`, `--setting-sources ""`, `--strict-mcp-config`
with an empty server list, hooks disabled, `--permission-mode dontAsk`, and
`--allowed-tools` set per group. Credentials: `CLAUDE_CODE_OAUTH_TOKEN` (from
`claude setup-token`) from the environment or `~/.config/lessence/value-eval.env`; never an API key.

## Running it

```bash
make value-eval PREVIEW=1   # list every call, spend no tokens
make value-eval             # working bank, Sonnet
make value-eval RELEASE=1   # full bank, Sonnet + Haiku (also run by make release-check)
```

## Tonight's numbers

TODO: the PM supplies these.

| Round | Log | R score /6 | S score /6 | R false claims | S false claims | Notes |
|---|---|---|---|---|---|---|
| 1 | kubelet | TODO | TODO | TODO | TODO | |
| 1 | k8s_etcd | TODO | TODO | TODO | TODO | |
| 1 | k8s_tetragon | TODO | TODO | TODO | TODO | |
| 1 | openssh_brute_force | TODO | TODO | TODO | TODO | |
| 2 | kubelet | TODO | TODO | TODO | TODO | |
| 2 | k8s_etcd | TODO | TODO | TODO | TODO | |
| 2 | k8s_tetragon | TODO | TODO | TODO | TODO | |
| 2 | openssh_brute_force | TODO | TODO | TODO | TODO | |
