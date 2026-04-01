## REMOVED Requirements

### Requirement: --max-tokens output limiting
**Reason**: Token counting was based on a fake heuristic (words/0.75) that does not reflect actual tokenizer behavior. The feature was misleading.
**Migration**: Use `head -n` or pipe through standard Unix tools to limit output size.
