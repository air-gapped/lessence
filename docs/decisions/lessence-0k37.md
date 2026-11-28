---
status: in force
---

# --sanitize masks the whole authorization value

With `--sanitize`, the value after an authorization key becomes one
`<SECRET>`, scheme word included: `Authorization: Bearer abc123` reads
`Authorization: <SECRET>`.

Why: masking errs toward hiding. Telling a scheme word from a value by shape
alone is not possible, and lessence recognises shapes, never vocabularies.
An agent that needs the scheme can read the log without `--sanitize`.

Evidence: commit 4be0422 and its test
`an_authorization_value_followed_by_a_word_is_masked` (src/sanitize.rs).
