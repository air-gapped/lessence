# Release-gate GitHub settings (run by the OWNER, once)

Adds `release-gate` as a second required status check on `main`, next to the
existing `test (ubuntu-latest)`. After this, `gh pr merge` on the release PR
is physically refused until both checks are green.

**Prerequisite**: the `release-gate` workflow must exist on `main` and have
produced at least one run (the context must be known to GitHub — the next
release-please PR event will trigger it). Apply the setting after that.

```bash
gh api -X PATCH repos/air-gapped/lessence/branches/main/protection/required_status_checks \
  --input - <<'EOF'
{"strict": false, "checks": [{"context": "test (ubuntu-latest)"}, {"context": "release-gate"}]}
EOF
```

Verify:

```bash
gh api repos/air-gapped/lessence/branches/main/protection/required_status_checks
```

Everything else (enforce_admins=false, daily direct pushes to main) is
unchanged. The `release-gate` job is skipped on non-release PRs — GitHub
treats a skipped required check as satisfied, so nothing else is affected.

Note: `verified-at:` in `.claude/skills/lessence/references/sources.md` was
initialized to the main sha at the time this change was authored
(9f1eba231e9bf5164759353a16a040c53ec378bc). When re-verifying the agent skill
before a release, set it to the then-current main sha.
