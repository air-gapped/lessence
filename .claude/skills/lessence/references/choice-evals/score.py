#!/usr/bin/env python3
"""Post-hoc scorer: raw first-choice + refined first-analysis metric.

Recon = scoping commands that read ≤5 lines or metadata (wc, ls, du, file,
head/tail -n<=5, which, find, --version). The refined metric classifies the
first NON-recon command that inspects the log (or invokes lessence anywhere).
"""
import json, re, sys
from collections import defaultdict

RECON = re.compile(
    r"^(ls\b|wc\b|du\b|file\b|which\b|command -v|find\b|stat\b)"
    r"|^\s*(head|tail)\s+(-n\s*)?-?[1-5]\b"
)


def is_recon(cmd: str) -> bool:
    if "lessence" in cmd and "--version" not in cmd and not cmd.startswith("which"):
        return False
    parts = [p.strip() for p in re.split(r"&&|;|\|\||\n", cmd)]
    return all(
        RECON.match(p) or "--version" in p or p.startswith("echo") or not p
        for p in parts
    )


def invokes_lessence(cmd: str) -> bool:
    """True if any pipeline segment actually RUNS lessence (not which/ls/find lookups)."""
    for part in re.split(r"&&|;|\|\||\n", cmd):
        part = part.strip()
        if "lessence" not in part or "--version" in part:
            continue
        if part.startswith(("which", "command -v", "ls", "find", "stat", "echo")):
            continue
        if re.search(r"(^|\|\s*)lessence\b", part) or re.search(r"\blessence\s+(-|<|/|\w+\.(log|jsonl))", part):
            return True
    return False


def first_analysis(rec: dict) -> str:
    for cmd in rec["commands"]:
        if cmd.startswith("Read "):
            if is_recon(cmd):
                continue
            return "read-limited" if "limit=" in cmd and "limit=None" not in cmd else "read-full"
        if invokes_lessence(cmd):
            return "lessence"
        if is_recon(cmd):
            continue
        if re.search(r"\b(tail|head)\b|grep|awk|sed|cat\b|rg\b", cmd):
            return "sampling"
        # non-log command (mkdir etc.) — skip
    return "none"


def summarize(path: str, label: str):
    recs = [json.loads(l) for l in open(path) if l.strip()]
    print(f"\n## {label} ({len(recs)} runs)")
    print(f"{'model':>8} | {'first-cmd lessence':>18} | {'first-analysis lessence':>23} | {'ever-used':>9} | errors")
    rows = {}
    for m in sorted({r['model'] for r in recs}):
        rs = [r for r in recs if r['model'] == m]
        ok = [r for r in rs if not r['error']]
        raw = sum(1 for r in ok if r['first_choice'] == 'lessence')
        ana = sum(1 for r in ok if first_analysis(r) == 'lessence')
        ever = sum(1 for r in ok if r['lessence_ever'])
        errs = len(rs) - len(ok)
        print(f"{m:>8} | {raw:>14}/{len(ok)} | {ana:>19}/{len(ok)} | {ever:>6}/{len(ok)} | {errs}")
        rows[m] = (raw, ana, ever, len(ok))
    # per-scenario for the analysis metric
    print("  per-scenario first-analysis=lessence:")
    by = defaultdict(lambda: defaultdict(list))
    for r in recs:
        if not r['error']:
            by[r['scenario']][r['model']].append(first_analysis(r) == 'lessence')
    for sc in sorted(by):
        cells = "  ".join(f"{m}:{sum(v)}/{len(v)}" for m, v in sorted(by[sc].items()))
        print(f"    {sc:>18}  {cells}")
    return rows


if __name__ == "__main__":
    for path, label in zip(sys.argv[1::2], sys.argv[2::2]):
        summarize(path, label)
