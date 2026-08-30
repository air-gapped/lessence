#!/usr/bin/env python3
"""Post-hoc scorer: raw first-choice + refined first-analysis metric, plus
behavioral scoring against each scenario's ground_truth/distractors.

Recon = scoping commands that read ≤5 lines or metadata (wc, ls, du, file,
head/tail -n<=5, which, find, --version). The refined metric classifies the
first NON-recon command that inspects the log (or invokes lessence anywhere).

Records predating the cold/framing axes lack "framing"/"cold"/"skill_present"
fields; missing values default to "none"/False/True so old JSONL still scores.
"""
import json, re, sys
from collections import defaultdict
from pathlib import Path

RECON = re.compile(
    r"^(ls\b|wc\b|du\b|file\b|which\b|command -v|find\b|stat\b)"
    r"|^\s*(head|tail)\s+(-n\s*)?-?[1-5]\b"
)

SCENARIOS_PATH = Path(__file__).parent / "scenarios.json"
try:
    _scen_data = json.loads(SCENARIOS_PATH.read_text())
    SCEN_BY_ID = {s["id"]: s for s in _scen_data.get("scenarios", [])}
except FileNotFoundError:
    SCEN_BY_ID = {}


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


def get_framing(r: dict) -> str:
    return r.get("framing", "none")


def get_cold(r: dict) -> bool:
    return r.get("cold", False)


def get_skill_present(r: dict) -> bool:
    return r.get("skill_present", True)


def behavioral_section(recs: list):
    print("\n  ground-truth reached (behavioral):")
    by_scenario = defaultdict(list)
    for r in recs:
        if not r["error"]:
            by_scenario[r["scenario"]].append(r)
    for sc in sorted(by_scenario):
        scen = SCEN_BY_ID.get(sc, {})
        gt = scen.get("ground_truth", [])
        distractors = scen.get("distractors", [])
        recs_sc = by_scenario[sc]
        violations = [r for r in recs_sc if r.get("cold_violation")]
        rest = [r for r in recs_sc if not r.get("cold_violation")]
        # A run that spent every turn was still working when we stopped it, and
        # its final_text is narration, not a verdict. Scoring it measures the
        # --max-turns cap. Report it, never average it in.
        truncated = [r for r in rest if r.get("hit_max_turns")
                     and not r.get("ended_on_text")]
        clean = [r for r in rest if r not in truncated]
        if not gt:
            print(f"    {sc:>18}  ground truth not yet derived")
            if violations:
                print(f"      ({len(violations)} cold_violation run(s) present, excluded)")
            continue
        total_weight = sum(g["weight"] for g in gt) or 1
        fracs, steps_list = [], []
        distractor_hits = defaultdict(int)
        item_hits = defaultdict(int)
        for r in clean:
            text = r.get("final_text") or ""
            steps_list.append(r.get("steps", 0))
            got = 0
            for g in gt:
                if any(re.search(pat, text, re.I) for pat in g["any_of"]):
                    got += g["weight"]
                    item_hits[g["id"]] += 1
            fracs.append(got / total_weight)
            for d in distractors:
                if any(re.search(pat, text, re.I) for pat in d["any_of"]):
                    distractor_hits[d["id"]] += 1
        mean_reach = sum(fracs) / len(fracs) if fracs else 0
        mean_steps = sum(steps_list) / len(steps_list) if steps_list else 0
        dist_str = ", ".join(f"{k}:{v}" for k, v in sorted(distractor_hits.items())) or "none"
        print(f"    {sc:>18}  reached={mean_reach:.0%} (n={len(clean)})  "
              f"distractors=[{dist_str}]  mean_steps={mean_steps:.1f}")
        # Which findings were missed matters more than the aggregate: a run that
        # scores 60% by naming the symptoms and missing the cause is not 60% right.
        for g in gt:
            hit = item_hits.get(g["id"], 0)
            if not clean:
                mark = "n/a "
            elif hit == len(clean):
                mark = "ok  "
            elif hit == 0:
                mark = "MISS"
            else:
                mark = "part"
            print(f"        {mark} {g['id']:<32} {hit}/{len(clean)} (w{g['weight']})")
        if truncated:
            print(f"      ({len(truncated)} run(s) hit --max-turns mid-investigation, "
                  f"excluded — raise --max-turns, do not read this as a wrong answer)")
        if violations:
            print(f"      ({len(violations)} cold_violation run(s) excluded from this score)")


def summarize(path: str, label: str):
    recs = [json.loads(l) for l in open(path) if l.strip()]
    print(f"\n## {label} ({len(recs)} runs)")
    cold_n = sum(1 for r in recs if get_cold(r))
    framings_seen = sorted({get_framing(r) for r in recs})
    print(f"  axes: cold={cold_n}/{len(recs)}  framings={framings_seen}")
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
    behavioral_section(recs)
    return rows


if __name__ == "__main__":
    for path, label in zip(sys.argv[1::2], sys.argv[2::2]):
        summarize(path, label)
