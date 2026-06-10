#!/usr/bin/env python3
"""Behavioral choice eval: does claude pick lessence over tail/head/grep
when diagnosing a large log, given the lessence skill in the project?

Each run: fresh temp project with .claude/skills/lessence + one big log +
a diagnosis prompt. Parse stream-json for tool_use events; classify the
FIRST log-inspection command and whether lessence is used at any point.
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# repo root: this file lives at .claude/skills/lessence/references/choice-evals/
REPO = Path(__file__).resolve().parents[5]

LIMITED = re.compile(r"\b(tail|head)\b|grep\s+.*-m\s*\d|sed\s+-n|awk\s+.*NR\s*[<>]|--max-count|\|\s*wc\b")
SEARCH = re.compile(r"\b(grep|rg|awk|sed|cut|sort|uniq)\b")
FULLREAD = re.compile(r"\bcat\b|\bless\b|\bmore\b")


def classify_command(cmd: str) -> str:
    if re.search(r"\blessence\b", cmd):
        return "lessence"
    if LIMITED.search(cmd):
        return "limited"        # tail/head/bounded grep — the habit under test
    if SEARCH.search(cmd):
        return "search"         # unbounded grep/rg etc.
    if FULLREAD.search(cmd):
        return "fullread"
    return "other"


def run_one(scenario: dict, model: str, run_idx: int, skill_dir: Path, timeout: int) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix=f"lechoice-{scenario['id']}-"))
    rec = {"scenario": scenario["id"], "model": model, "run": run_idx,
           "first_choice": None, "first_cmd": None, "lessence_ever": False,
           "skill_invoked": False, "commands": [], "error": None}
    try:
        dst_skill = tmp / ".claude" / "skills" / "lessence"
        dst_skill.parent.mkdir(parents=True)
        shutil.copytree(skill_dir, dst_skill)
        shutil.copy(REPO / scenario["fixture"], tmp / scenario["dest"])

        cmd = ["claude", "-p", scenario["prompt"],
               "--output-format", "stream-json", "--verbose",
               "--setting-sources", "project",
               "--max-turns", "5",
               "--allowedTools", "Bash", "Read", "Grep", "Glob", "Skill"]
        if model != "default":
            cmd += ["--model", model]
        env = dict(os.environ)
        proc = subprocess.run(cmd, cwd=tmp, capture_output=True, text=True,
                              timeout=timeout, env=env)
        logname = scenario["dest"]
        for line in proc.stdout.splitlines():
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = ev.get("message") or {}
            for block in (msg.get("content") or []):
                if block.get("type") != "tool_use":
                    continue
                name, binp = block.get("name"), block.get("input") or {}
                if name == "Skill" and "lessence" in json.dumps(binp):
                    rec["skill_invoked"] = True
                if name == "Bash":
                    c = binp.get("command", "")
                    rec["commands"].append(c[:200])
                    if re.search(r"\blessence\b", c):
                        rec["lessence_ever"] = True
                    if logname in c and rec["first_choice"] is None:
                        rec["first_choice"] = classify_command(c)
                        rec["first_cmd"] = c[:200]
                elif name == "Read":
                    fp = binp.get("file_path", "")
                    rec["commands"].append(f"Read {fp} limit={binp.get('limit')}")
                    if logname in fp and rec["first_choice"] is None:
                        rec["first_choice"] = "read-limited" if binp.get("limit") else "read-full"
                        rec["first_cmd"] = rec["commands"][-1]
        if proc.returncode != 0 and rec["first_choice"] is None:
            rec["error"] = (proc.stderr or "")[-300:]
    except subprocess.TimeoutExpired:
        rec["error"] = "timeout"
    except Exception as e:  # noqa: BLE001
        rec["error"] = repr(e)[:300]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default=str(Path(__file__).parent / "scenarios.json"))
    ap.add_argument("--skill-dir", default=str(REPO / ".claude/skills/lessence"))
    ap.add_argument("--models", nargs="+", default=["default"])
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=420)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    scenarios = json.loads(Path(args.scenarios).read_text())
    jobs = [(s, m, i) for s in scenarios for m in args.models for i in range(args.runs)]
    results = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(run_one, s, m, i, Path(args.skill_dir), args.timeout): (s["id"], m, i)
                for s, m, i in jobs}
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            print(f"[{len(results)}/{len(jobs)}] {r['scenario']:>18} {r['model']:>8} run{r['run']} "
                  f"first={r['first_choice']} lessence_ever={r['lessence_ever']} err={r['error'] is not None}",
                  flush=True)
    Path(args.out).write_text("\n".join(json.dumps(r) for r in results))

    # summary
    print(f"\n=== summary ({time.time()-t0:.0f}s) ===")
    models = sorted({r["model"] for r in results})
    for m in models:
        rs = [r for r in results if r["model"] == m and not r["error"]]
        n = len(rs)
        first = sum(1 for r in rs if r["first_choice"] == "lessence")
        ever = sum(1 for r in rs if r["lessence_ever"])
        errs = sum(1 for r in results if r["model"] == m and r["error"])
        print(f"{m:>10}: first-choice lessence {first}/{n}, ever-used {ever}/{n}, errors {errs}")


if __name__ == "__main__":
    main()
