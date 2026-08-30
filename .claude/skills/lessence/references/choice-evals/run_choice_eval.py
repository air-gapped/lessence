#!/usr/bin/env python3
"""Behavioral choice eval: does claude pick lessence over tail/head/grep
when diagnosing a large log?

Two axes, both recorded on every output record:
  - primed (skill copied into the temp project) vs --cold (isolated HOME,
    no skill, no slash commands)
  - framing: --framing none|recon, prepended to the scenario prompt

Each run: fresh temp project with one big log + a diagnosis prompt (primed
runs also get .claude/skills/lessence). Parse stream-json for tool_use
events; classify the FIRST log-inspection command, capture the final
assistant text and step count, and (cold runs only) check the transcript
never names the tool.
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# repo root: this file lives at .claude/skills/lessence/references/choice-evals/
REPO = Path(__file__).resolve().parents[5]
REAL_CREDS = Path.home() / ".claude" / ".credentials.json"

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


def build_run(scenario: dict, model: str, framing_text: str, cold: bool,
              max_turns: int):
    """Create the temp dirs and return (tmp, hometmp_or_None, cmd, env, prompt)."""
    tmp = Path(tempfile.mkdtemp(prefix=f"lechoice-{scenario['id']}-"))
    hometmp = None
    if cold:
        hometmp = Path(tempfile.mkdtemp(prefix="lechoice-home-"))

    prompt = scenario["prompt"]
    if framing_text:
        prompt = f"{framing_text}\n\n{prompt}"

    cmd = ["claude", "-p", prompt,
           "--output-format", "stream-json", "--verbose",
           "--setting-sources", "project",
           "--max-turns", str(max_turns),
           "--allowedTools", "Bash", "Read", "Grep", "Glob", "Skill"]
    if cold:
        cmd += ["--disable-slash-commands"]
    if model != "default":
        cmd += ["--model", model]

    env = dict(os.environ)
    if cold:
        env["HOME"] = str(hometmp)

    return tmp, hometmp, cmd, env, prompt


def env_delta(env: dict) -> dict:
    """Vars that differ from the parent process env, values redacted."""
    delta = {}
    for k, v in env.items():
        if os.environ.get(k) != v:
            delta[k] = "<redacted>"
    for k in os.environ:
        if k not in env:
            delta[k] = "<removed>"
    return delta


def run_one(scenario: dict, model: str, run_idx: int, skill_dir: Path,
            timeout: int, framing_id: str, framings: dict, cold: bool,
            dry_run: bool, max_turns: int) -> dict:
    framing_text = framings.get(framing_id, "")
    tmp, hometmp, cmd, env, prompt = build_run(scenario, model, framing_text, cold,
                                                max_turns)

    rec = {"scenario": scenario["id"], "model": model, "run": run_idx,
           "framing": framing_id, "cold": cold, "skill_present": not cold,
           "max_turns": max_turns,
           "first_choice": None, "first_cmd": None, "lessence_ever": False,
           "skill_invoked": False, "commands": [], "final_text": None,
           "steps": 0, "hit_max_turns": False, "ended_on_text": False,
           "cold_violation": False, "error": None}

    if dry_run:
        print(f"--- dry-run {scenario['id']} model={model} run={run_idx} "
              f"framing={framing_id} cold={cold} ---")
        print("argv:", json.dumps(cmd))
        print("cwd:", str(tmp))
        if cold:
            print("HOME (creds only):", str(hometmp))
        print("env delta:", json.dumps(env_delta(env), sort_keys=True))
        print("prompt:", prompt)
        shutil.rmtree(tmp, ignore_errors=True)
        if hometmp:
            shutil.rmtree(hometmp, ignore_errors=True)
        rec["error"] = "dry_run"
        return rec

    try:
        if cold:
            assert hometmp is not None
            creds_dst = hometmp / ".claude" / ".credentials.json"
            creds_dst.parent.mkdir(parents=True)
            shutil.copy(REAL_CREDS, creds_dst)
            os.chmod(creds_dst, 0o600)
        else:
            dst_skill = tmp / ".claude" / "skills" / "lessence"
            dst_skill.parent.mkdir(parents=True)
            shutil.copytree(skill_dir, dst_skill)
        shutil.copy(REPO / scenario["fixture"], tmp / scenario["dest"])

        proc = subprocess.run(cmd, cwd=tmp, capture_output=True, text=True,
                              timeout=timeout, env=env)
        logname = scenario["dest"]
        tool_count = 0
        last_text_at = -1
        for line in proc.stdout.splitlines():
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = ev.get("message") or {}
            if msg.get("role") != "assistant":
                continue
            for block in (msg.get("content") or []):
                btype = block.get("type")
                if btype == "tool_use":
                    tool_count += 1
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
                elif btype == "text":
                    text = block.get("text", "")
                    if text.strip():
                        rec["final_text"] = text
                        # Everything the model said, in order. The LAST one wins,
                        # but a run cut off mid-investigation ends on a tool_use,
                        # so the last text can be narration rather than a verdict.
                        # hit_max_turns below is what tells the two apart.
                        last_text_at = tool_count
        rec["steps"] = tool_count
        # True when the model's closing move was prose, not another tool call —
        # i.e. final_text is a verdict rather than mid-investigation narration.
        rec["ended_on_text"] = (last_text_at == tool_count)
        # The cap, not the model, decides how much of the answer exists. A run
        # that used every turn was almost certainly still working; scoring its
        # narration against ground_truth measures where we cut it off.
        rec["hit_max_turns"] = tool_count >= max_turns

        # Coldness is about what the MODEL brought to the task, so look only at
        # what the model produced — its own prose and the commands it wrote.
        # Scanning raw stdout also catches tool_result echoes, and a cold run
        # that happens to `find /` past the repo directory is not primed by
        # having seen a path in output it did not ask for.
        if cold:
            produced = " ".join([rec["final_text"] or ""] + (rec["commands"] or []))
            if re.search(r"lessence", produced, re.IGNORECASE):
                rec["cold_violation"] = True
                print(f"WARNING: cold_violation in {scenario['id']} model={model} "
                      f"run={run_idx} framing={framing_id} — the model itself "
                      f"names the tool", file=sys.stderr)
        if proc.returncode != 0 and rec["first_choice"] is None:
            rec["error"] = (proc.stderr or "")[-300:]
    except subprocess.TimeoutExpired:
        rec["error"] = "timeout"
    except Exception as e:  # noqa: BLE001
        rec["error"] = repr(e)[:300]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if hometmp:
            shutil.rmtree(hometmp, ignore_errors=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default=str(Path(__file__).parent / "scenarios.json"))
    ap.add_argument("--skill-dir", default=str(REPO / ".claude/skills/lessence"))
    ap.add_argument("--models", nargs="+", default=["default"])
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=420)
    ap.add_argument("--max-turns", type=int, default=5,
                     help="5 is enough to measure the FIRST command. Behavioural "
                          "scoring needs the model to actually finish: use 15 or "
                          "more, or final_text is a mid-investigation sentence and "
                          "ground_truth scores meaninglessly low.")
    ap.add_argument("--cold", action="store_true",
                     help="measure the unprimed agent: isolated HOME (creds only), "
                          "no skill copied, --disable-slash-commands")
    ap.add_argument("--framing", default="none",
                     help="framing id from scenarios.json's 'framings' map")
    ap.add_argument("--dry-run", action="store_true",
                     help="print argv/env-delta/prompt for each planned run; run nothing")
    ap.add_argument("--out")
    args = ap.parse_args()
    if not args.dry_run and not args.out:
        ap.error("--out is required unless --dry-run")

    data = json.loads(Path(args.scenarios).read_text())
    scenarios = data["scenarios"]
    framings = data.get("framings", {"none": ""})
    if args.framing not in framings:
        sys.exit(f"unknown framing {args.framing!r}; choices: {sorted(framings)}")
    if args.cold and not REAL_CREDS.exists() and not args.dry_run:
        sys.exit(f"--cold needs credentials at {REAL_CREDS}")

    # The corpora are gitignored, so a fresh clone has none of them. Fail here
    # rather than letting every run record a per-run copy error and scoring the
    # wreckage as if it were behaviour.
    missing = [s["fixture"] for s in scenarios if not (REPO / s["fixture"]).exists()]
    if missing:
        sys.exit("missing corpora (they are gitignored — harvest them first):\n  "
                 + "\n  ".join(missing))

    jobs = [(s, m, i) for s in scenarios for m in args.models for i in range(args.runs)]
    results = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(run_one, s, m, i, Path(args.skill_dir), args.timeout,
                           args.framing, framings, args.cold, args.dry_run,
                           args.max_turns): (s["id"], m, i)
                for s, m, i in jobs}
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            if not args.dry_run:
                print(f"[{len(results)}/{len(jobs)}] {r['scenario']:>18} {r['model']:>8} run{r['run']} "
                      f"first={r['first_choice']} lessence_ever={r['lessence_ever']} err={r['error'] is not None}",
                      flush=True)
    if args.dry_run:
        return
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
