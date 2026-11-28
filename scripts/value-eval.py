#!/usr/bin/env python3
"""Value eval: does lessence help an agent understand a log? (bead lessence-q9k0)

Per log in examples/value-eval/<log>/ (questions.md, key.md) and
examples/originals/<log>.log: solver runs for group R (raw log + shell text
tools) and group S (R + the lessence binary under test + its --skill text),
then one blind scorer per log and solver model over shuffled answer sets
A/B/C/D. Writes target/gate/value.json and prints the bar. --preview lists
every call and spends no tokens.

Every claude call is isolated per the claude-code-ci-harness method: env -i,
fresh HOME and empty CLAUDE_CONFIG_DIR, --safe-mode, --setting-sources "",
--strict-mcp-config with an empty server list, hooks disabled,
--permission-mode dontAsk, and only the tools the group allows. Credentials:
CLAUDE_CODE_OAUTH_TOKEN from the environment or
~/.config/lessence/value-eval.env; never an API key.
"""
import argparse, concurrent.futures as cf, json, os, random, re, shutil, stat
import subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BANK = ROOT / "examples" / "value-eval"
ORIGINALS = ROOT / "examples" / "originals"
OUT = ROOT / "target" / "gate" / "value.json"
ENV_FILE = Path.home() / ".config" / "lessence" / "value-eval.env"
WORKING_BANK = ["kubelet", "k8s_etcd", "k8s_tetragon", "openssh_brute_force"]

SOLVER = {"model": "claude-sonnet-5-5", "effort": "medium"}
RELEASE_SOLVER = {"model": "claude-haiku-5-5", "effort": "low"}
SCORER = {"model": "claude-opus-5-5", "effort": None}
RUNS_PER_GROUP = 3
TIMEOUT_S = 1800

TEXT_TOOLS = ["grep", "awk", "sort", "uniq", "wc", "head", "tail", "sed", "jq", "cut", "ls"]
BASE_TOOLS = ["Read", "Grep", "Glob"] + [f"Bash({c}:*)" for c in TEXT_TOOLS]
GROUP_TOOLS = {"R": BASE_TOOLS, "S": BASE_TOOLS + ["Bash(./lessence:*)"]}
SCORER_TOOLS = BASE_TOOLS

SOLVER_PROMPT = """You are investigating the log file ./{log}.log in this directory.
Answer every question below. Give counts and timestamps where asked, and
say how you established each answer. Only state what the log supports.

{questions}
"""
SCORER_PROMPT = """You are grading answer sets to questions about the log ./{log}.log.
The answer key is ./key.md (with the shell commands that prove it); the
questions are ./questions.md; the answer sets are ./set-*.md. When a set and
the key disagree, settle it by shell on the log. If the key itself is wrong,
say so.

Score each question Q1-Q6 as 0, 0.5 or 1. Q1 recall = error/warning kinds in
the key that the set names; Q3 recall = rare events in the key that the set
names. A false claim is a statement the log contradicts.

End your reply with exactly one fenced json block:
{{"sets": {{"A": {{"q": [q1,q2,q3,q4,q5,q6], "total": n, "q1_recall": [found, of],
"q3_recall": [found, of], "false_claims": n, "false_claim_list": ["..."]}}, ...}},
"key_errors": ["..."]}}
"""


def die(msg):
    print(f"value-eval: {msg}", file=sys.stderr)
    sys.exit(2)


def oauth_token():
    tok = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "").strip()
    if not tok and ENV_FILE.is_file():
        if ENV_FILE.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            die(f"{ENV_FILE} must be mode 0600")
        for line in ENV_FILE.read_text().splitlines():
            m = re.match(r"\s*(?:export\s+)?CLAUDE_CODE_OAUTH_TOKEN=(.*)$", line)
            if m:
                tok = m.group(1).strip().strip("'\"")
    if not tok:
        die("no CLAUDE_CODE_OAUTH_TOKEN. Run `claude setup-token` in a separate terminal and put "
            f"CLAUDE_CODE_OAUTH_TOKEN=<token> in {ENV_FILE} (mode 0600), or export it. "
            "An API key is never used.")
    return tok


def claude_args(model, effort, tools, cfg, system_prompt_file=None):
    args = ["-p", "--model", model, "--output-format", "stream-json", "--verbose",
            "--no-session-persistence", "--safe-mode", "--disable-slash-commands",
            "--setting-sources", "",
            "--strict-mcp-config", "--mcp-config", str(cfg / "mcp.json"),
            "--settings", str(cfg / "settings.json"),
            "--permission-mode", "dontAsk",
            "--tools", ",".join(sorted({t.split("(")[0] for t in tools})),
            "--allowed-tools", *tools, "--disallowed-tools", "mcp__*", "--no-chrome"]
    if effort:
        args += ["--effort", effort]
    if system_prompt_file:
        args += ["--append-system-prompt-file", system_prompt_file]
    return args


def run_claude(call, token):
    cli = shutil.which("claude") or die("claude not found on PATH")
    cli = os.path.realpath(cli)
    with tempfile.TemporaryDirectory(prefix="ve-env-") as envdir:
        env_root = Path(envdir)
        for d in ["home", "config", "xdg-config", "xdg-data", "xdg-state", "xdg-cache", "tmp"]:
            (env_root / d).mkdir()
        (env_root / "mcp.json").write_text('{"mcpServers":{}}\n')
        (env_root / "settings.json").write_text('{"disableAllHooks":true}\n')
        env = {
            "HOME": f"{envdir}/home", "CLAUDE_CONFIG_DIR": f"{envdir}/config",
            "XDG_CONFIG_HOME": f"{envdir}/xdg-config", "XDG_DATA_HOME": f"{envdir}/xdg-data",
            "XDG_STATE_HOME": f"{envdir}/xdg-state", "XDG_CACHE_HOME": f"{envdir}/xdg-cache",
            "TMPDIR": f"{envdir}/tmp",
            "PATH": f"{os.path.dirname(cli)}:/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb", "NO_COLOR": "1", "CI": "1",
            "CLAUDE_CODE_SKIP_PROMPT_HISTORY": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
            "ANTHROPIC_API_KEY": "", "CLAUDE_CODE_OAUTH_TOKEN": token,
        }
        args = claude_args(call["model"], call["effort"], call["tools"], env_root,
                           call.get("system_prompt_file"))
        t0 = time.monotonic()
        p = subprocess.run([cli, *args], input=call["prompt"], cwd=call["workdir"], env=env,
                           capture_output=True, text=True, timeout=TIMEOUT_S)
        wall = time.monotonic() - t0
    Path(call["transcript"]).parent.mkdir(parents=True, exist_ok=True)
    Path(call["transcript"]).write_text(p.stdout)
    result = None
    for line in p.stdout.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("type") == "result":
            result = ev
    if not result or result.get("is_error") or not (result.get("result") or "").strip():
        raise RuntimeError(f"{call['id']}: no successful result (exit {p.returncode}); "
                           f"transcript {call['transcript']}")
    return result_of(result, wall)


def result_of(result, wall=0.0):
    """Final answer, tokens and seconds from a stream-json result event."""
    u = result.get("usage", {})
    io = sum(u.get(k, 0) or 0 for k in ["input_tokens", "output_tokens"])
    cache = sum(u.get(k, 0) or 0 for k in ["cache_creation_input_tokens", "cache_read_input_tokens"])
    return {"text": result["result"], "tokens": io + cache, "tokens_io": io, "tokens_cache": cache,
            "seconds": round(result.get("duration_ms", wall * 1000) / 1000, 1)}


def from_transcript(path):
    """A finished solver run read back from its transcript, or None."""
    p = Path(path)
    if not p.is_file():
        return None
    result = None
    for line in p.read_text().splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("type") == "result":
            result = ev
    if not result or result.get("is_error") or not (result.get("result") or "").strip():
        return None
    return result_of(result)


def plan(logs, release, lessence_bin, scratch, runs, tdir):
    """Solver workdirs hold the log, and lessence for S; nothing else."""
    solvers = [SOLVER] + ([RELEASE_SOLVER] if release else [])
    skill = (subprocess.run([lessence_bin, "--skill"], capture_output=True, text=True).stdout
             if Path(lessence_bin).is_file() else "<lessence --skill output>")
    skill_file = Path(tempfile.mkdtemp(prefix="ve-skill-")) / "skill.md"
    skill_file.write_text(skill)
    calls = []
    for log in logs:
        questions = (BANK / log / "questions.md").read_text()
        for s in solvers:
            for group in ["R", "S"]:
                for run in range(1, runs + 1):
                    calls.append({
                        "id": f"{log}/{s['model']}/{group}{run}", "log": log, "group": group,
                        "run": run, "model": s["model"], "effort": s["effort"],
                        "tools": GROUP_TOOLS[group],
                        "workdir": tempfile.mkdtemp(prefix="ve-", dir=scratch),
                        "transcript": str(Path(tdir) / f"{log}-{s['model']}-{group}{run}.ndjson"),
                        "prompt": SOLVER_PROMPT.format(log=log, questions=questions),
                        "system_prompt_file": str(skill_file) if group == "S" else None,
                        "files": [str(ORIGINALS / f"{log}.log")] + ([lessence_bin] if group == "S" else []),
                    })
    return calls


def stage(call):
    for f in call["files"]:
        shutil.copy2(f, Path(call["workdir"]) / Path(f).name)


def score_log(log, model, answers, scratch, token):
    """The set-letter to group map stays in this process, never on disk."""
    order = answers[:]
    random.shuffle(order)
    letters = [chr(ord("A") + i) for i in range(len(order))]
    wd = Path(tempfile.mkdtemp(prefix="ve-score-", dir=scratch))
    shutil.copy2(ORIGINALS / f"{log}.log", wd / f"{log}.log")
    shutil.copy2(BANK / log / "key.md", wd / "key.md")
    shutil.copy2(BANK / log / "questions.md", wd / "questions.md")
    for letter, (_, _, text) in zip(letters, order):
        (wd / f"set-{letter}.md").write_text(text)
    call = {"id": f"{log}/{model}/score", "model": SCORER["model"], "effort": SCORER["effort"],
            "tools": SCORER_TOOLS, "workdir": str(wd),
            "transcript": str(Path(scratch) / "transcripts" / f"{log}-{model}-score.ndjson"),
            "prompt": SCORER_PROMPT.format(log=log)}
    res = run_claude(call, token)
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", res["text"], re.S)
    if not blocks:
        raise RuntimeError(f"{call['id']}: scorer gave no json block; transcript {call['transcript']}")
    verdict = json.loads(blocks[-1])
    return verdict, {letter: (g, r) for letter, (g, r, _) in zip(letters, order)}


def mean(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 2) if xs else None


def spread(xs):
    """Mean and min-max over runs."""
    xs = [x for x in xs if x is not None]
    return {"mean": mean(xs), "min": min(xs), "max": max(xs)} if xs else None


def fmt(s):
    return "-" if not s else f"{s['mean']:g} [{s['min']:g}-{s['max']:g}]"


def main():
    ap = argparse.ArgumentParser(description="lessence value eval (bead lessence-q9k0)")
    ap.add_argument("--preview", action="store_true", help="list every call; spend no tokens")
    ap.add_argument("--release", action="store_true", help="full bank plus the Haiku solver pass")
    ap.add_argument("--lessence", default=str(ROOT / "target" / "release" / "lessence"))
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--runs", type=int, default=RUNS_PER_GROUP, help="solver runs per group")
    ap.add_argument("--reuse-transcripts", metavar="DIR",
                    help="reuse solver runs whose transcript is in DIR; missing runs write there")
    a = ap.parse_args()
    a.lessence = os.path.realpath(a.lessence)

    bank = sorted(p.name for p in BANK.iterdir() if (p / "key.md").is_file()) if BANK.is_dir() else []
    logs = bank if a.release else [l for l in WORKING_BANK if l in bank]
    missing = [l for l in logs if not (ORIGINALS / f"{l}.log").is_file()]
    if not logs or missing:
        die(f"bank incomplete: logs={logs} missing originals={missing}")

    scratch = tempfile.mkdtemp(prefix="lessence-value-eval-")
    tdir = Path(a.reuse_transcripts).expanduser().resolve() if a.reuse_transcripts else Path(scratch) / "transcripts"
    tdir.mkdir(parents=True, exist_ok=True)
    calls = plan(logs, a.release, a.lessence, scratch, a.runs, tdir)
    reused = {c["id"]: r for c in calls if a.reuse_transcripts and (r := from_transcript(c["transcript"]))}
    solver_models = sorted({c["model"] for c in calls})

    if a.preview:
        for c in calls:
            tag = "reuse " if c["id"] in reused else "call  "
            print(f"solver {tag}{c['id']:<44} effort={c['effort']} "
                  f"workdir=[{', '.join(Path(f).name for f in c['files'])}] tools={','.join(c['tools'])}")
        for log in logs:
            for m in solver_models:
                sets = ",".join(chr(65 + i) for i in range(2 * a.runs))
                print(f"scorer {log + '/' + m + '/score':<44} model={SCORER['model']} "
                      f"workdir=[{log}.log, key.md, questions.md, set-{{{sets}}}.md] shuffled")
        print(f"{len(calls) - len(reused)} solver calls ({len(reused)} reused from {tdir}) + "
              f"{len(logs) * len(solver_models)} scorer calls; no tokens spent")
        shutil.rmtree(scratch)
        return 0

    if not Path(a.lessence).is_file():
        die(f"lessence binary not found: {a.lessence} (build it, or pass --lessence)")
    token = oauth_token()
    answers = {c["id"]: (c, reused[c["id"]]) for c in calls if c["id"] in reused}
    todo = [c for c in calls if c["id"] not in reused]
    for c in todo:
        stage(c)
    with cf.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = {ex.submit(run_claude, c, token): c for c in todo}
        for f in cf.as_completed(futs):
            c = futs[f]
            answers[c["id"]] = (c, f.result())
            print(f"done {c['id']} ({answers[c['id']][1]['seconds']} s)", file=sys.stderr)

    results, key_errors = {}, []
    for m in solver_models:
        for log in logs:
            mine = [(c["group"], c["run"], r["text"]) for c, r in answers.values()
                    if c["log"] == log and c["model"] == m]
            verdict, by_set = score_log(log, m, mine, scratch, token)
            key_errors += [f"{log}: {e}" for e in verdict.get("key_errors", [])]
            for letter, (g, run) in by_set.items():
                v = verdict["sets"][letter]
                _, r = answers[f"{log}/{m}/{g}{run}"]
                results.setdefault(m, {}).setdefault(g, {}).setdefault(log, []).append({
                    "run": run, "set": letter, "score": v["total"], "q": v["q"],
                    "q1_recall": v["q1_recall"], "q3_recall": v["q3_recall"],
                    "kinds_found": v["q1_recall"][0], "kinds_total": v["q1_recall"][1],
                    "rare_found": v["q3_recall"][0], "rare_total": v["q3_recall"][1],
                    "false_claims": v["false_claims"], "false_claim_list": v.get("false_claim_list", []),
                    "tokens": r["tokens"], "tokens_io": r.get("tokens_io"),
                    "tokens_cache": r.get("tokens_cache"), "seconds": r["seconds"],
                    "reused": f"{log}/{m}/{g}{run}" in reused})

    summary = {}
    for m, groups in results.items():
        for g, per_log in groups.items():
            runs = [x for xs in per_log.values() for x in xs]
            per = {l: mean([x["score"] for x in xs]) for l, xs in per_log.items()}
            per_log_stats = {l: {k: spread([x[k] for x in xs])
                                 for k in ["score", "kinds_found", "rare_found", "false_claims",
                                           "tokens_io", "tokens_cache"]}
                             for l, xs in per_log.items()}
            summary.setdefault(m, {})[g] = {
                "score_per_log": per, "per_log": per_log_stats,
                "tokens_io_mean": mean([x["tokens_io"] for x in runs]),
                "tokens_cache_mean": mean([x["tokens_cache"] for x in runs]), "score_sum": round(sum(v for v in per.values() if v is not None), 2),
                "false_claims_per_run": mean([x["false_claims"] for x in runs]),
                "tokens_mean": mean([x["tokens"] for x in runs]),
                "seconds_mean": mean([x["seconds"] for x in runs])}

    prev = json.loads(OUT.read_text()) if OUT.is_file() else {}
    bar = {}
    for m, s in summary.items():
        checks = {"S_beats_R_on_mean_score": s["S"]["score_sum"] > s["R"]["score_sum"],
                  "S_false_claims_le_R": s["S"]["false_claims_per_run"] <= s["R"]["false_claims_per_run"]}
        p = prev.get("summary", {}).get(m, {}).get("S")
        if p and set(p["score_per_log"]) == set(s["S"]["score_per_log"]):
            checks["S_not_below_previous"] = s["S"]["score_sum"] >= p["score_sum"]
        bar[m] = checks

    def out(cmd):
        return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    doc = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "git_head": out(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
           "lessence": out([a.lessence, "--version"]), "claude_cli": out(["claude", "--version"]),
           "release": a.release, "logs": logs,
           "models": {"solvers": [SOLVER] + ([RELEASE_SOLVER] if a.release else []), "scorer": SCORER},
           "runs_per_group": a.runs, "reused_runs": sorted(reused), "results": results, "summary": summary,
           "bar": bar, "key_errors": key_errors, "transcripts": str(tdir)}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT.with_name("value.json.tmp")
    tmp.write_text(json.dumps(doc, indent=2) + "\n")
    tmp.replace(OUT)

    ok = True
    for m, s in summary.items():
        print(f"{m}: R {s['R']['score_sum']}/{6 * len(logs)} ({s['R']['false_claims_per_run']} false/run), "
              f"S {s['S']['score_sum']}/{6 * len(logs)} ({s['S']['false_claims_per_run']} false/run)")
        for name, passed in bar[m].items():
            print(f"  {'pass' if passed else 'FAIL'} {name}")
            ok &= passed
        print(f"  {'log':<22} grp {'score':<16} {'kinds':<16} {'rare':<14} {'false':<12} "
              f"{'tok in+out':<10} cache")
        for log in logs:
            for g in ["R", "S"]:
                st = s[g]["per_log"].get(log, {})
                print(f"  {log:<22} {g:<3} {fmt(st.get('score')):<16} {fmt(st.get('kinds_found')):<16} "
                      f"{fmt(st.get('rare_found')):<14} {fmt(st.get('false_claims')):<12} "
                      f"{(st.get('tokens_io') or {}).get('mean', '-')!s:<10} "
                      f"{(st.get('tokens_cache') or {}).get('mean', '-')}")
    for e in key_errors:
        print(f"key error: {e}")
    print(f"value.json: {OUT}; transcripts: {doc['transcripts']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
