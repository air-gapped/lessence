#!/usr/bin/env python3
"""The gate's size check: default stdout/stderr bytes and tokens per corpus
against the reviewed baseline in tests/fixtures, plus max(128, 1%).

Fails closed. A missing tokenizer, a missing baseline file, a corpus absent
from the baseline, or a missing field in a baseline entry is an error, never
a skip. Creating the baseline is a separate, explicit operation (`bless`),
never implied by an ordinary run.

Two size numbers per stream, and they are not the same number:

  * the 16 KiB bound is asserted on the actual, unmodified stdout bytes of
    the run, because that is the promise the tool makes;
  * the comparative metric replaces the one part of the overview whose size
    says nothing about the overview — the report path, run id and byte size,
    all of which vary with where the repository sits and when it ran — with
    fixed placeholders, so the baseline is comparable across machines.

Prints one JSON object and exits 0 even when it has errors; the caller reads
`errors` and `over` and decides the verdict, so gate.json records the whole
measurement either way.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

# Every field a baseline entry must carry. The four size fields are compared;
# the rest are recorded per run so a change in what the overview selected is
# visible next to the bytes it took.
COMPARED = ("stdout_bytes", "stderr_bytes", "stdout_tokens", "stderr_tokens")
REQUIRED = COMPARED + ("corpus_sha256", "total", "selected", "printed", "omitted", "previewed")
STDOUT_LIMIT = 16 * 1024
ENCODING = "cl100k_base"

LOCATOR = re.compile(
    r"groups: (\d+) total, (\d+) selected, (\d+) printed, (\d+) omitted"
)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv):
    binary, baseline_path, corpora, bless = argv[1], argv[2], argv[3:-1], argv[-1] == "bless"
    errors = []

    try:
        import tiktoken

        enc = tiktoken.get_encoding(ENCODING)
        tokenizer = {
            "name": "tiktoken",
            "encoding": ENCODING,
            "version": getattr(tiktoken, "__version__", "unknown"),
        }
    except Exception as e:  # noqa: BLE001 - any import/encoding failure is the same fault
        enc = None
        tokenizer = None
        errors.append("tokenizer unavailable: tiktoken %s (%s)" % (ENCODING, e))

    def tokens(s):
        return None if enc is None else len(enc.encode(s, disallowed_special=()))

    baseline = {}
    baseline_sha = None
    if os.path.exists(baseline_path):
        baseline_sha = sha256_file(baseline_path)
        baseline = json.load(open(baseline_path)).get("corpora", {})
    elif not bless:
        errors.append(
            "baseline %s does not exist — create it explicitly with GATE_BLESS_SIZE=1"
            % baseline_path
        )

    measured = {}
    # Under target/, not /tmp: /tmp is a tmpfs on most distributions and the
    # filesystem policy rejects it for a report directory.
    os.makedirs("target/gate", exist_ok=True)
    with tempfile.TemporaryDirectory(dir="target/gate") as reports:
        for path in corpora:
            name = os.path.basename(path)[:-4]
            run = subprocess.run(
                [binary, "--threads", "1", "--report-dir", reports, path],
                capture_output=True,
            )
            if run.returncode != 0:
                errors.append(
                    "%s exited %d: %s"
                    % (path, run.returncode, run.stderr.decode("utf-8", "replace")[:300])
                )
                continue
            if len(run.stdout) > STDOUT_LIMIT:
                errors.append(
                    "%s: stdout is %d bytes, over the %d-byte bound"
                    % (name, len(run.stdout), STDOUT_LIMIT)
                )

            def scrub(b):
                s = b.decode("utf-8", "replace")
                s = re.sub(
                    re.escape(reports) + r"/run-[0-9-]+-[0-9a-f]{8}/report\.jsonl",
                    "<REPORT>",
                    s,
                )
                s = re.sub(r"run: \S+", "run: <RUN>", s)
                return re.sub(r"size: \d+ bytes", "size: <SIZE> bytes", s)

            out, err = scrub(run.stdout), scrub(run.stderr)
            counts = LOCATOR.search(out)
            entry = {
                "stdout_bytes": len(out.encode()),
                "stderr_bytes": len(err.encode()),
                "stdout_tokens": tokens(out),
                "stderr_tokens": tokens(err),
                "corpus_sha256": sha256_file(path),
                "previewed": out.count("previewed here:"),
            }
            for i, field in enumerate(("total", "selected", "printed", "omitted")):
                entry[field] = int(counts.group(i + 1)) if counts else None
            if counts is None:
                errors.append("%s: no locator line in stdout to read the counts from" % name)
            measured[name] = entry

    over = []
    if not bless:
        for name, now in sorted(measured.items()):
            was = baseline.get(name)
            if not was:
                errors.append("corpus %s is not in the baseline %s" % (name, baseline_path))
                continue
            for field in REQUIRED:
                if was.get(field) is None:
                    errors.append("baseline %s is missing field %s" % (name, field))
            for field in COMPARED:
                old, value = was.get(field), now.get(field)
                if old is None:
                    continue
                if value is None:
                    errors.append("%s: field %s was not measured" % (name, field))
                    continue
                allowance = max(128, old // 100)
                if value > old + allowance:
                    over.append(
                        {
                            "corpus": name,
                            "field": field,
                            "baseline": old,
                            "now": value,
                            "allowance": allowance,
                        }
                    )

    if bless:
        if errors:
            print(json.dumps({"errors": errors, "over": [], "corpora": {}}))
            return 0
        json.dump(
            {
                "note": "reviewed size baseline; + max(128, 1%) is the gate allowance",
                "tokenizer": tokenizer,
                "corpora": measured,
            },
            open(baseline_path, "w"),
            indent=2,
            sort_keys=True,
        )
        open(baseline_path, "a").write("\n")
        baseline_sha = sha256_file(baseline_path)

    print(
        json.dumps(
            {
                "tokenizer": tokenizer,
                "baseline": os.path.basename(baseline_path),
                "baseline_sha256": baseline_sha,
                "stdout_limit_bytes": STDOUT_LIMIT,
                "corpora_measured": len(measured),
                "corpora_baselined": len(baseline),
                "corpora": measured,
                "errors": errors,
                "over": over,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
