"""
Eval harness: run the agent on labelled scenarios and score it.

    python evals/run_evals.py                 # mock backend, offline (CI)
    python evals/run_evals.py --real          # Claude (needs ANTHROPIC_API_KEY)
    python evals/run_evals.py --real --out results_real.json

Scores classification (the gate), false-positive rate on benign cases, and
severity / ATT&CK technique agreement. Exits non-zero if classification
accuracy is below --min-accuracy, so it can block CI.

Read the mock numbers honestly: the mock is deterministic, so a mock PASS
proves the pipeline and the harness work, not that the analysis is smart.
The interesting run is --real.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from argus_copilot import analyze_process, make_backend, parse_file  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", action="store_true", help="use Claude instead of the mock")
    ap.add_argument("--model", default=None)
    ap.add_argument("--cases", default=str(ROOT / "cases.json"))
    ap.add_argument("--min-accuracy", type=float, default=1.0)
    ap.add_argument("--out", help="write per-case results to this JSON file")
    ap.add_argument("-v", "--verbose", action="store_true", help="print each report")
    args = ap.parse_args(argv)

    backend = make_backend(use_mock=not args.real, model=args.model)
    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    base = Path(args.cases).resolve().parent

    rows = []
    print(f"backend: {backend.name}   cases: {len(cases)}\n")
    print(f"{'case':22} {'expect':10} {'got':10} {'sev exp/got':19} "
          f"{'tech exp/got':23} {'tools':>5}")
    for c in cases:
        cap = parse_file(base / c["file"])
        t0 = time.time()
        res = analyze_process(backend, cap, c["pid"])
        dt = time.time() - t0
        got = res.classification or {}
        exp = c["expect"]
        row = {
            "id": c["id"], "expect": exp, "got": got,
            "class_ok": got.get("classification") == exp["classification"],
            "sev_ok": str(got.get("severity", "")).upper() == exp["severity"],
            "tech_ok": (got.get("technique_id") == exp["technique_id"])
                       if exp["technique_id"] else None,
            "tools": [t.name for t in res.tool_trace], "seconds": round(dt, 2),
            "report": res.report,
        }
        rows.append(row)
        mark = "ok" if row["class_ok"] else "FAIL"
        print(f"{c['id']:22} {exp['classification']:10} "
              f"{str(got.get('classification')):10} "
              f"{exp['severity'] + '/' + str(got.get('severity')):19} "
              f"{str(exp['technique_id'] or '-') + '/' + str(got.get('technique_id') or '-'):23} "
              f"{len(res.tool_trace):>5}  {mark}")
        if args.verbose:
            print("\n" + res.report + "\n")

    n = len(rows)
    acc = sum(r["class_ok"] for r in rows) / n
    benign = [r for r in rows if r["expect"]["classification"] == "benign"]
    fp = sum(r["got"].get("classification") != "benign" for r in benign)
    sev = sum(r["sev_ok"] for r in rows) / n
    tech_rows = [r for r in rows if r["tech_ok"] is not None]
    tech = sum(r["tech_ok"] for r in tech_rows)

    print(f"\nclassification accuracy: {acc:.0%} ({sum(r['class_ok'] for r in rows)}/{n})"
          f" · FP: {fp}/{len(benign)} benign"
          f" · severity match: {sev:.0%}"
          f" · technique match: {tech}/{len(tech_rows)}")

    if args.out:
        Path(args.out).write_text(json.dumps({"backend": backend.name, "rows": rows},
                                             indent=2), encoding="utf-8")
        print(f"results -> {args.out}")

    if acc < args.min_accuracy:
        print(f"FAIL — accuracy {acc:.0%} < {args.min_accuracy:.0%}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
