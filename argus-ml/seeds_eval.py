"""
Multi-seed evaluation — the protocol behind the numbers in RESULTS.md.

With 55 traces, one training run can be lucky or unlucky, so every metric is
measured over several seeds:

  1. train on all traces → detection / FPR / AUC / per-technique detection,
     both on the traces as captured and with timestamps removed (as in the
     live agent log, which has none);
  2. leave-one-technique-out: hold each injection technique out of training
     entirely and measure detection on it.

    python seeds_eval.py --data "data/*.ndjson"            # 5 seeds (default)
    python seeds_eval.py --data "data/*.ndjson" --seeds 10

To reproduce the "before" column of RESULTS §6, set USE_TIMING = True in
schema.py and run it again.
"""

from __future__ import annotations

import argparse
import glob
import json
import statistics

import torch

from dataset import TraceDataset, load_many
from evaluate import leave_one_technique_out, metrics
from schema import FEATURE_NAMES, USE_TIMING
from train import train


def _strip_timestamps(trace: dict) -> dict:
    return {**trace, "events": [{k: v for k, v in e.items() if k != "t_ms"}
                                for e in trace["events"]]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", nargs="+", required=True)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--json", action="store_true", help="print raw per-seed results")
    args = ap.parse_args()

    paths = sorted(p for pat in args.data for p in glob.glob(pat))
    traces = load_many(paths)
    no_ts = [_strip_timestamps(t) for t in traces]
    runs = []
    for seed in range(args.seeds):
        torch.manual_seed(seed)
        model, _ = train(TraceDataset.from_traces(traces), epochs=args.epochs,
                         seed=seed, verbose=False)
        torch.manual_seed(seed)
        loto = leave_one_technique_out(traces, epochs=args.epochs, seed=seed)
        runs.append({
            "seed": seed,
            "captured": metrics(model, TraceDataset.from_traces(traces)),
            "no_timestamps": metrics(model, TraceDataset.from_traces(no_ts)),
            "loto": {k: v["detection_rate"] for k, v in loto.items()},
        })

    if args.json:
        print(json.dumps(runs, indent=2, default=float))
        return

    mean = lambda xs: statistics.mean(xs)  # noqa: E731
    print(f"{len(traces)} traces · {len(FEATURE_NAMES)} features · "
          f"USE_TIMING={USE_TIMING} · {args.seeds} seeds\n")
    for view in ("captured", "no_timestamps"):
        r = [x[view] for x in runs]
        print(f"[{view}] detection {mean(m['detection_rate'] for m in r):.1%}  "
              f"FPR {mean(m['false_positive_rate'] for m in r):.1%}  "
              f"AUC {mean(m['auc'] for m in r):.3f}")
        for tech in sorted(r[0]["per_technique_detection"]):
            vals = [m["per_technique_detection"][tech] for m in r]
            print(f"    {tech:18} {mean(vals):6.1%}")
    print("\n[leave-one-technique-out] detection on the held-out technique")
    for tech in sorted(runs[0]["loto"]):
        vals = [x["loto"][tech] for x in runs]
        print(f"    {tech:18} {mean(vals):6.1%}   per seed {vals}")


if __name__ == "__main__":
    main()
