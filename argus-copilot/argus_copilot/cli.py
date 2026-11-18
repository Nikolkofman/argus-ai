"""
Command-line interface.

  python -m argus_copilot processes data/remote_thread.ndjson
  python -m argus_copilot analyze   data/remote_thread.ndjson --mock -v
  python -m argus_copilot analyze   argus_agent.log --pid 4120          # Claude if a key is set
  python -m argus_copilot ask       data/remote_thread.ndjson "why was 4120 flagged?" --mock
  python -m argus_copilot ml-status
"""

from __future__ import annotations

import argparse
import json
import sys

from . import ml_bridge
from .agent import analyze_process, ask
from .events import parse_file
from .llm import make_backend


def _backend(args):
    b = make_backend(use_mock=True if args.mock else None, model=args.model)
    if b.name == "mock" and not args.mock:
        print("[argus-copilot] no ANTHROPIC_API_KEY — using the mock backend", file=sys.stderr)
    return b


def _emit(result, args) -> None:
    if args.verbose:
        for inv in result.tool_trace:
            print(f"  · {inv.name}({', '.join(f'{k}={v!r}' for k, v in inv.input.items())})",
                  file=sys.stderr)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.report)
        print()


def cmd_processes(args) -> int:
    cap = parse_file(args.capture)
    rows = cap.summary(only_flagged=not args.all)
    if not rows:
        print("No flagged processes (use --all to list every process).")
        return 0
    print(f"{'pid':>7}  {'severity':9} {'events':>6} {'findings':>8}  name")
    for r in rows:
        print(f"{r['pid']:>7}  {r['severity']:9} {r['events']:>6} {r['findings']:>8}  "
              f"{r['name'] or '-'}")
    return 0


def cmd_analyze(args) -> int:
    cap = parse_file(args.capture)
    pids = [args.pid] if args.pid is not None else cap.flagged_pids()
    if not pids:
        print("No flagged processes in this capture. Pass --pid to analyze one.")
        return 0
    backend = _backend(args)
    for pid in pids:
        _emit(analyze_process(backend, cap, pid), args)
    return 0


def cmd_ask(args) -> int:
    cap = parse_file(args.capture)
    _emit(ask(_backend(args), cap, args.question, pid=args.pid), args)
    return 0


def cmd_ml_status(args) -> int:
    print(json.dumps(ml_bridge.status(), indent=2))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="argus-copilot",
                                 description="LLM incident analyst for ArgusEDR telemetry.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, question=False):
        p.add_argument("capture", help="agent .log, .ndjson capture, or argus-ml trace file")
        if question:
            p.add_argument("question")
        p.add_argument("--pid", type=int)
        p.add_argument("--mock", action="store_true", help="offline deterministic backend")
        p.add_argument("--model", default=None, help="Claude model id (real backend)")
        p.add_argument("--json", action="store_true", help="print the full result as JSON")
        p.add_argument("-v", "--verbose", action="store_true", help="show the tool calls")

    p = sub.add_parser("processes", help="list flagged processes")
    p.add_argument("capture")
    p.add_argument("--all", action="store_true")
    p.set_defaults(fn=cmd_processes)

    p = sub.add_parser("analyze", help="incident report per flagged process (or --pid)")
    common(p)
    p.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("ask", help="free-form question about the capture")
    common(p, question=True)
    p.set_defaults(fn=cmd_ask)

    p = sub.add_parser("ml-status", help="is the GRU detector available?")
    p.set_defaults(fn=cmd_ml_status)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
