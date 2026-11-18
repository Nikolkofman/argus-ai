"""
Argus EDR — trace recorder (run this on Windows during data collection).

Continuous collector. It follows the running agent's log, groups the hook
events the agent prints (`[IPC] event: {...}`) by the process they act on, and
appends one labelled trace per process — automatically — as each process goes
quiet. It also notices when a new agent run starts (the dashboard resets the log
on every RUN DEMO, and each run begins with the agent banner) and finalises the
previous run's traces at that point.

This is a defensive logging tool: it only reads log lines the agent already
emits and writes them out as structured rows. It injects nothing and runs no
attack code.

Live feedback: it prints a line when it starts capturing a process and when it
saves a trace, so you can see it working in real time.

Timing note: the raw events carry no timestamp, so t_ms here is arrival time
relative to that process's first event. Good enough for a first model; if you
later add a real timestamp field to the event JSON, it is used automatically.

Typical use (one console, left running):
    python collect.py --agent-log "..\\build\\bin\\Debug\\argus_agent.log" ^
        --label injection --technique remote_thread --out data\\injection.ndjson

Then click RUN DEMO a few times (or run a test repeatedly). Each run is saved
as a trace. Ctrl-C when done. The output file is appended to, so restarting the
recorder does not wipe earlier captures (delete the file to start fresh).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path

EVENT_RE = re.compile(r"\[IPC\] event: (\{.+\})")
AGENT_BANNER = "ArgusEDR Agent"  # printed once at the start of every agent run


def _extract_event(line: str) -> dict | None:
    m = EVENT_RE.search(line)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-log", required=True, type=Path)
    ap.add_argument("--label", required=True, choices=["benign", "injection"])
    ap.add_argument("--technique", default="",
                    help="e.g. remote_thread, process_hollowing, module_stomping, "
                         "shellcode_runner (injection runs only)")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--flush-idle", type=float, default=30.0,
                    help="finalise a process's trace after this many seconds of silence. "
                         "Must exceed the gap between a single run's events (the dashboard "
                         "spreads one run's hook events over ~20s), so a run is not split.")
    ap.add_argument("--min-events", type=int, default=2,
                    help="skip processes with fewer than this many events")
    ap.add_argument("--from-start", action="store_true",
                    help="read the whole existing log first (default: only new content)")
    args = ap.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    out = open(args.out, "a", encoding="utf-8")  # append — restarts don't wipe
    saved = {"n": 0}
    active: dict[int, dict] = {}  # pid -> {"first","last","events"}

    def flush(pid: int):
        tr = active.pop(pid, None)
        if not tr or len(tr["events"]) < args.min_events:
            return
        trace = {"label": args.label, "technique": args.technique,
                 "pid": pid, "events": tr["events"]}
        out.write(json.dumps(trace) + "\n")
        out.flush()
        saved["n"] += 1
        print(f"[collect] saved trace #{saved['n']}: pid={pid}, {len(tr['events'])} events")

    def flush_all():
        for pid in list(active.keys()):
            flush(pid)

    def note(event: dict):
        pid = event.get("target_pid", event.get("pid"))
        if pid is None:
            return
        now = time.time()
        tr = active.get(pid)
        if tr is None:
            tr = {"first": now, "last": now, "events": []}
            active[pid] = tr
            print(f"[collect] capturing new process pid={pid} ...")
        if "t_ms" in event or "ts_ms" in event:
            t_ms = float(event.get("t_ms", event.get("ts_ms")))
        else:
            t_ms = round((now - tr["first"]) * 1000.0, 1)
        rec = dict(event)
        rec["t_ms"] = t_ms
        tr["events"].append(rec)
        tr["last"] = now

    print(f"[collect] label={args.label} technique={args.technique or '-'} -> {args.out}")
    print("[collect] continuous mode — run your tests; traces save automatically.")
    print("[collect] Ctrl-C to finish.")

    while not args.agent_log.exists():
        print("[collect] waiting for agent log to appear ...")
        time.sleep(1.0)

    # Binary mode so byte positions match os.path.getsize (no CRLF/encoding drift).
    fh = open(args.agent_log, "rb")
    pos = fh.seek(0, 2) if not args.from_start else 0
    buf = ""

    try:
        while True:
            try:
                size = os.path.getsize(args.agent_log)
            except OSError:
                size = pos

            if size < pos:
                # log was reset (new agent run) — finalise the previous run
                flush_all()
                print("[collect] --- new run detected (log reset) ---")
                pos = 0
                buf = ""

            if size > pos:
                fh.seek(pos)
                chunk = fh.read(size - pos)
                pos = fh.tell()
                buf += chunk.decode("utf-8", "replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if AGENT_BANNER in line:
                        # a fresh agent run started within the same file
                        flush_all()
                    ev = _extract_event(line)
                    if ev is not None:
                        note(ev)
            else:
                now = time.time()
                for pid in list(active.keys()):
                    if now - active[pid]["last"] > args.flush_idle:
                        flush(pid)
                time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[collect] finishing ...")
    finally:
        flush_all()
        out.close()
        print(f"[collect] done — {saved['n']} new trace(s) appended to {args.out}")


if __name__ == "__main__":
    main()
