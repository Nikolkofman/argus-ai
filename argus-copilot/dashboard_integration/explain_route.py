"""
Drop-in "Explain" route for the ArgusEDR dashboard (dashboard/server.py).

Adds   POST /api/explain/{pid}   → incident report for one process
       GET  /api/explain/status   → which backend / log / ML model is active

It reads the SAME agent log the dashboard already tails, so there is no new
data path. Wire it into server.py with two lines:

    from explain_route import router as explain_router
    app.include_router(explain_router)

Configuration (environment):
    ARGUS_AGENT_LOG    path to argus_agent.log   (default: build/bin/Release/argus_agent.log)
    ANTHROPIC_API_KEY  use Claude; without it the offline mock answers
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException

from argus_copilot import analyze_process, make_backend, parse_file
from argus_copilot import ml_bridge

router = APIRouter(prefix="/api/explain", tags=["copilot"])

DEFAULT_LOG = Path("build") / "bin" / "Release" / "argus_agent.log"


def _log_path() -> Path:
    return Path(os.environ.get("ARGUS_AGENT_LOG", str(DEFAULT_LOG)))


@router.get("/status")
def status() -> dict:
    log = _log_path()
    return {"backend": make_backend().name, "agent_log": str(log),
            "log_exists": log.is_file(), "ml": ml_bridge.status()}


@router.post("/{pid}")
def explain(pid: int) -> dict:
    log = _log_path()
    if not log.is_file():
        raise HTTPException(404, f"Agent log not found: {log} (set ARGUS_AGENT_LOG)")
    cap = parse_file(log)  # re-read on each click: the log is small and always current
    if cap.get(pid) is None:
        raise HTTPException(404, f"No telemetry for pid {pid} in the current run")
    result = analyze_process(make_backend(), cap, pid)
    return {"pid": pid, **result.to_dict()}
