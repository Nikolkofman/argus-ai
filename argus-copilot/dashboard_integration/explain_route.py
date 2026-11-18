"""
"Explain" route for the ArgusEDR dashboard (edr/dashboard/server.py).

Adds   POST /api/explain/{pid}   → incident report for one process
       GET  /api/explain/status   → active backend, agent log, ML model

It reads the SAME agent log the dashboard already tails, so there is no new
data path. In this repo, server.py enables it automatically:

    import explain_route
    explain_route.configure(lambda: _find_bin_dir() / "argus_agent.log")
    app.include_router(explain_route.router)

Elsewhere, set ARGUS_AGENT_LOG instead of calling configure().
Without ANTHROPIC_API_KEY the offline mock answers; with it, Claude does.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Optional

from fastapi import APIRouter, HTTPException

from argus_copilot import analyze_process, make_backend, ml_bridge, parse_file

router = APIRouter(prefix="/api/explain", tags=["copilot"])

DEFAULT_LOG = Path("build") / "bin" / "argus_agent.log"
_log_path_fn: Optional[Callable[[], Path]] = None


def configure(log_path_fn: Callable[[], Path]) -> None:
    """Tell the route where the agent log is (called once by the dashboard)."""
    global _log_path_fn
    _log_path_fn = log_path_fn


def _log_path() -> Path:
    if os.environ.get("ARGUS_AGENT_LOG"):
        return Path(os.environ["ARGUS_AGENT_LOG"])
    if _log_path_fn is not None:
        return Path(_log_path_fn())
    return DEFAULT_LOG


@router.get("/status")
def status() -> dict:
    log = _log_path()
    return {"backend": make_backend().name, "agent_log": str(log),
            "log_exists": log.is_file(), "ml": ml_bridge.status()}


@router.post("/{pid}")
def explain(pid: int) -> dict:
    # Plain `def`: FastAPI runs it in a worker thread, so a slow model call
    # never blocks the dashboard's event loop or its live WebSocket feed.
    log = _log_path()
    if not log.is_file():
        raise HTTPException(404, f"Agent log not found: {log}. Run the demo first.")
    cap = parse_file(log)  # re-read on each click: the log is small and always current
    if cap.get(pid) is None:
        raise HTTPException(404, f"No telemetry for PID {pid} in the current run.")
    try:
        result = analyze_process(make_backend(), cap, pid)
    except RuntimeError as e:  # e.g. Claude backend misconfigured
        raise HTTPException(500, str(e))
    return {"pid": pid, **result.to_dict()}
