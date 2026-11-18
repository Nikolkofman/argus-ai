"""
Argus Copilot — HTTP service (FastAPI).

    uvicorn argus_copilot.api:app --host 127.0.0.1 --port 8100

Endpoints
    GET  /health          liveness, active backend, capture, ML status
    GET  /processes       flagged processes in the capture (?all=true for every pid)
    POST /explain/{pid}   incident report for one process
    POST /ask             free-form question about the capture

Capture source, per request, in priority order:
    1. `capture_text` in the body   (inline NDJSON / agent-log text)
    2. `capture_path` in the body   (must be inside ARGUS_CAPTURE_ROOT)
    3. ARGUS_CAPTURE                (env: path to the agent log / capture file)

Backend: Claude when ANTHROPIC_API_KEY is set and ARGUS_USE_MOCK is not;
otherwise the offline mock.

Security: the service reads local files, so it binds to 127.0.0.1 in the
examples and only reads paths under ARGUS_CAPTURE_ROOT (default: the working
directory). It is a local analyst tool, not an internet-facing service.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import __version__, ml_bridge
from .agent import analyze_process, ask
from .events import Capture, parse_file, parse_text
from .llm import make_backend

app = FastAPI(title="Argus Copilot", version=__version__,
              description="LLM incident analyst over ArgusEDR telemetry.")


class CaptureSource(BaseModel):
    capture_text: Optional[str] = None
    capture_path: Optional[str] = None


class AskRequest(CaptureSource):
    question: str
    pid: Optional[int] = None


def _capture_root() -> Path:
    return Path(os.environ.get("ARGUS_CAPTURE_ROOT", os.getcwd())).resolve()


def _load_capture(src: Optional[CaptureSource]) -> Capture:
    if src and src.capture_text:
        return parse_text(src.capture_text)
    path = (src.capture_path if src else None) or os.environ.get("ARGUS_CAPTURE")
    if not path:
        raise HTTPException(400, "No capture: send capture_text / capture_path "
                                 "or set ARGUS_CAPTURE.")
    p = Path(path).resolve()
    if src and src.capture_path:
        root = _capture_root()
        if p != root and root not in p.parents:
            raise HTTPException(403, f"capture_path must be inside {root}")
    if not p.is_file():
        raise HTTPException(404, f"Capture file not found: {p}")
    return parse_file(p)


def _backend():
    try:
        return make_backend()
    except RuntimeError as e:
        raise HTTPException(500, str(e))


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "backend": _backend().name,
            "capture": os.environ.get("ARGUS_CAPTURE"), "ml": ml_bridge.status()}


@app.get("/processes")
def processes(all: bool = False) -> list[dict]:  # noqa: A002 — query param name
    return _load_capture(None).summary(only_flagged=not all)


@app.post("/explain/{pid}")
def explain(pid: int, src: Optional[CaptureSource] = None) -> dict:
    cap = _load_capture(src)
    if cap.get(pid) is None:
        raise HTTPException(404, f"No telemetry for pid {pid} (known: {cap.pids()[:50]})")
    return {"pid": pid, **analyze_process(_backend(), cap, pid).to_dict()}


@app.post("/ask")
def ask_endpoint(req: AskRequest) -> dict:
    cap = _load_capture(req)
    return ask(_backend(), cap, req.question, pid=req.pid).to_dict()
