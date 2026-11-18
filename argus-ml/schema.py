"""
Argus EDR — ML feature schema.

This module is the single source of truth for two things:

1. The on-disk *trace* format (one process's event sequence + a label).
2. How each hook event becomes a fixed-length numeric feature vector.

A *trace* is one monitored process's lifetime, as seen by the Argus hooks:
an ordered list of events (the six hooked Win32 APIs) plus a label saying
whether that process was benign or the victim of an injection, and which
technique produced it. On disk a trace is ONE JSON object per line (NDJSON),
so a dataset file is just many traces concatenated.

Example trace line:
    {"label": "injection", "technique": "remote_thread", "pid": 4812,
     "events": [
        {"api": "VirtualAllocEx", "pid": 900, "target_pid": 4812,
         "size": 4096, "protect": 64, "t_ms": 0},
        {"api": "WriteProcessMemory", "pid": 900, "target_pid": 4812,
         "size": 320, "t_ms": 12},
        ...
     ]}

The feature vector per event is intentionally small and interpretable — the
point of the model is to learn the *shape* of a sequence, not to memorise
exact addresses. Addresses are deliberately dropped (they carry no signal and
would let the model overfit to one run).
"""

from __future__ import annotations

import math
from typing import Any

# ── The six hooked APIs, in a fixed order (index = one-hot position) ──────────
API_NAMES = [
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "VirtualProtect",
    "CreateThread",
    "CreateRemoteThread",
]
API_INDEX = {name: i for i, name in enumerate(API_NAMES)}
N_API = len(API_NAMES)

# ── Windows memory-protection constants (winnt.h) ─────────────────────────────
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08

_EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
_WRITE_MASK = (
    PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
)


def protect_is_exec(protect: int | None) -> bool:
    """True if a protection value grants execute permission."""
    return bool(protect) and bool(int(protect) & _EXEC_MASK)


def protect_is_write(protect: int | None) -> bool:
    """True if a protection value grants write permission."""
    return bool(protect) and bool(int(protect) & _WRITE_MASK)


# ── Feature layout ────────────────────────────────────────────────────────────
# [ api one-hot (6) | cross_process | exec | write | log10(size) | log10(dt_ms) ]
FEATURE_NAMES = API_NAMES + [
    "cross_process",   # target_pid != pid  → a cross-process operation
    "exec_protect",    # protection grants execute
    "write_protect",   # protection grants write
    "log_size",        # log10(size + 1), 0 for thread events
    "log_dt_ms",       # log10(inter-event delta + 1); 0 for the first event
]
N_FEATURES = len(FEATURE_NAMES)


def event_to_vector(event: dict[str, Any], prev_t_ms: float | None) -> list[float]:
    """Convert one event dict into a fixed-length feature vector.

    prev_t_ms is the timestamp of the previous event in the same trace (or None
    for the first event), used to derive the inter-event time delta.
    """
    vec = [0.0] * N_FEATURES

    api = event.get("api", "")
    idx = API_INDEX.get(api)
    if idx is not None:
        vec[idx] = 1.0

    pid = event.get("pid")
    target_pid = event.get("target_pid", pid)
    vec[N_API + 0] = 1.0 if (target_pid is not None and target_pid != pid) else 0.0

    protect = event.get("protect")
    vec[N_API + 1] = 1.0 if protect_is_exec(protect) else 0.0
    vec[N_API + 2] = 1.0 if protect_is_write(protect) else 0.0

    size = event.get("size", 0) or 0
    vec[N_API + 3] = math.log10(size + 1.0)

    t_ms = event.get("t_ms")
    if t_ms is not None and prev_t_ms is not None:
        dt = max(0.0, float(t_ms) - float(prev_t_ms))
    else:
        dt = 0.0
    vec[N_API + 4] = math.log10(dt + 1.0)

    return vec


def trace_to_matrix(trace: dict[str, Any]) -> list[list[float]]:
    """Convert a full trace into a list of per-event feature vectors (a matrix
    of shape [n_events, N_FEATURES])."""
    rows: list[list[float]] = []
    prev_t: float | None = None
    for ev in trace.get("events", []):
        rows.append(event_to_vector(ev, prev_t))
        prev_t = ev.get("t_ms", prev_t)
    return rows


# ── Labels ────────────────────────────────────────────────────────────────────
LABEL_BENIGN = "benign"
LABEL_INJECTION = "injection"
LABEL_TO_INT = {LABEL_BENIGN: 0, LABEL_INJECTION: 1}
