"""
The agent's tools.

Each tool is a plain Python function over a `Capture` that returns a JSON-able
dict. `TOOL_SPECS` describes them to the model (Anthropic tool-use schema);
`run_tool` dispatches a model's tool call to the right function.

Tools return facts from the telemetry, never conclusions — the conclusion is
the model's job, and it has to be grounded in what the tools returned.
"""

from __future__ import annotations

from typing import Any

from . import mitre
from .events import Capture

_EXEC_MASK = 0x10 | 0x20 | 0x40 | 0x80        # PAGE_EXECUTE*
_WRITE_MASK = 0x04 | 0x08 | 0x40 | 0x80       # PAGE_READWRITE / WRITECOPY / EXECUTE_RW*
PAGE_EXECUTE_READWRITE = 0x40

ALLOC_APIS = {"VirtualAlloc", "VirtualAllocEx"}
THREAD_APIS = {"CreateThread", "CreateRemoteThread"}

MAX_TIMELINE_EVENTS = 200


def _flags(protect: Any) -> tuple[bool, bool]:
    try:
        p = int(protect)
    except (TypeError, ValueError):
        return False, False
    return bool(p & _EXEC_MASK), bool(p & _WRITE_MASK)


def _not_found(cap: Capture, pid: Any) -> dict[str, Any]:
    return {"pid": pid, "found": False, "error": f"No telemetry for pid {pid}.",
            "known_pids": cap.pids()[:50]}


# ── tool implementations ─────────────────────────────────────────────────────

def get_process_timeline(cap: Capture, pid: int) -> dict[str, Any]:
    """Ordered hook events for one process, plus a summary of the injection chain."""
    proc = cap.get(int(pid))
    if proc is None:
        return _not_found(cap, pid)

    events = []
    chain = {"alloc": False, "write": False, "exec_protect": False,
             "thread": False, "cross_process": False, "cross_process_write": False,
             "rwx_alloc": False}
    for i, ev in enumerate(proc.events):
        api = ev.get("api", "")
        actor = ev.get("pid")
        target = ev.get("target_pid", actor)
        cross = target is not None and actor is not None and target != actor
        is_exec, is_write = _flags(ev.get("protect"))

        chain["alloc"] |= api in ALLOC_APIS
        chain["write"] |= api == "WriteProcessMemory"
        chain["exec_protect"] |= is_exec and (api == "VirtualProtect" or api in ALLOC_APIS)
        chain["thread"] |= api in THREAD_APIS
        chain["cross_process"] |= cross
        chain["cross_process_write"] |= cross and api == "WriteProcessMemory"
        chain["rwx_alloc"] |= api in ALLOC_APIS and ev.get("protect") == PAGE_EXECUTE_READWRITE

        if i < MAX_TIMELINE_EVENTS:
            row = {"i": i, "api": api, "actor_pid": actor, "target_pid": target,
                   "cross_process": cross}
            if "size" in ev:
                row["size"] = ev["size"]
            if "protect" in ev:
                row["protect"] = hex(int(ev["protect"])) if ev["protect"] is not None else None
                row["exec"], row["write"] = is_exec, is_write
            if "t_ms" in ev:
                row["t_ms"] = ev["t_ms"]
            events.append(row)

    # collapse consecutive repeats for a readable one-liner
    seq: list[str] = []
    for ev in proc.events:
        api = ev.get("api", "?")
        if seq and seq[-1].split(" ×")[0] == api:
            base, _, n = seq[-1].partition(" ×")
            seq[-1] = f"{base} ×{int(n or 1) + 1}"
        else:
            seq.append(api)

    return {
        "pid": proc.pid, "found": True, "name": proc.name or None,
        "n_events": len(proc.events), "truncated": len(proc.events) > MAX_TIMELINE_EVENTS,
        "api_sequence": " → ".join(seq),
        "chain": chain,
        "events": events,
    }


def get_findings(cap: Capture, pid: int) -> dict[str, Any]:
    """Memory-scanner / YARA findings and Diamond FSM verdicts for one process."""
    proc = cap.get(int(pid))
    if proc is None:
        return _not_found(cap, pid)
    return {
        "pid": proc.pid, "found": True, "name": proc.name or None,
        "findings": proc.findings,
        "correlator_verdicts": proc.verdicts,
        "max_finding_severity": proc.finding_severity,
        "correlator_severity": proc.verdict_severity,
    }


def lookup_attack_technique(cap: Capture, finding_type: str = "",
                            technique_id: str = "") -> dict[str, Any]:
    """Map a finding type (or a technique id) to MITRE ATT&CK."""
    if technique_id:
        return mitre.get_technique(technique_id)
    if finding_type:
        return mitre.lookup_by_finding(finding_type)
    return {"matched": False, "error": "Provide finding_type or technique_id."}


def score_injection_model(cap: Capture, pid: int) -> dict[str, Any]:
    """Run the learned GRU detector (argus-ml) on one process — a second opinion."""
    from . import ml_bridge
    proc = cap.get(int(pid))
    if proc is None:
        return _not_found(cap, pid)
    result = ml_bridge.score_trace(proc)
    result["pid"] = proc.pid
    return result


# ── tool specs shown to the model ────────────────────────────────────────────

_PID_SCHEMA = {
    "type": "object",
    "properties": {"pid": {"type": "integer", "description": "Process id."}},
    "required": ["pid"],
}

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "get_process_timeline",
        "description": (
            "Return the ordered Win32 API hook events (VirtualAlloc[Ex], "
            "WriteProcessMemory, VirtualProtect, CreateThread, "
            "CreateRemoteThread) observed for a process, with a summary of "
            "which steps of the allocate → write → make-executable → thread "
            "chain are present and whether any step crossed process "
            "boundaries. Call this first for any process you investigate."
        ),
        "input_schema": _PID_SCHEMA,
    },
    {
        "name": "get_findings",
        "description": (
            "Return memory-scanner (PE-Sieve) and YARA findings for a process, "
            "plus the rule-based correlator's (Diamond FSM) severity verdicts. "
            "An empty list means the scanners found nothing, not that the "
            "process is proven clean."
        ),
        "input_schema": _PID_SCHEMA,
    },
    {
        "name": "lookup_attack_technique",
        "description": (
            "Map an EDR finding type (e.g. FINDING_CODE_CAVE) or a technique id "
            "(e.g. T1055.012) to its MITRE ATT&CK technique. The result says "
            "whether the mapping is exact or approximate — report that honestly."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_type": {"type": "string",
                                 "description": "Finding type from get_findings."},
                "technique_id": {"type": "string",
                                 "description": "ATT&CK id such as T1055.001."},
            },
        },
    },
]

# Offered only when the learned detector can actually run (see ml_bridge.status()).
ML_TOOL_SPEC: dict[str, Any] = {
    "name": "score_injection_model",
    "description": (
        "Run the learned GRU injection detector (argus-ml) on a process's event "
        "sequence and return P(injection) with a label. Use it as a second "
        "opinion next to the rule-based findings. If it reports it is "
        "unavailable or has nothing to score, treat that as 'no ML signal', "
        "not as 'benign'. If it disagrees with the findings, report both."
    ),
    "input_schema": _PID_SCHEMA,
}

_DISPATCH = {
    "get_process_timeline": get_process_timeline,
    "get_findings": get_findings,
    "lookup_attack_technique": lookup_attack_technique,
    "score_injection_model": score_injection_model,
}


def tool_specs(include_ml: bool = False) -> list[dict[str, Any]]:
    return TOOL_SPECS + ([ML_TOOL_SPEC] if include_ml else [])


def run_tool(name: str, tool_input: dict[str, Any], cap: Capture) -> dict[str, Any]:
    """Execute one tool call from the model. Errors come back as data, so the
    model can recover instead of the loop crashing."""
    fn = _DISPATCH.get(name)
    if fn is None:
        return {"error": f"Unknown tool {name!r}.", "available": sorted(_DISPATCH)}
    try:
        return fn(cap, **(tool_input or {}))
    except TypeError as e:
        return {"error": f"Bad arguments for {name}: {e}"}
    except (ValueError, KeyError) as e:
        return {"error": f"{name} failed: {e}"}
