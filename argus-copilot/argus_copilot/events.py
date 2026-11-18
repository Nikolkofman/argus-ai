"""
Telemetry parsing for Argus Copilot.

Turns whatever the ArgusEDR pipeline produced into one in-memory `Capture`:
a map of pid -> ProcessTrace (hook events + findings + verdicts).

Accepted inputs, mixed freely in one file, one record per line:

1. Raw agent-log lines, where the agent wraps hook events as
       [IPC] event: {"api": "VirtualAllocEx", "pid": 3312, "target_pid": 4120, ...}
2. Bare NDJSON hook events:      {"api": ..., "pid": ..., "target_pid": ..., ...}
3. Findings (PE-Sieve / YARA / memory scanner):
       {"type": "finding", "pid": 4120, "finding": "FINDING_CODE_CAVE",
        "severity": "HIGH", "source": "pe-sieve", "detail": "..."}
4. Correlator (Diamond FSM) verdicts:
       {"type": "verdict", "pid": 4120, "severity": "HIGH",
        "rules": ["ALLOC", "WRITE", "PROTECT"]}
5. argus-ml trace lines (collect.py output):
       {"label": "injection", "technique": "...", "pid": 4812, "events": [...]}

Events are grouped by the process they act ON (`target_pid`, falling back to
`pid`), the same convention argus-ml's collect.py uses.

Ground truth from argus-ml traces (`label`, `technique`) is kept in
`ProcessTrace.meta` and is never exposed to the agent's tools — otherwise the
evaluation would be measuring a lookup, not an analysis.

If your agent prints findings/verdicts with different key names, adapt
`_as_finding` / `_as_verdict` below; nothing else depends on the raw shape.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Union

SEVERITY_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

_IPC_EVENT_RE = re.compile(r"\[IPC\] event: (\{.+\})")


def severity_rank(sev: Optional[str]) -> int:
    return _SEV_RANK.get(str(sev or "NONE").upper(), 0)


def max_severity(*sevs: Optional[str]) -> str:
    best = "NONE"
    for s in sevs:
        if severity_rank(s) > severity_rank(best):
            best = str(s).upper()
    return best


@dataclass
class ProcessTrace:
    pid: int
    name: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    verdicts: list[dict[str, Any]] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)  # ground truth; hidden from tools

    @property
    def verdict_severity(self) -> str:
        return max_severity(*(v.get("severity") for v in self.verdicts))

    @property
    def finding_severity(self) -> str:
        return max_severity(*(f.get("severity") for f in self.findings))

    @property
    def severity(self) -> str:
        return max_severity(self.verdict_severity, self.finding_severity)

    @property
    def flagged(self) -> bool:
        return bool(self.findings) or severity_rank(self.verdict_severity) >= _SEV_RANK["MEDIUM"]


class Capture:
    """All telemetry from one capture, indexed by pid."""

    def __init__(self) -> None:
        self.processes: dict[int, ProcessTrace] = {}

    def _proc(self, pid: int) -> ProcessTrace:
        if pid not in self.processes:
            self.processes[pid] = ProcessTrace(pid=pid)
        return self.processes[pid]

    def get(self, pid: int) -> Optional[ProcessTrace]:
        return self.processes.get(int(pid))

    def pids(self) -> list[int]:
        return sorted(self.processes)

    def flagged_pids(self) -> list[int]:
        """Flagged processes, worst severity first."""
        flagged = [p for p in self.processes.values() if p.flagged]
        flagged.sort(key=lambda p: (-severity_rank(p.severity), p.pid))
        return [p.pid for p in flagged]

    def summary(self, only_flagged: bool = True) -> list[dict[str, Any]]:
        pids = self.flagged_pids() if only_flagged else self.pids()
        out = []
        for pid in pids:
            p = self.processes[pid]
            out.append({"pid": pid, "name": p.name or None, "severity": p.severity,
                        "events": len(p.events), "findings": len(p.findings)})
        return out

    def __len__(self) -> int:
        return len(self.processes)


# ── normalisation of individual records ──────────────────────────────────────

def _int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _name_of(obj: dict[str, Any]) -> str:
    return str(obj.get("process_name") or obj.get("process") or obj.get("name")
               or obj.get("image") or "")


_SOURCE_BY_TYPE = {"FINDING_YARA_MATCH": "yara",
                   "FINDING_PRIVATE_EXECUTABLE": "memory-scanner"}


def parse_addr(v: Any) -> Optional[int]:
    """'0x1ee02e50000' / '000001EE02E50000' / 123 -> int (None if unparsable)."""
    if v is None or v == "":
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v), 16)
    except ValueError:
        return None


def _as_finding(obj: dict[str, Any]) -> Optional[dict[str, Any]]:
    ftype = obj.get("finding") or obj.get("finding_type")
    if not ftype and str(obj.get("type", "")).lower() == "finding":
        ftype = obj.get("rule") or obj.get("name") or "FINDING_UNKNOWN"
    if not ftype:
        return None
    ftype = str(ftype).upper()
    out: dict[str, Any] = {
        "type": ftype,
        "severity": str(obj.get("severity", "MEDIUM")).upper(),
        "source": obj.get("source") or _SOURCE_BY_TYPE.get(
            ftype, "pe-sieve" if "PE" in ftype else ""),
    }
    detail = obj.get("detail")
    if isinstance(detail, dict):            # real scanner output
        for k in ("reason", "yara_rule", "pe_anomaly"):
            if detail.get(k):
                out[k] = str(detail[k])
    elif detail:
        out["detail"] = str(detail)
    region = obj.get("region")
    if isinstance(region, dict):
        base = parse_addr(region.get("base_address"))
        out["region"] = {"base_address": hex(base) if base is not None else None,
                         "size": region.get("size"), "protect": region.get("protect")}
    return out


def _finding_key(f: dict[str, Any]) -> tuple:
    r = f.get("region") or {}
    return (f["type"], r.get("base_address"), f.get("yara_rule"), f.get("pe_anomaly"),
            f.get("detail"))


def _as_verdict(obj: dict[str, Any]) -> Optional[dict[str, Any]]:
    is_verdict = (str(obj.get("type", "")).lower() in ("verdict", "process_verdict")
                  or "verdict" in obj)
    if not is_verdict:
        return None
    sev = obj.get("severity") or obj.get("verdict") or obj.get("state") or "NONE"
    return {
        "severity": str(sev).upper(),
        "rules": list(obj.get("rules", [])),
        "reason": obj.get("reason", ""),
        "trigger": obj.get("trigger", ""),
    }


def _hook_event(obj: dict[str, Any]) -> dict[str, Any]:
    keep = ("api", "pid", "target_pid", "address", "start_address", "size", "protect", "t_ms")
    return {k: obj[k] for k in keep if k in obj}


def ingest_obj(cap: Capture, obj: Any) -> None:
    """Add one parsed JSON record to the capture (unknown shapes are ignored)."""
    if not isinstance(obj, dict):
        return

    # argus-ml trace line: a whole process at once
    if isinstance(obj.get("events"), list):
        pid = _int(obj.get("pid"))
        if pid is None:
            return
        proc = cap._proc(pid)
        proc.name = proc.name or _name_of(obj)
        for ev in obj["events"]:
            if isinstance(ev, dict) and "api" in ev:
                proc.events.append(_hook_event(ev))
        for k in ("label", "technique"):
            if k in obj:
                proc.meta[k] = obj[k]
        return

    # single hook event — grouped by the process acted on
    if "api" in obj:
        pid = _int(obj.get("target_pid", obj.get("pid")))
        if pid is None:
            return
        proc = cap._proc(pid)
        proc.events.append(_hook_event(obj))
        return

    pid = _int(obj.get("pid", obj.get("target_pid")))
    if pid is None:
        return

    finding = _as_finding(obj)
    if finding is not None:
        proc = cap._proc(pid)
        proc.name = proc.name or _name_of(obj)
        key = _finding_key(finding)
        for existing in proc.findings:
            if _finding_key(existing) == key:
                existing["count"] = existing.get("count", 1) + 1
                break
        else:
            proc.findings.append(finding)
        return

    verdict = _as_verdict(obj)
    if verdict is not None:
        proc = cap._proc(pid)
        proc.name = proc.name or _name_of(obj)
        proc.verdicts.append(verdict)


def _iter_json_from_line(line: str) -> Iterator[Any]:
    line = line.strip()
    if not line:
        return
    m = _IPC_EVENT_RE.search(line)
    if m:
        try:
            yield json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
        return
    if line.startswith("{"):
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            pass


def parse_lines(lines: Iterable[str]) -> Capture:
    cap = Capture()
    for line in lines:
        for obj in _iter_json_from_line(line):
            ingest_obj(cap, obj)
    return cap


def parse_text(text: str) -> Capture:
    return parse_lines(text.splitlines())


def parse_file(path: Union[str, Path]) -> Capture:
    """Parse an agent .log, an .ndjson capture, or an argus-ml trace file."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_text(text)
