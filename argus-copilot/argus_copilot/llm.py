"""
LLM backends for Argus Copilot.

Both backends implement the same one-method interface:

    respond(system, messages, tools) -> LLMResponse(text, tool_calls, stop_reason)

`messages` use the Anthropic Messages API shape (user / assistant turns with
text, tool_use and tool_result blocks), so the agent loop is identical whether
the "brain" is Claude or the offline mock.

* ClaudeBackend — the real model, via the `anthropic` SDK. Needs ANTHROPIC_API_KEY.
* MockBackend   — a deterministic stand-in that walks the same tool loop
                  (timeline → findings → [GRU] → ATT&CK) and fills a report
                  template. Runs offline, costs nothing, and is the baseline the
                  evals and CI use.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from .events import severity_rank

DEFAULT_CLAUDE_MODEL = "claude-sonnet-5-5"


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"


class LLMBackend(Protocol):
    name: str

    def respond(self, system: str, messages: list[dict[str, Any]],
                tools: list[dict[str, Any]]) -> LLMResponse: ...


# ── real model ───────────────────────────────────────────────────────────────

class ClaudeBackend:
    def __init__(self, model: Optional[str] = None, max_tokens: int = 2048,
                 api_key: Optional[str] = None) -> None:
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("The Claude backend needs the SDK: pip install anthropic") from e
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set (or use the mock backend).")
        self.client = anthropic.Anthropic(api_key=key)
        self.model = model or os.environ.get("ARGUS_CLAUDE_MODEL", DEFAULT_CLAUDE_MODEL)
        self.max_tokens = max_tokens
        self.name = f"claude:{self.model}"

    def respond(self, system: str, messages: list[dict[str, Any]],
                tools: list[dict[str, Any]]) -> LLMResponse:
        resp = self.client.messages.create(
            model=self.model, max_tokens=self.max_tokens,
            system=system, tools=tools, messages=messages,
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input))
                 for b in resp.content if b.type == "tool_use"]
        return LLMResponse(text=text, tool_calls=calls, stop_reason=resp.stop_reason)


# ── offline mock ─────────────────────────────────────────────────────────────

def _history(messages: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map tool name -> {"input", "output"} for every tool already run."""
    calls: dict[str, dict[str, Any]] = {}
    by_id: dict[str, str] = {}
    for m in messages:
        content = m.get("content")
        if not isinstance(content, list):
            continue
        for b in content:
            if b.get("type") == "tool_use":
                by_id[b["id"]] = b["name"]
                calls[b["name"]] = {"input": b["input"], "output": None}
            elif b.get("type") == "tool_result":
                name = by_id.get(b["tool_use_id"])
                if name:
                    try:
                        calls[name]["output"] = json.loads(b["content"])
                    except (TypeError, json.JSONDecodeError):
                        calls[name]["output"] = {"raw": b["content"]}
    return calls


class MockBackend:
    """Deterministic stand-in for the model. Same interface, fixed policy."""

    name = "mock"

    def __init__(self) -> None:
        self._n = 0

    def _call(self, name: str, **inp: Any) -> LLMResponse:
        self._n += 1
        return LLMResponse(text="", tool_calls=[ToolCall(f"mock_{self._n}", name, inp)],
                           stop_reason="tool_use")

    def respond(self, system: str, messages: list[dict[str, Any]],
                tools: list[dict[str, Any]]) -> LLMResponse:
        first = messages[0]["content"]
        prompt = first if isinstance(first, str) else ""
        m = re.search(r"PID=(\d+)", prompt)
        pid = int(m.group(1)) if m else 0
        offered = {t["name"] for t in tools}
        done = _history(messages)

        if "get_process_timeline" not in done:
            return self._call("get_process_timeline", pid=pid)
        timeline = done["get_process_timeline"]["output"] or {}
        if not timeline.get("found", False):
            return LLMResponse(text=_not_found_report(pid, timeline))
        if "get_findings" not in done:
            return self._call("get_findings", pid=pid)
        if "score_injection_model" in offered and "score_injection_model" not in done:
            return self._call("score_injection_model", pid=pid)

        if "lookup_attack_technique" not in done:
            a = _assess(timeline, done["get_findings"]["output"] or {})
            if a["cls"] != "benign":
                return self._call("lookup_attack_technique", **_technique_query(a))

        return LLMResponse(text=_compose_report(pid, done, question=_question(prompt)))


# ── the mock's analysis policy ───────────────────────────────────────────────

WEAK_FINDINGS = {"FINDING_PRIVATE_EXECUTABLE"}


def _question(prompt: str) -> Optional[str]:
    m = re.search(r"Question about the current EDR capture \(focus PID=\d+\): (.+)", prompt)
    return m.group(1).strip() if m else None


def _full_chain(chain: dict[str, Any]) -> bool:
    return all(chain.get(k) for k in ("alloc", "write", "exec_protect", "thread"))


def _suspicious_behaviour(chain: dict[str, Any]) -> bool:
    """Behaviour worth flagging even with no scanner finding."""
    return _full_chain(chain) or bool(chain.get("cross_process_write"))


def _sev_max(*sevs: Optional[str]) -> str:
    return max([s or "NONE" for s in sevs] or ["NONE"], key=severity_rank)


def _assess(tl: dict[str, Any], fd: dict[str, Any]) -> dict[str, Any]:
    """Weigh the evidence the way an analyst would.

    Strong: YARA / PE-Sieve style findings, or a correlator verdict >= HIGH.
    Weak:   FINDING_PRIVATE_EXECUTABLE — explained away when the region is
            flagged in other processes too (shared memory) or is the process's
            own RX allocation in a JIT-like pattern (allocate → make executable,
            in-process, no write, no thread, no RWX).
    """
    chain = tl.get("chain", {})
    findings = fd.get("findings", [])
    corr = fd.get("correlator_severity", "NONE")
    jit_like = (chain.get("alloc") and chain.get("exec_protect") and not chain.get("write")
                and not chain.get("thread") and not chain.get("cross_process")
                and not chain.get("rwx_alloc"))

    strong = [f for f in findings if f["type"] not in WEAK_FINDINGS
              and severity_rank(f.get("severity")) >= severity_rank("HIGH")]
    weak = [f for f in findings if f["type"] in WEAK_FINDINGS]
    shared = [f for f in weak if f.get("seen_in_other_pids", 0) > 0]
    own_jit = [f for f in weak if f not in shared and jit_like
               and f.get("allocated_via_hooked_call") and not f.get("rwx")]
    unexplained = [f for f in weak if f not in shared and f not in own_jit]
    other = [f for f in findings if f not in strong and f not in weak]  # low-sev non-weak

    if strong or severity_rank(corr) >= severity_rank("HIGH"):
        cls, sev = "malicious", _sev_max(corr, *(f.get("severity") for f in strong))
    elif unexplained or other:
        cls = "suspicious"
        sev = "MEDIUM" if (not jit_like or any(f.get("rwx") for f in unexplained)) else "LOW"
    elif severity_rank(corr) >= severity_rank("MEDIUM") and not jit_like:
        cls, sev = "suspicious", "MEDIUM"
    elif _suspicious_behaviour(chain):
        cls, sev = "suspicious", ("MEDIUM" if chain.get("cross_process") else "LOW")
    else:
        cls, sev = "benign", "NONE"
    return {"cls": cls, "sev": sev, "jit_like": bool(jit_like), "corr": corr,
            "strong": strong, "shared": shared, "own_jit": own_jit,
            "unexplained": unexplained, "chain": chain}


def _technique_query(a: dict[str, Any]) -> dict[str, str]:
    if a["strong"]:
        top = max(a["strong"], key=lambda f: severity_rank(f.get("severity")))
        anomaly = str(top.get("pe_anomaly", "")).lower()
        if "replac" in anomaly or "hollow" in anomaly:
            return {"technique_id": "T1055.012"}
        if "implant" in anomaly:
            return {"technique_id": "T1055.002"}
        return {"finding_type": top["type"]}
    if a["chain"].get("cross_process"):
        return {"technique_id": "T1055"}
    if a["unexplained"]:
        return {"finding_type": a["unexplained"][0]["type"]}
    return {"technique_id": "T1055"}


def _not_found_report(pid: int, timeline: dict[str, Any]) -> str:
    known = ", ".join(str(p) for p in timeline.get("known_pids", [])) or "none"
    cls = {"classification": "unknown", "severity": "NONE", "technique_id": None,
           "confidence": "mock-deterministic"}
    return (f"No telemetry was recorded for PID {pid} in this capture "
            f"(known PIDs: {known}). Nothing to analyze.\n\n"
            f"```json\n{json.dumps(cls)}\n```")


def _finding_line(f: dict[str, Any]) -> str:
    bits = [f"{f['type']} ({f.get('severity')}"
            + (f" via {f['source']}" if f.get("source") else "") + ")"]
    for k in ("yara_rule", "pe_anomaly", "detail", "reason"):
        if f.get(k):
            bits.append(f"{k.replace('_', ' ')}: {f[k]}")
            break
    r = f.get("region") or {}
    if r.get("base_address"):
        prot = r.get("protect")
        bits.append(f"region {r['base_address']} ({r.get('size')} B, protect "
                    f"{hex(prot) if isinstance(prot, int) else prot})")
    tags = []
    if f.get("rwx"):
        tags.append("RWX")
    if f.get("allocated_via_hooked_call"):
        tags.append(f"allocated via hooked call by pid {f.get('allocated_by_pid')}")
    if f.get("seen_in_other_pids"):
        tags.append(f"also flagged in {f['seen_in_other_pids']} other process(es)")
    if f.get("count", 1) > 1:
        tags.append(f"reported {f['count']}×")
    return "- Finding: " + " — ".join(bits) + (f" [{'; '.join(tags)}]" if tags else "")


def _compose_report(pid: int, done: dict[str, dict[str, Any]],
                    question: Optional[str]) -> str:
    tl = done["get_process_timeline"]["output"] or {}
    fd = done["get_findings"]["output"] or {}
    ml = (done.get("score_injection_model") or {}).get("output") or {}
    tech = (done.get("lookup_attack_technique") or {}).get("output") or {}
    a = _assess(tl, fd)
    cls, sev, chain = a["cls"], a["sev"], a["chain"]
    findings = fd.get("findings", [])
    verdicts = fd.get("correlator_verdicts", [])

    name = tl.get("name") or fd.get("name") or "unknown image"
    yn = lambda b: "yes" if b else "no"  # noqa: E731
    lines = [f"## Incident report — PID {pid} ({name})", ""]
    if question:
        verdict = "was flagged" if cls != "benign" else "was not flagged as malicious"
        lines += [f"**Question.** {question}",
                  f"**Answer.** PID {pid} {verdict}; the evidence is below.", ""]

    if cls == "malicious" and a["strong"]:
        what = (f"The memory scanners confirmed injected code ({len(a['strong'])} strong "
                f"finding(s)), and the correlator reached {a['corr']}.")
    elif cls == "malicious":
        what = (f"The rule-based correlator escalated to {a['corr']} on the API sequence"
                + (" across process boundaries" if chain.get("cross_process") else "")
                + "; the scanner findings are consistent with it.")
    elif cls == "suspicious" and a["unexplained"]:
        what = ("Executable memory was flagged that the process's own allocation pattern "
                "does not explain; not conclusive on its own.")
    elif cls == "suspicious":
        what = ("The API-level behaviour matches the injection pattern"
                + (" across process boundaries" if chain.get("cross_process") else "")
                + ", but no memory-scanner finding confirms it. Suspicious, not proven.")
    elif findings or severity_rank(a["corr"]) >= severity_rank("MEDIUM"):
        what = (f"The EDR raised {len(findings)} private-executable finding(s) and a "
                f"{a['corr']} verdict, but the pattern is a JIT-style in-process "
                "allocate → make-executable"
                + (f"; {len(a['shared'])} flagged region(s) also appear in other processes "
                   "(shared memory, not injection into this one)" if a["shared"] else "")
                + ". Likely a false positive.")
    elif chain.get("exec_protect"):
        what = ("In-process allocate → make-executable with no cross-process write and no "
                "scanner finding — the normal pattern of a JIT engine (.NET, V8, Java).")
    else:
        what = ("No executable-memory or cross-process activity and no scanner findings; "
                "nothing indicates injection.")

    lines += [f"**What happened.** {what}", "", "**Evidence.**",
              f"- Hook timeline: {tl.get('api_sequence') or '(no events)'} "
              f"({tl.get('n_events', 0)} events; cross-process: {yn(chain.get('cross_process'))}; "
              f"RWX allocation: {yn(chain.get('rwx_alloc'))})"]
    lines += [_finding_line(f) for f in findings] or \
             ["- Findings: none from the memory scanner / YARA / PE-Sieve"]
    trail = " → ".join(f"{v.get('severity')}" + (f" ({v['trigger']})" if v.get("trigger") else "")
                       for v in verdicts)
    lines.append(f"- Correlator (Diamond FSM): {trail or a['corr']}")

    ml_p = None
    if ml.get("scored"):
        ml_p = ml["probability"]
        lines.append(f"- Learned model (GRU): P(injection)={ml_p} → {ml['label']} "
                     f"(second opinion over {ml['n_events']} events)")
        if (ml["label"] == "injection") != (cls != "benign"):
            lines.append("  - The learned model disagrees with the rule-based evidence. "
                         "The rule-based evidence drives the classification; the "
                         "disagreement is worth a manual look.")
    elif ml:
        lines.append(f"- Learned model (GRU): no signal ({ml.get('reason', 'unavailable')})")

    lines.append("")
    tid = tech.get("id") if (tech.get("matched") and cls != "benign") else None
    if tid:
        note = f" — {tech['note']}" if tech.get("note") else ""
        lines.append(f"**Technique.** {tid} {tech['name']} "
                     f"({tech.get('confidence', 'exact')} mapping){note}")
    else:
        lines.append("**Technique.** none identified")
    lines.append(f"**Severity.** {sev}")

    actors = sorted({e.get("actor_pid") for e in tl.get("events", [])
                     if e.get("cross_process") and e.get("actor_pid") is not None})
    if cls == "malicious":
        action = ("Isolate the host; capture a full memory image of the process before "
                  "terminating it; ")
        action += (f"investigate the source process(es) {', '.join(map(str, actors))}; "
                   if actors else "")
        action += "hunt for the same finding on other endpoints."
    elif cls == "suspicious":
        action = ("Keep the process under watch and take a memory dump; check whether it "
                  "is a known JIT host (.NET, V8, Java) before escalating.")
    elif findings:
        action = ("No incident. Consider tuning: regions flagged in every process and "
                  "JIT-style own allocations are recurring false positives.")
    else:
        action = "No action needed."
    lines += [f"**Recommended action.** {action}", "",
              "_Generated by the mock backend (deterministic policy, not model reasoning)._",
              "", "```json",
              json.dumps({"classification": cls, "severity": sev, "technique_id": tid,
                          "ml_probability": ml_p, "confidence": "mock-deterministic"}),
              "```"]
    return "\n".join(lines)


# ── factory ──────────────────────────────────────────────────────────────────

def _truthy(v: Optional[str]) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "on"}


def make_backend(use_mock: Optional[bool] = None, model: Optional[str] = None) -> LLMBackend:
    """use_mock=True → mock; False → Claude (error without a key);
    None → Claude if ANTHROPIC_API_KEY is set and ARGUS_USE_MOCK is not, else mock."""
    if use_mock is None:
        use_mock = _truthy(os.environ.get("ARGUS_USE_MOCK")) or not os.environ.get("ANTHROPIC_API_KEY")
    return MockBackend() if use_mock else ClaudeBackend(model=model)
