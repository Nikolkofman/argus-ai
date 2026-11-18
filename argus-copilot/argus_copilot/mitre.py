"""
MITRE ATT&CK knowledge base for Argus Copilot.

A small, curated map from the EDR's own finding types to ATT&CK techniques
under T1055 (Process Injection). This is what the `lookup_attack_technique`
tool reads.

Honesty note: ATT&CK has no dedicated entry for every detector concept (a
"code cave" or "module stomping" finding is evidence, not a technique). Where a
mapping is approximate, `confidence` says so instead of overclaiming.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    url: str
    summary: str


TECHNIQUES: dict[str, Technique] = {t.id: t for t in [
    Technique("T1055", "Process Injection",
              "https://attack.mitre.org/techniques/T1055/",
              "Executing code in the address space of another live process to "
              "evade defenses and possibly elevate privileges."),
    Technique("T1055.001", "Process Injection: Dynamic-link Library Injection",
              "https://attack.mitre.org/techniques/T1055/001/",
              "Getting a DLL's code to run inside another live process."),
    Technique("T1055.002", "Process Injection: Portable Executable Injection",
              "https://attack.mitre.org/techniques/T1055/002/",
              "A full PE image placed into another process's memory and run "
              "from there, with no backing file on disk."),
    Technique("T1055.003", "Process Injection: Thread Execution Hijacking",
              "https://attack.mitre.org/techniques/T1055/003/",
              "Redirecting an existing thread of a live process to run "
              "foreign code."),
    Technique("T1055.004", "Process Injection: Asynchronous Procedure Call",
              "https://attack.mitre.org/techniques/T1055/004/",
              "Running foreign code in a process via its APC queue."),
    Technique("T1055.012", "Process Injection: Process Hollowing",
              "https://attack.mitre.org/techniques/T1055/012/",
              "A legitimate process's image is replaced in memory so it runs "
              "foreign code under a trusted name."),
]}

# finding type -> (technique id, confidence, note)
FINDING_MAP: dict[str, tuple[str, str, str]] = {
    "FINDING_CODE_CAVE": (
        "T1055", "approximate",
        "Executable code in a region with no backing module is evidence of "
        "injection in general; it does not identify the sub-technique."),
    "FINDING_UNBACKED_EXEC": (
        "T1055", "approximate",
        "Executable private memory with no file behind it — generic "
        "injection evidence."),
    "FINDING_SHELLCODE": (
        "T1055", "approximate",
        "Shellcode-like content in memory — generic injection evidence."),
    "FINDING_YARA_MATCH": (
        "T1055", "approximate",
        "A signature matched in process memory; the exact technique depends "
        "on the rule that fired."),
    "FINDING_REMOTE_THREAD": (
        "T1055", "approximate",
        "A thread started in another process; common to several injection "
        "sub-techniques."),
    "FINDING_HOLLOWED": (
        "T1055.012", "exact",
        "The main image in memory no longer matches the file on disk."),
    "FINDING_PROCESS_HOLLOWING": (
        "T1055.012", "exact",
        "The main image in memory no longer matches the file on disk."),
    "FINDING_IMPLANTED_PE": (
        "T1055.002", "exact",
        "A PE image is present in memory with no corresponding module on disk."),
    "FINDING_MODULE_STOMPING": (
        "T1055.001", "approximate",
        "A loaded DLL's code was overwritten in memory. ATT&CK has no "
        "dedicated sub-technique; it is usually filed under DLL injection."),
    "FINDING_PATCHED_MODULE": (
        "T1055.001", "approximate",
        "A loaded module's code differs from its file on disk."),
    "FINDING_THREAD_HIJACK": (
        "T1055.003", "exact",
        "An existing thread's context was redirected."),
    "FINDING_APC_QUEUE": (
        "T1055.004", "exact",
        "Foreign code was queued to a thread's APC queue."),
}


def get_technique(technique_id: str) -> dict[str, Any]:
    t = TECHNIQUES.get(str(technique_id).upper())
    if t is None:
        return {"matched": False, "error": f"Unknown technique id {technique_id!r}.",
                "known_ids": sorted(TECHNIQUES)}
    return {"matched": True, "confidence": "exact", **asdict(t)}


def lookup_by_finding(finding_type: str) -> dict[str, Any]:
    key = str(finding_type).upper()
    entry = FINDING_MAP.get(key)
    if entry is None:
        return {"matched": False, "finding_type": key,
                "error": "No ATT&CK mapping for this finding type.",
                "known_findings": sorted(FINDING_MAP)}
    tid, confidence, note = entry
    return {"matched": True, "finding_type": key, "confidence": confidence,
            "note": note, **asdict(TECHNIQUES[tid])}
