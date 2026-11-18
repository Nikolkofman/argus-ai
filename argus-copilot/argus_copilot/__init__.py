"""
Argus Copilot — an LLM incident analyst for the ArgusEDR endpoint detection system.

    from argus_copilot import parse_file, make_backend, analyze_process, ask

    cap = parse_file("data/remote_thread.ndjson")
    result = analyze_process(make_backend(use_mock=True), cap, pid=4120)
    print(result.report)
"""

from .agent import CopilotResult, analyze_process, ask
from .events import Capture, parse_file, parse_lines, parse_text
from .llm import ClaudeBackend, MockBackend, make_backend

__version__ = "0.1.0"

__all__ = [
    "Capture", "parse_file", "parse_text", "parse_lines",
    "make_backend", "MockBackend", "ClaudeBackend",
    "analyze_process", "ask", "CopilotResult",
]
