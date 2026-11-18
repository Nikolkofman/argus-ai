"""
Unit tests — offline, no API key.

    python -m unittest discover -s tests -v

The Claude backend is tested against a local fake of the Messages API, so the
real SDK's request/response wiring (tool_use → tool_result round trips) is
exercised without a key or network.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from argus_copilot import analyze_process, ask, make_backend, parse_file, parse_text  # noqa: E402
from argus_copilot import ml_bridge, tools  # noqa: E402

DATA = ROOT / "data"

try:
    import fastapi  # noqa: F401
    from fastapi.testclient import TestClient
    HAVE_FASTAPI = True
except ImportError:  # pragma: no cover
    HAVE_FASTAPI = False

try:
    import anthropic  # noqa: F401
    HAVE_ANTHROPIC = True
except ImportError:  # pragma: no cover
    HAVE_ANTHROPIC = False


class ParserTests(unittest.TestCase):
    def test_agent_log_groups_by_target_and_reads_findings(self):
        cap = parse_file(DATA / "remote_thread.ndjson")
        self.assertEqual(cap.pids(), [2264, 4120])
        self.assertEqual(cap.flagged_pids(), [4120])
        p = cap.get(4120)
        self.assertEqual(len(p.events), 4)
        self.assertEqual(p.findings[0]["type"], "FINDING_CODE_CAVE")
        self.assertEqual(p.severity, "HIGH")
        self.assertEqual(p.name, "test_target.exe")

    def test_argus_ml_trace_format_hides_ground_truth(self):
        cap = parse_file(DATA / "sample_traces.ndjson")
        p = cap.get(6100)
        self.assertEqual(p.meta["label"], "injection")
        out = tools.get_process_timeline(cap, 6100)
        self.assertNotIn("injection", json.dumps(out))  # label never reaches the agent

    def test_garbage_lines_are_ignored(self):
        cap = parse_text("hello\n{not json\n[IPC] event: {broken\n\n")
        self.assertEqual(len(cap), 0)


class RealAgentLogTests(unittest.TestCase):
    """Slices of real ArgusEDR agent logs (evals/cases/real_*.ndjson)."""
    CASES = ROOT / "evals" / "cases"

    def test_verdicts_and_findings_in_real_format(self):
        cap = parse_file(self.CASES / "real_shellcode.ndjson")
        p = cap.get(25320)
        self.assertEqual(p.name, "shellcode_runner.exe")
        self.assertEqual(p.verdict_severity, "CRITICAL")
        rules = sorted(f.get("yara_rule") for f in p.findings if f.get("yara_rule"))
        self.assertEqual(len(rules), 2)
        self.assertTrue(all(f["region"]["base_address"].startswith("0x") for f in p.findings))
        # the scanner re-reports regions on every scan; they are deduplicated with a count
        self.assertTrue(any(f.get("count", 1) > 1 for f in p.findings))

    def test_finding_context_separates_noise_from_injection(self):
        cap = parse_file(self.CASES / "real_benign_jit.ndjson")
        fs = tools.get_findings(cap, 6264)["findings"]
        shared = [f for f in fs if f["seen_in_other_pids"] > 0]
        own = [f for f in fs if f["allocated_via_hooked_call"]]
        self.assertEqual(len(shared), 1)
        self.assertEqual(len(own), 1)
        self.assertFalse(any(f["rwx"] for f in fs))

    def test_real_cases_classified(self):
        b = make_backend(use_mock=True)
        expect = {("real_benign_jit", 6264): "benign", ("real_shellcode", 25320): "malicious",
                  ("real_hollowing", 4048): "malicious"}
        for (case, pid), cls in expect.items():
            res = analyze_process(b, parse_file(self.CASES / f"{case}.ndjson"), pid)
            self.assertEqual(res.classification["classification"], cls, case)


class ToolTests(unittest.TestCase):
    def test_chain_summary(self):
        cap = parse_file(DATA / "remote_thread.ndjson")
        tl = tools.get_process_timeline(cap, 4120)
        self.assertTrue(all(tl["chain"][k] for k in ("alloc", "write", "exec_protect", "thread")))
        self.assertFalse(tl["chain"]["cross_process"])

    def test_unknown_pid_and_bad_tool_return_errors_as_data(self):
        cap = parse_file(DATA / "remote_thread.ndjson")
        self.assertFalse(tools.run_tool("get_findings", {"pid": 1}, cap)["found"])
        self.assertIn("error", tools.run_tool("nope", {}, cap))
        self.assertIn("error", tools.run_tool("get_findings", {"bogus": 1}, cap))

    def test_mitre_mapping_reports_confidence(self):
        cap = parse_file(DATA / "remote_thread.ndjson")
        r = tools.lookup_attack_technique(cap, finding_type="FINDING_HOLLOWED")
        self.assertEqual((r["id"], r["confidence"]), ("T1055.012", "exact"))
        r = tools.lookup_attack_technique(cap, finding_type="FINDING_CODE_CAVE")
        self.assertEqual(r["confidence"], "approximate")


class MockAgentTests(unittest.TestCase):
    def setUp(self):
        self.backend = make_backend(use_mock=True)

    def test_flagged_process(self):
        res = analyze_process(self.backend, parse_file(DATA / "remote_thread.ndjson"), 4120)
        self.assertEqual(res.classification["classification"], "malicious")
        self.assertEqual([t.name for t in res.tool_trace][:2],
                         ["get_process_timeline", "get_findings"])

    def test_benign_jit(self):
        res = analyze_process(self.backend, parse_file(DATA / "benign_jit.ndjson"), 8080)
        self.assertEqual(res.classification["classification"], "benign")

    def test_ask(self):
        res = ask(self.backend, parse_file(DATA / "remote_thread.ndjson"), "why was 4120 flagged?")
        self.assertIn("**Answer.**", res.report)

    def test_ml_tool_hidden_when_unavailable(self):
        with mock.patch.dict(os.environ, {"ARGUS_ML_DIR": "/nonexistent"}):
            self.assertFalse(ml_bridge.status()["available"])
            res = analyze_process(self.backend, parse_file(DATA / "remote_thread.ndjson"), 4120)
        self.assertNotIn("score_injection_model", [t.name for t in res.tool_trace])


@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed")
class ApiTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {
            "ARGUS_CAPTURE": str(DATA / "remote_thread.ndjson"),
            "ARGUS_CAPTURE_ROOT": str(ROOT), "ARGUS_USE_MOCK": "1"})
        self.env.start()
        from argus_copilot.api import app
        self.client = TestClient(app)

    def tearDown(self):
        self.env.stop()

    def test_endpoints(self):
        self.assertEqual(self.client.get("/health").json()["backend"], "mock")
        self.assertEqual([r["pid"] for r in self.client.get("/processes").json()], [4120])
        r = self.client.post("/explain/4120").json()
        self.assertEqual(r["classification"]["classification"], "malicious")
        r = self.client.post("/ask", json={"question": "why was 4120 flagged?"}).json()
        self.assertIn("Answer", r["report"])
        inline = (DATA / "benign_jit.ndjson").read_text()
        r = self.client.post("/explain/8080", json={"capture_text": inline}).json()
        self.assertEqual(r["classification"]["classification"], "benign")
        self.assertEqual(self.client.post("/explain/1").status_code, 404)

    def test_capture_path_is_confined_to_root(self):
        r = self.client.post("/explain/4120", json={"capture_path": "/etc/passwd"})
        self.assertEqual(r.status_code, 403)

    def test_dashboard_route(self):
        sys.path.insert(0, str(ROOT / "dashboard_integration"))
        from fastapi import FastAPI
        import explain_route
        explain_route.configure(lambda: DATA / "remote_thread.ndjson")
        app = FastAPI()
        app.include_router(explain_route.router)
        client = TestClient(app)
        self.assertTrue(client.get("/api/explain/status").json()["log_exists"])
        r = client.post("/api/explain/4120").json()
        self.assertEqual(r["classification"]["severity"], "HIGH")
        self.assertEqual(client.post("/api/explain/1").status_code, 404)

    @unittest.skipUnless((ROOT.parent / "edr" / "dashboard" / "server.py").is_file(),
                         "edr/ dashboard not present next to argus-copilot/")
    def test_edr_dashboard_has_explain(self):
        """The real dashboard in this repo serves the EXPLAIN route."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "edr_dashboard_server", ROOT.parent / "edr" / "dashboard" / "server.py")
        server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server)
        with mock.patch.dict(os.environ, {"ARGUS_AGENT_LOG": str(DATA / "remote_thread.ndjson")}):
            r = TestClient(server.app).post("/api/explain/4120")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["classification"]["classification"], "malicious")
        html = (ROOT.parent / "edr" / "dashboard" / "index.html").read_text(encoding="utf-8")
        self.assertIn("explain-btn", html)


class _FakeMessagesAPI(BaseHTTPRequestHandler):
    """Minimal stand-in for POST /v1/messages: two tool calls, then a report."""
    requests: list = []

    def log_message(self, *a):  # silence
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).requests.append(body)
        n = len(type(self).requests)
        if n == 1:
            content = [{"type": "tool_use", "id": "toolu_1",
                        "name": "get_process_timeline", "input": {"pid": 4120}}]
            stop = "tool_use"
        elif n == 2:
            content = [{"type": "text", "text": "Checking findings."},
                       {"type": "tool_use", "id": "toolu_2",
                        "name": "get_findings", "input": {"pid": 4120}}]
            stop = "tool_use"
        else:
            content = [{"type": "text", "text": "Report.\n```json\n"
                        '{"classification": "malicious", "severity": "HIGH", '
                        '"technique_id": "T1055", "ml_probability": null}\n```'}]
            stop = "end_turn"
        payload = json.dumps({
            "id": f"msg_{n}", "type": "message", "role": "assistant",
            "model": body["model"], "content": content, "stop_reason": stop,
            "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@unittest.skipUnless(HAVE_ANTHROPIC, "anthropic SDK not installed")
class ClaudeWireTests(unittest.TestCase):
    def test_tool_use_round_trip_through_real_sdk(self):
        _FakeMessagesAPI.requests = []
        server = HTTPServer(("127.0.0.1", 0), _FakeMessagesAPI)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        env = {"ANTHROPIC_API_KEY": "test-key",
               "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{server.server_port}",
               "ARGUS_ML_DIR": "/nonexistent"}
        try:
            with mock.patch.dict(os.environ, env):
                backend = make_backend(use_mock=False, model="test-model")
                res = analyze_process(backend, parse_file(DATA / "remote_thread.ndjson"), 4120)
        finally:
            server.shutdown()
            server.server_close()

        reqs = _FakeMessagesAPI.requests
        self.assertEqual(len(reqs), 3)
        self.assertIn("Argus Copilot", reqs[0]["system"])
        self.assertEqual({t["name"] for t in reqs[0]["tools"]},
                         {"get_process_timeline", "get_findings", "lookup_attack_technique"})
        tool_result = reqs[1]["messages"][-1]["content"][0]
        self.assertEqual(tool_result["tool_use_id"], "toolu_1")
        self.assertIn("api_sequence", tool_result["content"])
        self.assertEqual(res.classification["classification"], "malicious")
        self.assertEqual([t.name for t in res.tool_trace], ["get_process_timeline", "get_findings"])
        self.assertTrue(res.backend.startswith("claude:"))


if __name__ == "__main__":
    unittest.main()
