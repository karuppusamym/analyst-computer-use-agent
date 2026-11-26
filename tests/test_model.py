"""Model client: SSE parsing, the stdlib HTTP backend against a local stub, request building."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from analyst_agent.config import load_settings
from analyst_agent.gateway_check import run_gateway_check
from analyst_agent.model import HttpBackend, MockBackend, ModelClient, ModelError, RefusalError, mock_text
from analyst_agent.model.sse import MessageAccumulator, iter_sse


def sse(events: list[dict]) -> bytes:
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


STREAM = [
    {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5", "content": [], "stop_reason": None, "usage": {"input_tokens": 12, "output_tokens": 1}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "Plan: "}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "click."}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "sig123"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "Clicking"}},
    {"type": "content_block_stop", "index": 1},
    {"type": "content_block_start", "index": 2, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "left_click", "toolset_name": "computer", "input": {}}},
    {"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": '{"coordinate": [10'}},
    {"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": ", 20]}"}},
    {"type": "content_block_stop", "index": 2},
    {"type": "ping"},
    {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 40, "cache_read_input_tokens": 5}},
    {"type": "message_stop"},
]


class SseTests(unittest.TestCase):
    def test_accumulates_thinking_text_and_toolset_call(self):
        acc = MessageAccumulator()
        for ev, data in iter_sse(sse(STREAM).splitlines(keepends=True)):
            acc.feed(ev, data)
        msg = acc.result()
        self.assertEqual(msg["stop_reason"], "tool_use")
        self.assertEqual(msg["content"][0], {"type": "thinking", "thinking": "Plan: click.", "signature": "sig123"})
        self.assertEqual(msg["content"][1]["text"], "Clicking")
        tool = msg["content"][2]
        self.assertEqual(tool["input"], {"coordinate": [10, 20]})
        self.assertEqual(tool["toolset_name"], "computer")
        self.assertEqual(msg["usage"]["output_tokens"], 40)
        self.assertEqual(msg["usage"]["cache_read_input_tokens"], 5)

    def test_truncated_tool_json_is_flagged_not_crashed(self):
        acc = MessageAccumulator()
        acc.feed("", json.dumps(STREAM[0]))
        acc.feed("", json.dumps({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "t", "name": "run_python", "input": {}}}))
        acc.feed("", json.dumps({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": '{"code": "pri'}}))
        acc.feed("", json.dumps({"type": "content_block_stop", "index": 0}))
        self.assertIn("INVALID_JSON", acc.result()["content"][0]["input"])


class _Stub(BaseHTTPRequestHandler):
    calls: list = []
    fail_first: int = 0

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        _Stub.calls.append({"headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        if _Stub.fail_first > 0:
            _Stub.fail_first -= 1
            self.send_response(529)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"type":"error","error":{"type":"overloaded_error","message":"busy"}}')
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        self.wfile.write(sse(STREAM))

    def log_message(self, *a):
        pass


class HttpBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Stub)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        _Stub.calls.clear()
        import os

        os.environ["TEST_GATEWAY_TOKEN"] = "tok-123"
        self.settings = load_settings(overrides={"gateway": {"base_url": f"http://127.0.0.1:{self.server.server_port}", "token_env": "TEST_GATEWAY_TOKEN", "backend": "http", "max_retries": 2}})

    def test_native_request_shape_and_headers(self):
        client = ModelClient(self.settings, backend=HttpBackend(self.settings))
        history = [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_0", "name": "screenshot", "toolset_name": "computer", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_0", "toolset_name": "computer", "content": "OK"}]},
        ]
        reply = client.create("executor", history, tools=[{"type": "computer_toolset_20260801"}])
        self.assertEqual(reply.tool_uses()[0]["input"], {"coordinate": [10, 20]})
        call = _Stub.calls[0]
        h, b = call["headers"], call["body"]
        self.assertEqual(h["x-api-key"], "tok-123")
        self.assertEqual(h["anthropic-version"], "2026-10-21")
        self.assertIn("server-side-fallback-2026-07-01", h["anthropic-beta"])
        self.assertTrue(b["stream"])
        self.assertEqual(b["model"], "claude-opus-5-5")
        self.assertEqual(b["output_config"], {"effort": "medium"})
        self.assertEqual(b["fallbacks"], "default")
        self.assertEqual(b["cache_control"], {"type": "ephemeral"})
        self.assertNotIn("thinking", b)
        self.assertEqual(b["messages"][2]["content"][0]["toolset_name"], "computer")
        self.assertEqual(client.usage.calls, 1)
        self.assertEqual(client.backend.last_stream["text_events"], 1)
        self.assertIsNotNone(client.backend.last_stream["seconds_to_first_text"])

    def test_retries_overloaded_then_succeeds(self):
        _Stub.fail_first = 1
        self.settings.data["gateway"]["max_retries"] = 2
        backend = HttpBackend(self.settings)
        import analyst_agent.model.client as mc

        orig = mc.time.sleep
        mc.time.sleep = lambda s: None
        try:
            msg = backend.send({"model": "m", "max_tokens": 5, "messages": []}, [])
        finally:
            mc.time.sleep = orig
        self.assertEqual(msg["stop_reason"], "tool_use")
        self.assertEqual(len(_Stub.calls), 2)

    def test_bearer_auth_style(self):
        self.settings.data["gateway"]["auth_style"] = "bearer"
        HttpBackend(self.settings).send({"model": "m", "max_tokens": 5, "messages": []}, [])
        self.assertEqual(_Stub.calls[0]["headers"]["authorization"], "Bearer tok-123")
        self.assertNotIn("x-api-key", _Stub.calls[0]["headers"])

    def test_unreachable_gateway_raises_model_error(self):
        self.settings.data["gateway"]["base_url"] = "http://127.0.0.1:1"
        self.settings.data["gateway"]["max_retries"] = 0
        with self.assertRaises(ModelError):
            HttpBackend(self.settings).send({"model": "m", "max_tokens": 5, "messages": []}, [])


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.settings = load_settings(overrides={"gateway": {"backend": "mock"}})

    def test_structured_output_and_roles(self):
        backend = MockBackend([mock_text('{"a": 1}')])
        client = ModelClient(self.settings, backend=backend)
        reply = client.create("planner", [{"role": "user", "content": "x"}], output_schema={"type": "object"})
        self.assertEqual(reply.json(), {"a": 1})
        body = backend.requests[0]["body"]
        self.assertEqual(body["model"], "claude-fable-5-2")
        self.assertEqual(body["output_config"]["format"]["type"], "json_schema")
        self.assertEqual(body["output_config"]["effort"], "high")

    def test_refusal_raises(self):
        client = ModelClient(self.settings, backend=MockBackend([{"content": [], "stop_reason": "refusal", "stop_details": {"category": "cyber", "explanation": "no"}}]))
        with self.assertRaises(RefusalError) as cm:
            client.create("executor", [{"role": "user", "content": "x"}])
        self.assertEqual(cm.exception.category, "cyber")


class GatewayCheckTests(unittest.TestCase):
    def setUp(self):
        import analyst_agent.gateway_check as gc

        self.gc = gc
        self._sleep = gc.time.sleep
        gc.time.sleep = lambda s: None
        self.settings = load_settings(overrides={"gateway": {"backend": "mock"}})

    def tearDown(self):
        self.gc.time.sleep = self._sleep

    THINK = {"type": "thinking", "thinking": "", "signature": "s"}
    LIVE = {"text_events": 400, "seconds_to_first_text": 1.2, "seconds_total": 60.0}

    def script(self, **over):
        """A gateway that passes everything; `over` replaces single replies by step name."""
        tool_call = {"content": [self.THINK, {"type": "tool_use", "id": "toolu_9", "name": "get_region_total", "input": {"region": "North"}}], "stop_reason": "tool_use"}
        steps = {
            "tool_exec": mock_text("OK"),
            "tool_plan": mock_text("OK"),
            "cache1": {**mock_text("OK"), "id": "msg_a", "diagnostics": {}},
            "cache2": {**mock_text("OK"), "diagnostics": {"cache": "hit"}, "usage": {"input_tokens": 10, "output_tokens": 1, "cache_read_input_tokens": 5000}},
            "think1": tool_call,
            "think2": mock_text("Yes, above 1 million."),
            "stream": {**mock_text("# Guide ..."), "usage": {"input_tokens": 10, "output_tokens": 3300}, "_stream": self.LIVE},
        }
        steps.update(over)
        return MockBackend(list(steps.values()))

    def run_check(self, backend):
        return {r.name[:2]: r for r in run_gateway_check(self.settings, ModelClient(self.settings, backend=backend))}

    def test_all_five_checks_with_scripted_gateway(self):
        backend = self.script()
        results = self.run_check(backend)
        self.assertTrue(all(r.status == "PASS" for r in results.values()), [(r.name, r.status, r.detail) for r in results.values()])
        reqs = backend.requests
        self.assertEqual(reqs[0]["body"]["tools"], [{"type": "computer_toolset_20260801"}])
        self.assertEqual(reqs[1]["body"]["model"], "claude-fable-5-2")
        # cache-diagnosis beta and its body field, chained to the first call's id
        self.assertIn("cache-diagnosis-2026-04-07", reqs[2]["betas"])
        self.assertEqual(reqs[3]["body"]["diagnostics"], {"previous_message_id": "msg_a"})
        # assistant turn sent back unchanged, followed by the tool_result
        replay = reqs[5]["body"]["messages"]
        self.assertEqual(replay[1]["content"], self.script().script[4]["content"])
        self.assertEqual(replay[2]["content"][0]["tool_use_id"], "toolu_9")
        self.assertIn("GATEWAY OK", self.gc.format_results(list(results.values())))

    def test_missing_diagnostics_fails_check_2(self):
        results = self.run_check(self.script(cache2={**mock_text("OK"), "usage": {"cache_read_input_tokens": 5000}}))
        self.assertEqual(results["2."].status, "FAIL")
        self.assertEqual(results["3."].status, "PASS")

    def test_missing_cache_read_fails_check_3(self):
        results = self.run_check(self.script(cache2={**mock_text("OK"), "diagnostics": {}}))
        self.assertEqual(results["3."].status, "FAIL")

    def test_unsigned_thinking_fails_check_4(self):
        unsigned = {"content": [{"type": "thinking", "thinking": "x"}, {"type": "tool_use", "id": "t", "name": "get_region_total", "input": {}}], "stop_reason": "tool_use"}
        results = self.run_check(self.script(think1=unsigned, think2=mock_text("x"), stream=mock_text("x")))
        self.assertEqual(results["4."].status, "FAIL")

    def test_no_thinking_block_warns(self):
        bare = {"content": [{"type": "tool_use", "id": "t", "name": "get_region_total", "input": {}}], "stop_reason": "tool_use"}
        results = self.run_check(self.script(think1=bare))
        self.assertEqual(results["4."].status, "WARN")
        self.assertTrue(results["4."].passed)

    def test_buffered_stream_warns_and_cut_off_stream_fails(self):
        buffered = {**mock_text("x"), "usage": {"output_tokens": 3300}, "_stream": {"text_events": 3, "seconds_to_first_text": 55.0, "seconds_total": 56.0}}
        results = self.run_check(self.script(stream=buffered))
        self.assertEqual(results["5."].status, "WARN")
        self.assertIn("WITH WARNINGS", self.gc.verdict(list(results.values())))
        cut = {**mock_text("x"), "stop_reason": "max_tokens", "usage": {"output_tokens": 16000}, "_stream": self.LIVE}
        self.assertEqual(self.run_check(self.script(stream=cut))["5."].status, "FAIL")

    def test_failing_gateway_and_report(self):
        backend = MockBackend([mock_text("OK")] * 4 + [{"content": [{"type": "text", "text": "x"}]}, {**mock_text("x"), "usage": {"output_tokens": 10}}])
        results = list(self.run_check(backend).values())
        by = {r.name[:2]: r for r in results}
        self.assertEqual(by["2."].status, "FAIL")
        self.assertEqual(by["3."].status, "FAIL")
        self.assertEqual(by["4."].status, "WARN")  # no tool call
        self.assertEqual(by["5."].status, "WARN")  # too short
        out = self.gc.format_results(results)
        self.assertIn("GATEWAY NOT READY", out)
        self.assertIn("Likely fixes:", out)
        import tempfile
        from pathlib import Path

        self.settings.data["gateway"]["extra_headers"] = {"x-team": "fin"}
        with tempfile.TemporaryDirectory() as d:
            path = self.gc.write_report(results, self.settings, Path(d) / "r.json")
            report = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(report["verdict"].startswith("GATEWAY NOT READY"))
        self.assertEqual(report["extra_header_names"], ["x-team"])
        self.assertIn("2. beta headers pass through", report["fixes"])
        self.assertEqual({c["status"] for c in report["checks"]}, {"PASS", "WARN", "FAIL"})

    def test_config_error(self):
        self.assertIn("mock", self.gc.config_error(self.settings))
        s = load_settings(overrides={"gateway": {"backend": "http", "token_env": "SURELY_UNSET_GATEWAY_TOKEN"}})
        self.assertIn("SURELY_UNSET_GATEWAY_TOKEN", self.gc.config_error(s))


class StreamStatsTests(unittest.TestCase):
    def test_message_delta_keeps_extra_top_level_fields(self):
        acc = MessageAccumulator()
        acc.feed("message_start", json.dumps({"type": "message_start", "message": {"id": "m", "content": [], "usage": {}}}))
        acc.feed("message_delta", json.dumps({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 1}, "diagnostics": {"cache": "miss"}}))
        msg = acc.result()
        self.assertEqual(msg["diagnostics"], {"cache": "miss"})
        self.assertEqual(msg["stop_reason"], "end_turn")


if __name__ == "__main__":
    unittest.main()
