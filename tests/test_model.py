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
    def test_all_five_checks_with_scripted_gateway(self):
        settings = load_settings(overrides={"gateway": {"backend": "mock"}})
        thinking = {"content": [{"type": "thinking", "thinking": "", "signature": "s"}, {"type": "text", "text": "3h25m"}]}
        backend = MockBackend([
            mock_text("OK"), mock_text("OK"),  # toolset on executor + planner
            mock_text("OK"),  # betas
            mock_text("OK"), {**mock_text("OK"), "usage": {"input_tokens": 10, "output_tokens": 1, "cache_read_input_tokens": 5000}},  # caching
            thinking, mock_text("205"),  # thinking round-trip
            {**mock_text("1. ..."), "usage": {"input_tokens": 10, "output_tokens": 5000}},  # long stream
        ])
        import analyst_agent.gateway_check as gc

        orig = gc.time.sleep
        gc.time.sleep = lambda s: None
        try:
            results = run_gateway_check(settings, ModelClient(settings, backend=backend))
        finally:
            gc.time.sleep = orig
        self.assertTrue(all(r.passed for r in results), [(r.name, r.detail) for r in results])
        reqs = backend.requests
        self.assertEqual(reqs[0]["body"]["tools"], [{"type": "computer_toolset_20260801"}])
        self.assertEqual(reqs[1]["body"]["model"], "claude-fable-5-2")
        self.assertIn("server-side-fallback-2026-07-01", reqs[2]["betas"])
        # thinking blocks sent back unchanged
        self.assertEqual(reqs[6]["body"]["messages"][1]["content"], thinking["content"])

    def test_missing_cache_read_fails_check(self):
        settings = load_settings(overrides={"gateway": {"backend": "mock"}})
        backend = MockBackend([mock_text("OK")] * 5 + [{"content": [{"type": "text", "text": "x"}]}, mock_text("x"), {**mock_text("x"), "usage": {"output_tokens": 10}}])
        import analyst_agent.gateway_check as gc

        orig = gc.time.sleep
        gc.time.sleep = lambda s: None
        try:
            results = {r.name[:2]: r for r in run_gateway_check(settings, ModelClient(settings, backend=backend))}
        finally:
            gc.time.sleep = orig
        self.assertFalse(results["3."].passed)
        self.assertFalse(results["4."].passed)
        self.assertFalse(results["5."].passed)


if __name__ == "__main__":
    unittest.main()
