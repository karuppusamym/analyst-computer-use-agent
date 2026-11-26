"""Phase 0, week-1 gateway test (design doc, Risk 1).

Sends a few small calls through the internal gateway, using the same client
the agent uses. Checks:
  1. computer_toolset_20260801 is accepted by the executor and planner models
     (if not, 1c tries the custom computer tool as a fallback)
  2. beta headers reach the provider: the cache-diagnosis beta's `diagnostics`
     field must come back in the response
  3. prompt caching works (second identical call reads from cache)
  4. thinking blocks come back signed and are accepted when the assistant turn
     is sent back unchanged together with a tool_result
  5. a long response streams live to end_turn without a time-out

Each check is PASS, WARN (worked, but something looked off) or FAIL. A JSON
report for the gateway team is written next to the console output. It never
contains the token.

Costs a few cents of tokens. Run: python -m analyst_agent gateway-check
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings
from .model import ModelClient, ModelError

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
CACHE_DIAGNOSIS_BETA = "cache-diagnosis-2026-04-07"
MIN_STREAM_EVENTS = 20

# Likely cause and fix per check, for the console and the report.
FIXES = {
    "1": "Gateway translates to an OpenAI-style API or filters tool types: add a native pass-through route for /v1/messages. "
    "On Amazon Bedrock the models take computer_20251124 instead; test that.",
    "2": "Gateway drops anthropic-beta headers or unknown body fields: forward all anthropic-* headers and the body unchanged.",
    "3": "cache_control stripped, system prompt altered, or calls spread across backends/keys: pass the body unchanged and "
    "keep one upstream key per team so the cache is shared.",
    "4": "Gateway rewrites, trims or re-serialises history or thinking blocks: never modify messages; pass content blocks through byte for byte.",
    "5": "Gateway buffers streams or has a short request time-out: pass server-sent events through live and allow requests of 10+ minutes.",
}


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """WARN counts as passed: the call worked."""
        return self.status != FAIL


def _status(ok: bool | str) -> str:
    if isinstance(ok, str):
        return ok
    return PASS if ok else FAIL


def _try(name: str, fn) -> CheckResult:
    try:
        out = fn()
    except ModelError as e:
        return CheckResult(name, FAIL, str(e)[:400])
    status, detail, *rest = out
    return CheckResult(name, _status(status), detail, rest[0] if rest else {})


def _stream_stats(client: ModelClient) -> dict:
    return dict(getattr(client.backend, "last_stream", None) or {})


def run_gateway_check(settings: Settings, client: ModelClient | None = None, long_tokens: int = 4000) -> list[CheckResult]:
    client = client or ModelClient(settings)
    results: list[CheckResult] = []
    hi = [{"role": "user", "content": "Reply with the single word OK. Do not use any tool."}]

    # ------------------------------------------------------------ 1. toolset
    def toolset(role: str):
        def run():
            r = client.create(role, hi, tools=[{"type": "computer_toolset_20260801"}])
            return True, f"{client.role(role)['model']} accepted the toolset (stop_reason={r.stop_reason})"

        return run

    results.append(_try("1a. computer toolset on executor", toolset("executor")))
    results.append(_try("1b. computer toolset on planner", toolset("planner")))
    if not (results[0].passed and results[1].passed):

        def custom():
            from .tools.computer import custom_tool_definition

            msgs = [{"role": "user", "content": "Call the computer tool once with action screenshot."}]
            r = client.create("executor", msgs, tools=[custom_tool_definition(1280, 800)])
            calls = [b for b in r.tool_uses() if b.get("name") == "computer"]
            ok = bool(calls) and calls[0].get("input", {}).get("action") == "screenshot"
            return ok, ('fallback works: set tiers.desktop_pixels.tool_mode = "custom"' if ok else f"model did not call the custom tool (stop_reason={r.stop_reason})")

        results.append(_try("1c. custom computer tool [informational]", custom))

    # ------------------------------------------------- 2 + 3. betas, caching
    # Two identical calls with the cache-diagnosis beta. The beta-only
    # `diagnostics` field coming back proves the header reached the provider
    # (a gateway can accept the request yet silently drop the header). The
    # second call must read the long system prompt from the cache.
    system = "You are a test assistant for a gateway check.\n" + ("Reference line for cache warm-up. " * 1200)
    try:
        first = client.create("executor", hi, system=system, extra_betas=[CACHE_DIAGNOSIS_BETA], diagnostics={"previous_message_id": None})
        time.sleep(1)
        second = client.create(
            "executor", hi, system=system, extra_betas=[CACHE_DIAGNOSIS_BETA], diagnostics={"previous_message_id": first.message.get("id")}
        )
    except ModelError as e:
        msg = str(e)[:400]
        results.append(CheckResult("2. beta headers pass through", FAIL, msg))
        results.append(CheckResult("3. prompt caching", FAIL, "not run: the request above failed. " + msg))
    else:
        diag = second.message.get("diagnostics")
        if diag is not None:
            results.append(CheckResult("2. beta headers pass through", PASS, "the beta-only 'diagnostics' field came back", {"diagnostics": diag}))
        else:
            results.append(
                CheckResult(
                    "2. beta headers pass through",
                    FAIL,
                    "request accepted but no 'diagnostics' field came back: the gateway likely drops anthropic-beta headers or unknown body fields",
                )
            )
        read = second.usage.get("cache_read_input_tokens", 0) or 0
        usage = {"first_call": first.usage, "second_call": second.usage}
        results.append(CheckResult("3. prompt caching", _status(read > 0), f"cache_read_input_tokens on second call = {read}", usage))

    # --------------------------------------------------- 4. thinking + tools
    def thinking():
        tools = [
            {
                "name": "get_region_total",
                "description": "Returns the sales total in USD for one region for last week.",
                "input_schema": {
                    "type": "object",
                    "properties": {"region": {"type": "string", "description": "Region name, e.g. North"}},
                    "required": ["region"],
                    "additionalProperties": False,
                },
            }
        ]
        mode = {"type": "adaptive", "display": "summarized"}
        msgs = [{"role": "user", "content": "Use the tool to get last week's total for the North region, then tell me whether it is above 1 million USD."}]
        r = client.create("executor", msgs, tools=tools, thinking=mode)
        calls = r.tool_uses()
        if not calls:
            return WARN, f"model did not call the tool (stop_reason={r.stop_reason}); re-run the check"
        blocks = [b for b in r.content if b.get("type") in ("thinking", "redacted_thinking")]
        if blocks and not all(b.get("signature") or b.get("type") == "redacted_thinking" for b in blocks):
            return FAIL, "thinking blocks came back without a signature: the gateway is altering them"
        # Send the assistant turn back exactly as received, plus the tool result.
        replay = msgs + [
            {"role": "assistant", "content": r.content},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": calls[0]["id"], "content": "1,240,500"}]},
        ]
        try:
            r2 = client.create("executor", replay, tools=tools, thinking=mode)
        except ModelError as e:
            return FAIL, f"replaying the assistant turn unchanged was rejected: {str(e)[:300]} (the gateway may be rewriting history or thinking blocks)"
        if not blocks:
            return WARN, "replay accepted, but no thinking block came back on the first call: the gateway may strip thinking blocks"
        return PASS, f"{len(blocks)} signed thinking block(s) returned; replay with tool_result accepted (stop_reason={r2.stop_reason})"

    results.append(_try("4. thinking round-trip", thinking))

    # ----------------------------------------------------------- 5. stream
    def long_stream():
        start = time.monotonic()
        msgs = [
            {
                "role": "user",
                "content": "Write a detailed, roughly 2,500-word guide for new financial analysts on building a weekly sales report: "
                "data sources, reconciliation, pivot design, commentary, and review. Use headings.",
            }
        ]
        saved = client.role("executor")["max_tokens"]
        client.role("executor")["max_tokens"] = max(saved, long_tokens * 4)
        try:
            r = client.create("executor", msgs)
        except ModelError as e:
            return FAIL, f"{str(e)[:300]} (the gateway may buffer or time out streamed responses)", {"seconds": round(time.monotonic() - start, 1)}
        finally:
            client.role("executor")["max_tokens"] = saved
        stats = _stream_stats(client)
        out = r.usage.get("output_tokens", 0) or 0
        data = {"seconds_total": round(time.monotonic() - start, 1), "output_tokens": out, "stop_reason": r.stop_reason, **stats}
        if r.stop_reason != "end_turn":
            return FAIL, f"stream ended with stop_reason={r.stop_reason}, not end_turn", data
        events = stats.get("text_events")
        if events is not None and events < MIN_STREAM_EVENTS:
            return WARN, f"completed, but only {events} text events arrived: the gateway may buffer the stream instead of passing it through live", data
        if out < long_tokens // 2:
            return WARN, f"completed, but only {out} output tokens: too short to test a long stream", data
        ttft = stats.get("seconds_to_first_text")
        live = f", {events} text events, first text after {ttft}s" if events is not None else ""
        return PASS, f"{out} output tokens streamed in {data['seconds_total']:.0f}s{live}", data

    results.append(_try("5. long streamed response", long_stream))
    return results


def verdict(results: list[CheckResult]) -> str:
    core = [r for r in results if "[informational]" not in r.name]
    fallback_ok = any(r.passed for r in results if "[informational]" in r.name)
    warned = any(r.status == WARN for r in core)
    if all(r.passed for r in core):
        return "GATEWAY OK WITH WARNINGS - re-run once; if a warning repeats, raise it with the gateway team" if warned else "GATEWAY OK"
    if fallback_ok and all(r.passed or r.name.startswith("1") for r in core):
        return 'GATEWAY OK EXCEPT NATIVE COMPUTER USE - run the pixel tier with tool_mode "custom" and eval it'
    return "GATEWAY NOT READY - see design doc, Risk 1 fix order"


def format_results(results: list[CheckResult]) -> str:
    lines = [f"[{r.status}] {r.name}: {r.detail}" for r in results]
    fixes = sorted({r.name[0] for r in results if r.status == FAIL and "[informational]" not in r.name and r.name[0] in FIXES})
    if fixes:
        lines += ["", "Likely fixes:"] + [f"  {n}. {FIXES[n]}" for n in fixes]
    counts = {s: sum(r.status == s for r in results) for s in (PASS, WARN, FAIL)}
    lines += ["", f"{verdict(results)}  ({counts[PASS]} pass, {counts[WARN]} warn, {counts[FAIL]} fail)"]
    return "\n".join(lines)


def write_report(results: list[CheckResult], settings: Settings, path: Path) -> Path:
    """Write a JSON report to share with the gateway team. Never includes the token."""
    g = settings["gateway"]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gateway": {k: g.get(k) for k in ("base_url", "backend", "auth_style", "api_version", "fallbacks")},
        "extra_header_names": sorted((g.get("extra_headers") or {}).keys()),
        "models": {role: settings["models"][role]["model"] for role in ("executor", "planner")},
        "verdict": verdict(results),
        "checks": [asdict(r) for r in results],
        "fixes": {r.name: FIXES[r.name[0]] for r in results if r.status == FAIL and r.name[0] in FIXES and "[informational]" not in r.name},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


def config_error(settings: Settings) -> str | None:
    """A reason the check cannot run, or None."""
    g = settings["gateway"]
    if g["backend"] == "mock":
        return "gateway.backend is 'mock': point the config at a real gateway"
    if not g.get("base_url"):
        return "gateway.base_url is not set"
    if not settings.gateway_token() and not g.get("extra_headers"):
        return f"no gateway token: set {g.get('token_env')} (or gateway.extra_headers if the gateway authenticates another way)"
    return None
