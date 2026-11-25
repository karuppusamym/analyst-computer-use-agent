"""Phase 0, week-1 gateway test (design doc, Risk 1).

Sends a few small calls through the internal gateway. It passes only if all
five checks pass:
  1. computer_toolset_20260801 is accepted by the executor and planner models
  2. beta feature headers reach the provider unchanged
  3. prompt caching works (second identical call reads from cache)
  4. thinking blocks come back and are accepted when sent back unchanged
  5. a long response streams without a time-out

Costs a few cents of tokens. Run: python -m analyst_agent gateway-check
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .config import Settings
from .model import ModelClient, ModelError


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str


def _try(name: str, fn) -> CheckResult:
    try:
        ok, detail = fn()
        return CheckResult(name, ok, detail)
    except ModelError as e:
        return CheckResult(name, False, str(e)[:400])


def run_gateway_check(settings: Settings, client: ModelClient | None = None, long_tokens: int = 6000) -> list[CheckResult]:
    client = client or ModelClient(settings)
    results: list[CheckResult] = []
    hi = [{"role": "user", "content": "Reply with the single word OK. Do not use any tool."}]

    def toolset(role: str):
        def run():
            r = client.create(role, hi, tools=[{"type": "computer_toolset_20260801"}])
            return True, f"{client.role(role)['model']} accepted the toolset (stop_reason={r.stop_reason})"

        return run

    results.append(_try("1a. computer toolset on executor", toolset("executor")))
    results.append(_try("1b. computer toolset on planner", toolset("planner")))

    def betas():
        # The fallbacks field is only accepted with its beta header. A gateway
        # that strips or rewrites anthropic-beta makes this call a 400.
        saved = settings["gateway"].get("fallbacks")
        settings["gateway"]["fallbacks"] = "default"
        try:
            client.create("executor", hi)
        finally:
            settings["gateway"]["fallbacks"] = saved
        return True, "request with a beta-gated field was accepted"

    results.append(_try("2. beta headers pass through", betas))

    def caching():
        # Must exceed the model's minimum cacheable prefix (up to 4096 tokens).
        system = "You are a test assistant for a gateway check.\n" + ("Reference line for cache warm-up. " * 1200)
        client.create("executor", hi, system=system)
        time.sleep(1)
        r = client.create("executor", hi, system=system)
        read = r.usage.get("cache_read_input_tokens", 0) or 0
        return read > 0, f"cache_read_input_tokens on second call = {read}"

    results.append(_try("3. prompt caching", caching))

    def thinking():
        msgs = [{"role": "user", "content": "A train leaves at 09:40 and arrives at 13:05. How long is the trip? Think it through, then answer in one line."}]
        r = client.create("executor", msgs, thinking={"type": "adaptive", "display": "summarized"})
        blocks = [b for b in r.content if b.get("type") in ("thinking", "redacted_thinking")]
        if not blocks:
            return False, "no thinking block came back (gateway may drop them)"
        if not all(b.get("signature") or b.get("type") == "redacted_thinking" for b in blocks):
            return False, "thinking block lost its signature"
        follow = msgs + [{"role": "assistant", "content": r.content}, {"role": "user", "content": "And in minutes?"}]
        client.create("executor", follow, thinking={"type": "adaptive", "display": "summarized"})
        return True, f"{len(blocks)} thinking block(s) returned and accepted back unchanged"

    results.append(_try("4. thinking round-trip", thinking))

    def long_stream():
        start = time.time()
        msgs = [{"role": "user", "content": f"Write a numbered list of {long_tokens // 12} short, different facts about spreadsheets, one per line."}]
        saved = client.role("executor")["max_tokens"]
        client.role("executor")["max_tokens"] = long_tokens + 2000
        try:
            r = client.create("executor", msgs)
        finally:
            client.role("executor")["max_tokens"] = saved
        out = r.usage.get("output_tokens", 0)
        return out >= long_tokens // 2, f"{out} output tokens streamed in {time.time() - start:.0f}s (stop_reason={r.stop_reason})"

    results.append(_try("5. long streamed response", long_stream))
    return results


def format_results(results: list[CheckResult]) -> str:
    lines = [f"[{'PASS' if r.passed else 'FAIL'}] {r.name}: {r.detail}" for r in results]
    verdict = "GATEWAY OK" if all(r.passed for r in results) else "GATEWAY NOT READY - see design doc, Risk 1 fix order"
    return "\n".join(lines + ["", verdict])
