"""Tests for the desktop-pixels tier (computer_toolset_20260801).

Pure tests always run. The screenshot test runs on Windows (read-only).
The live input test moves the real mouse and types into the Legacy Ledger
test app only; it runs when RUN_DESKTOP_TESTS=1.
"""

from __future__ import annotations

import csv
import json
import math
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib
from pathlib import Path

from analyst_agent.audit import AuditLog
from analyst_agent.config import load_settings
from analyst_agent.policy import PolicyEngine, ScriptedApprover
from analyst_agent.tools import screen_win as sw
from analyst_agent.tools.base import ToolContext
from analyst_agent.tools.computer import MAX_TOKENS_IMG, ComputerTier, fits, scale_factor, to_screen

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "test_targets" / "legacy_app.py"
WIN = sys.platform == "win32"
LIVE = WIN and os.environ.get("RUN_DESKTOP_TESTS") == "1"


def make_ctx(tmp: Path, titles: list[str], apps: list[str] | None = None, dry_run: bool = False):
    settings = load_settings(
        overrides={
            "workspace": {"root": str(tmp / "ws"), "input_dirs": [str(tmp / "in")], "output_dir": str(tmp / "ws" / "out")},
            "policy": {"allowed_apps": apps or []},
            "tiers": {"desktop_pixels": {"enabled": True, "dry_run": dry_run, "allowed_window_titles": titles}},
            "audit": {"dir": str(tmp / "audit")},
        }
    )
    tier = ComputerTier(settings)
    ctx = ToolContext(settings=settings, policy=PolicyEngine(settings), audit=AuditLog(tmp / "audit"), approver=ScriptedApprover([]), step_id="t", workdir=tmp / "ws")
    return tier, ctx


def call(tier, ctx, name, **inp):
    return tier.execute({"type": "tool_use", "id": "toolu_x", "name": name, "toolset_name": "computer", "input": inp}, ctx)


class PureTests(unittest.TestCase):
    def test_scale_1080p_is_one(self):
        self.assertEqual(scale_factor(1920, 1080), 1.0)

    def test_scale_4k_fits_limits(self):
        s = scale_factor(3840, 2160)
        self.assertLess(s, 1.0)
        w, h = round(3840 * s), round(2160 * s)
        self.assertTrue(fits(w, h, 2576))
        self.assertLessEqual(math.ceil(w / 28) * math.ceil(h / 28), MAX_TOKENS_IMG)
        self.assertGreater(w, 2000)  # not over-shrunk

    def test_unscale_and_clamp(self):
        self.assertEqual(to_screen([100, 50], 0.5, (3840, 2160)), (200, 100))
        self.assertEqual(to_screen([99999, -5], 0.5, (3840, 2160)), (3839, 0))

    def test_png_encoder(self):
        rgb = bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255])  # 2x2
        png = sw.encode_png(rgb, 2, 2)
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        length, tag = struct.unpack(">I4s", png[8:16])
        self.assertEqual((length, tag), (13, b"IHDR"))
        w, h, depth, color = struct.unpack(">IIBB", png[16:26])
        self.assertEqual((w, h, depth, color), (2, 2, 8, 2))
        idat_len = struct.unpack(">I", png[33:37])[0]
        raw = zlib.decompress(png[41 : 41 + idat_len])
        self.assertEqual(raw, b"\x00" + rgb[:6] + b"\x00" + rgb[6:])

    def test_bgra_to_rgb(self):
        self.assertEqual(bytes(sw.bgra_to_rgb(bytes([1, 2, 3, 255]))), bytes([3, 2, 1]))

    def test_key_parsing(self):
        self.assertEqual(sw.parse_combo("ctrl+shift+s"), [0x11, 0x10, ord("S")])
        self.assertEqual(sw.parse_combo("Return"), [0x0D])
        self.assertEqual(sw.parse_combo("a"), [ord("A")])
        self.assertEqual(sw.parse_combo("Page_Down"), [0x22])
        with self.assertRaises(ValueError):
            sw.parse_combo("notakey")

    def test_api_tool_shape(self):
        with tempfile.TemporaryDirectory() as d:
            tier, _ = make_ctx(Path(d), [])
            self.assertEqual(tier.api_tools(), [{"type": "computer_toolset_20260801"}])
            self.assertTrue(tier.handles({"name": "left_click", "toolset_name": "computer"}))
            self.assertFalse(tier.handles({"name": "run_python"}))

    def test_disabled_tier_unavailable(self):
        settings = load_settings()
        ok, reason = ComputerTier(settings).available()
        self.assertFalse(ok)
        self.assertIn("disabled", reason)


@unittest.skipUnless(WIN, "Windows only")
class ScreenshotTest(unittest.TestCase):
    def test_screenshot_png(self):
        with tempfile.TemporaryDirectory() as d:
            tier, ctx = make_ctx(Path(d), [])
            out = call(tier, ctx, "screenshot")
            self.assertFalse(out.is_error, out.text)
            png = out.images[0]
            self.assertTrue(png.startswith(b"\x89PNG"))
            w, h = struct.unpack(">II", png[16:24])
            self.assertTrue(fits(w, h, 2576), (w, h))
            self.assertGreater(w, 300)
            self.assertGreater(h, 200)

    def test_refused_when_not_allowlisted(self):
        with tempfile.TemporaryDirectory() as d:
            tier, ctx = make_ctx(Path(d), [], [])
            out = call(tier, ctx, "mouse_move", coordinate=[5, 5])
            self.assertTrue(out.is_error)
            self.assertIn("refused", out.text)
            kinds = [e["kind"] for e in ctx.audit.events()]
            self.assertIn("computer_action_refused", kinds)
            self.assertNotIn("computer_action", kinds)  # nothing was executed
            self.assertGreater(sw.cursor_pos()[0], 5)  # cursor not moved to (5, 5)


@unittest.skipUnless(LIVE, "set RUN_DESKTOP_TESTS=1 to drive the real mouse and keyboard")
class LiveLegacyAppTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.out = self.tmp / "ledger.csv"
        self.coords = self.tmp / "coords.json"
        self.proc = subprocess.Popen([sys.executable, str(APP), "--out", str(self.out), "--coords", str(self.coords)])
        deadline = time.time() + 15
        while time.time() < deadline and not self.coords.exists():
            time.sleep(0.2)
        self.assertTrue(self.coords.exists(), "test app did not start")
        time.sleep(0.3)
        self.rects = json.loads(self.coords.read_text())
        hwnd = sw.find_window("Legacy Ledger - TEST")
        self.assertTrue(hwnd, "window not found")
        sw.bring_to_front(hwnd)

    def tearDown(self):
        self.proc.kill()
        self.proc.wait(5)

    def center(self, name, s):
        r = self.rects[name]
        return [round((r["x"] + r["w"] / 2) * s), round((r["y"] + r["h"] / 2) * s)]

    def test_fill_form_through_toolset(self):
        tier, ctx = make_ctx(self.tmp, ["Legacy Ledger - TEST"])
        _, s = tier.geometry()
        steps = [
            ("left_click", {"coordinate": self.center("account", s)}),
            ("type", {"text": "4000-SALES"}),
            ("left_click", {"coordinate": self.center("amount", s)}),
            ("type", {"text": "1250.50"}),
            ("left_click", {"coordinate": self.center("memo", s)}),
            ("type", {"text": "Week 47 accrual"}),
            ("left_click", {"coordinate": self.center("save_entry", s)}),
        ]
        for name, inp in steps:
            out = call(tier, ctx, name, **inp)
            self.assertFalse(out.is_error, f"{name}: {out.text}")
        time.sleep(0.5)
        with open(self.out, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(rows, [{"account": "4000-SALES", "amount": "1250.50", "memo": "Week 47 accrual"}])
        shot = call(tier, ctx, "screenshot")
        self.assertFalse(shot.is_error)

    def test_dry_run_sends_nothing(self):
        tier, ctx = make_ctx(self.tmp, ["Legacy Ledger - TEST"], dry_run=True)
        _, s = tier.geometry()
        out = call(tier, ctx, "left_click", coordinate=self.center("save_entry", s))
        self.assertIn("dry run", out.text)
        time.sleep(0.3)
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
