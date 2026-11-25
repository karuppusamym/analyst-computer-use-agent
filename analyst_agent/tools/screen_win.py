"""Windows screen capture and input with ctypes only (no packages).

Screenshots: GDI StretchBlt (scales in the GPU/driver, so no image library is
needed) -> 32bpp DIB -> RGB -> PNG via zlib.
Input: SendInput for mouse buttons, wheel and keyboard (unicode typing).

Imports cleanly on other platforms; every function then raises OSError.
"""

from __future__ import annotations

import ctypes
import os
import struct
import sys
import time
import zlib
from ctypes import wintypes

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
else:  # pragma: no cover - non-Windows
    user32 = gdi32 = kernel32 = None


def _need_windows() -> None:
    if not IS_WINDOWS:
        raise OSError("desktop control via screen_win is only available on Windows")


# --------------------------------------------------------------------------- PNG


def encode_png(rgb: bytes, width: int, height: int) -> bytes:
    """Encode tightly packed RGB bytes as a PNG (filter 0 on every row)."""
    stride = width * 3
    if len(rgb) != stride * height:
        raise ValueError("rgb buffer size does not match width*height*3")
    raw = b"".join(b"\x00" + rgb[y * stride : (y + 1) * stride] for y in range(height))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")


def bgra_to_rgb(bgra: bytes | bytearray) -> bytearray:
    n = len(bgra) // 4
    rgb = bytearray(n * 3)
    rgb[0::3] = bgra[2::4]
    rgb[1::3] = bgra[1::4]
    rgb[2::3] = bgra[0::4]
    return rgb


# --------------------------------------------------------------------------- DPI / screen

_dpi_set = False


def set_dpi_aware() -> None:
    global _dpi_set
    _need_windows()
    if _dpi_set:
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor aware
    except Exception:
        try:
            user32.SetProcessDPIAware()
        except Exception:
            pass
    _dpi_set = True


def screen_size() -> tuple[int, int]:
    _need_windows()
    set_dpi_aware()
    return user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)


# --------------------------------------------------------------------------- capture


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


if IS_WINDOWS:
    user32.GetDC.restype = wintypes.HDC
    user32.GetDC.argtypes = [wintypes.HWND]
    user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    gdi32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
    gdi32.SelectObject.restype = wintypes.HGDIOBJ
    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    gdi32.SetStretchBltMode.argtypes = [wintypes.HDC, ctypes.c_int]
    gdi32.SetBrushOrgEx.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    gdi32.StretchBlt.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.DWORD]
    gdi32.GetDIBits.argtypes = [wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT, ctypes.c_void_p, ctypes.POINTER(BITMAPINFO), wintypes.UINT]
    gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi32.DeleteDC.argtypes = [wintypes.HDC]

SRCCOPY = 0x00CC0020
CAPTUREBLT = 0x40000000
HALFTONE = 4


def capture(region: tuple[int, int, int, int] | None = None, out_size: tuple[int, int] | None = None) -> tuple[bytes, int, int]:
    """Capture (x0, y0, x1, y1) of the primary screen (default: whole screen),
    scaled to out_size (w, h). Returns (png_bytes, w, h)."""
    _need_windows()
    sw, sh = screen_size()
    x0, y0, x1, y1 = region or (0, 0, sw, sh)
    x0, y0 = max(0, int(x0)), max(0, int(y0))
    x1, y1 = min(sw, int(x1)), min(sh, int(y1))
    src_w, src_h = x1 - x0, y1 - y0
    if src_w <= 0 or src_h <= 0:
        raise ValueError(f"empty capture region {region}")
    dw, dh = out_size or (src_w, src_h)
    dw, dh = max(1, int(dw)), max(1, int(dh))

    hdc_screen = user32.GetDC(None)
    if not hdc_screen:
        raise OSError("GetDC failed (is the desktop locked?)")
    hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
    hbmp = gdi32.CreateCompatibleBitmap(hdc_screen, dw, dh)
    old = gdi32.SelectObject(hdc_mem, hbmp)
    try:
        gdi32.SetStretchBltMode(hdc_mem, HALFTONE)
        gdi32.SetBrushOrgEx(hdc_mem, 0, 0, None)
        if not gdi32.StretchBlt(hdc_mem, 0, 0, dw, dh, hdc_screen, x0, y0, src_w, src_h, SRCCOPY | CAPTUREBLT):
            raise OSError(f"StretchBlt failed: {ctypes.get_last_error()}")
        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = dw
        bmi.bmiHeader.biHeight = -dh  # top-down
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = 0  # BI_RGB
        buf = ctypes.create_string_buffer(dw * dh * 4)
        # GetDIBits needs the bitmap not selected into a DC.
        gdi32.SelectObject(hdc_mem, old)
        old = None
        lines = gdi32.GetDIBits(hdc_mem, hbmp, 0, dh, buf, ctypes.byref(bmi), 0)
        if lines != dh:
            raise OSError(f"GetDIBits returned {lines} of {dh} lines")
    finally:
        if old:
            gdi32.SelectObject(hdc_mem, old)
        gdi32.DeleteObject(hbmp)
        gdi32.DeleteDC(hdc_mem)
        user32.ReleaseDC(None, hdc_screen)
    return encode_png(bytes(bgra_to_rgb(buf.raw)), dw, dh), dw, dh


# --------------------------------------------------------------------------- input structs

ULONG_PTR = ctypes.c_size_t


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]


INPUT_MOUSE, INPUT_KEYBOARD = 0, 1
MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP = 0x0002, 0x0004
MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP = 0x0008, 0x0010
MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP = 0x0020, 0x0040
MOUSEEVENTF_WHEEL, MOUSEEVENTF_HWHEEL = 0x0800, 0x01000
KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE = 0x0001, 0x0002, 0x0004

if IS_WINDOWS:
    user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
    user32.SendInput.restype = wintypes.UINT
    user32.VkKeyScanW.argtypes = [wintypes.WCHAR]
    user32.VkKeyScanW.restype = ctypes.c_short


def _send(*inputs: INPUT) -> None:
    arr = (INPUT * len(inputs))(*inputs)
    sent = user32.SendInput(len(inputs), arr, ctypes.sizeof(INPUT))
    if sent != len(inputs):
        raise OSError(f"SendInput sent {sent} of {len(inputs)} events (error {ctypes.get_last_error()}); input may be blocked by a higher-privilege window")


def _mouse(flags: int, data: int = 0) -> INPUT:
    return INPUT(type=INPUT_MOUSE, u=_INPUTUNION(mi=MOUSEINPUT(0, 0, ctypes.c_uint32(data).value, flags, 0, 0)))


def _key(vk: int, up: bool = False, scan: int = 0, unicode: bool = False) -> INPUT:
    flags = (KEYEVENTF_KEYUP if up else 0) | (KEYEVENTF_UNICODE if unicode else 0)
    if not unicode and vk in EXTENDED_VKS:
        flags |= KEYEVENTF_EXTENDEDKEY
    return INPUT(type=INPUT_KEYBOARD, u=_INPUTUNION(ki=KEYBDINPUT(0 if unicode else vk, scan, flags, 0, 0)))


# --------------------------------------------------------------------------- keys

VK = {
    "return": 0x0D, "enter": 0x0D, "kp_enter": 0x0D, "tab": 0x09, "escape": 0x1B, "esc": 0x1B,
    "backspace": 0x08, "delete": 0x2E, "del": 0x2E, "home": 0x24, "end": 0x23,
    "page_up": 0x21, "pageup": 0x21, "prior": 0x21, "page_down": 0x22, "pagedown": 0x22, "next": 0x22,
    "left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28, "space": 0x20, "insert": 0x2D,
    "shift": 0x10, "shift_l": 0x10, "shift_r": 0x10, "ctrl": 0x11, "control": 0x11, "control_l": 0x11, "control_r": 0x11,
    "alt": 0x12, "alt_l": 0x12, "alt_r": 0x12, "super": 0x5B, "super_l": 0x5B, "win": 0x5B, "cmd": 0x5B, "meta": 0x5B,
    "caps_lock": 0x14, "print": 0x2C, "menu": 0x5D,
    "minus": 0xBD, "plus": 0xBB, "equal": 0xBB, "comma": 0xBC, "period": 0xBE, "slash": 0xBF, "semicolon": 0xBA,
}
VK.update({f"f{i}": 0x6F + i for i in range(1, 25)})
EXTENDED_VKS = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x5B, 0x5D}
MODIFIER_VKS = {0x10, 0x11, 0x12, 0x5B}


def key_to_vk(name: str) -> tuple[int, list[int]]:
    """Map one key name to (vk, extra modifier vks needed, e.g. shift for '?')."""
    n = name.strip()
    low = n.lower()
    if low in VK:
        return VK[low], []
    if len(n) == 1:
        if n.isascii() and n.isalnum():
            return ord(n.upper()), []
        if IS_WINDOWS:
            res = user32.VkKeyScanW(n)
            if res != -1:
                mods = []
                shift_state = (res >> 8) & 0xFF
                if shift_state & 1:
                    mods.append(0x10)
                if shift_state & 2:
                    mods.append(0x11)
                if shift_state & 4:
                    mods.append(0x12)
                return res & 0xFF, mods
    raise ValueError(f"unknown key name: {name!r}")


def parse_combo(combo: str) -> list[int]:
    """'ctrl+shift+s' -> [VK_CONTROL, VK_SHIFT, ord('S')]. A lone '+' is the plus key."""
    parts = ["+"] if combo.strip() == "+" else [p for p in combo.split("+") if p != ""]
    vks: list[int] = []
    for p in parts:
        vk, mods = key_to_vk(p)
        for m in mods:
            if m not in vks:
                vks.append(m)
        vks.append(vk)
    if not vks:
        raise ValueError(f"empty key combination: {combo!r}")
    return vks


def parse_modifiers(text: str | None) -> list[int]:
    return parse_combo(text) if text else []


# --------------------------------------------------------------------------- mouse / keyboard API


def move(x: int, y: int) -> None:
    _need_windows()
    set_dpi_aware()
    if not user32.SetCursorPos(int(x), int(y)):
        raise OSError(f"SetCursorPos failed: {ctypes.get_last_error()}")


def cursor_pos() -> tuple[int, int]:
    _need_windows()
    set_dpi_aware()
    pt = wintypes.POINT()
    user32.GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y


_BUTTONS = {
    "left": (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
    "right": (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
    "middle": (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
}


def mouse_button(button: str = "left", down: bool = True) -> None:
    _need_windows()
    d, u = _BUTTONS[button]
    _send(_mouse(d if down else u))


def press_modifiers(vks: list[int], up: bool = False) -> None:
    if vks:
        _send(*[_key(v, up=up) for v in (reversed(vks) if up else vks)])


def click(x: int | None, y: int | None, button: str = "left", count: int = 1, modifiers: list[int] | None = None) -> None:
    _need_windows()
    if x is not None and y is not None:
        move(x, y)
        time.sleep(0.03)
    mods = modifiers or []
    press_modifiers(mods)
    try:
        d, u = _BUTTONS[button]
        for _ in range(count):
            _send(_mouse(d), _mouse(u))
            time.sleep(0.04)
    finally:
        press_modifiers(mods, up=True)


def drag(start: tuple[int, int], end: tuple[int, int], modifiers: list[int] | None = None) -> None:
    _need_windows()
    move(*start)
    mods = modifiers or []
    press_modifiers(mods)
    try:
        _send(_mouse(MOUSEEVENTF_LEFTDOWN))
        steps = 12
        for i in range(1, steps + 1):
            move(start[0] + (end[0] - start[0]) * i // steps, start[1] + (end[1] - start[1]) * i // steps)
            time.sleep(0.01)
        _send(_mouse(MOUSEEVENTF_LEFTUP))
    finally:
        press_modifiers(mods, up=True)


def scroll(x: int | None, y: int | None, direction: str, amount: int = 3, modifiers: list[int] | None = None) -> None:
    _need_windows()
    if x is not None and y is not None:
        move(x, y)
    mods = modifiers or []
    press_modifiers(mods)
    try:
        if direction in ("up", "down"):
            _send(_mouse(MOUSEEVENTF_WHEEL, 120 * amount * (1 if direction == "up" else -1)))
        elif direction in ("left", "right"):
            _send(_mouse(MOUSEEVENTF_HWHEEL, 120 * amount * (1 if direction == "right" else -1)))
        else:
            raise ValueError(f"scroll_direction must be up/down/left/right, got {direction!r}")
    finally:
        press_modifiers(mods, up=True)


def key_combo(combo: str, repeat: int = 1) -> None:
    _need_windows()
    vks = parse_combo(combo)
    for _ in range(max(1, int(repeat))):
        _send(*[_key(v) for v in vks])
        _send(*[_key(v, up=True) for v in reversed(vks)])
        time.sleep(0.02)


def hold(combo: str, seconds: float) -> None:
    _need_windows()
    vks = parse_combo(combo)
    _send(*[_key(v) for v in vks])
    try:
        time.sleep(max(0.0, min(300.0, float(seconds))))
    finally:
        _send(*[_key(v, up=True) for v in reversed(vks)])


def type_text(text: str, delay: float = 0.005) -> None:
    _need_windows()
    for ch in text.replace("\r\n", "\n"):
        if ch == "\n":
            key_combo("Return")
            continue
        if ch == "\t":
            key_combo("Tab")
            continue
        data = ch.encode("utf-16-le")
        units = [int.from_bytes(data[i : i + 2], "little") for i in range(0, len(data), 2)]
        for u in units:
            _send(_key(0, scan=u, unicode=True), _key(0, up=True, scan=u, unicode=True))
        if delay:
            time.sleep(delay)


# --------------------------------------------------------------------------- windows

if IS_WINDOWS:
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def _window_title(hwnd) -> str:
    n = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value


def _exe_for_pid(pid: int) -> str:
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
        return ""
    finally:
        kernel32.CloseHandle(h)


def foreground_window() -> tuple[str, str]:
    """(window title, executable name) of the window that would receive input."""
    _need_windows()
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return "", ""
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return _window_title(hwnd), _exe_for_pid(pid.value)


def find_window(title: str):
    _need_windows()
    user32.FindWindowW.restype = wintypes.HWND
    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    return user32.FindWindowW(None, title)


def bring_to_front(hwnd) -> bool:
    """Best effort: Windows only lets a process take focus in some cases.
    The Alt tap is the documented workaround for SetForegroundWindow limits."""
    _need_windows()
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.ShowWindow(hwnd, 9)  # SW_RESTORE
    _send(_key(0x12), _key(0x12, up=True))
    ok = bool(user32.SetForegroundWindow(hwnd))
    time.sleep(0.2)
    return ok and user32.GetForegroundWindow() == hwnd
