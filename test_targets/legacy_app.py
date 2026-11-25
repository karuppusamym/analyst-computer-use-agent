"""Legacy Ledger - TEST: a stand-in "legacy desktop app with no API" (pilot workflow 6).

Used to test the desktop tiers on a real PC without a VM. It touches nothing
but the CSV file given by --out.

  python test_targets/legacy_app.py --out workspace/legacy_ledger.csv [--coords coords.json]

--coords writes each widget's screen rectangle (physical pixels) after the
window is shown, so tests can find targets without pixel guessing.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import json
import sys
import tkinter as tk
from pathlib import Path

TITLE = "Legacy Ledger - TEST"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="workspace/legacy_ledger.csv")
    ap.add_argument("--coords", default="")
    args = ap.parse_args()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

    root = tk.Tk(className="legacyledger")
    root.title(TITLE)
    root.geometry("+120+120")
    root.attributes("-topmost", True)

    frame = tk.Frame(root, name="form", padx=16, pady=16)
    frame.pack()
    entries: dict[str, tk.Entry] = {}
    for row, label in enumerate(("Account", "Amount", "Memo")):
        tk.Label(frame, text=label + ":", name=f"label_{label.lower()}", width=10, anchor="w").grid(row=row, column=0, pady=4)
        e = tk.Entry(frame, name=f"entry_{label.lower()}", width=32)
        e.grid(row=row, column=1, pady=4)
        entries[label.lower()] = e

    status = tk.Label(frame, name="status", text="Saved: 0 entries", anchor="w")

    def count() -> int:
        if not out.exists():
            return 0
        with open(out, newline="", encoding="utf-8") as f:
            return max(0, sum(1 for _ in f) - 1)

    def save() -> None:
        new = not out.exists()
        with open(out, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["account", "amount", "memo"])
            w.writerow([entries["account"].get(), entries["amount"].get(), entries["memo"].get()])
        for e in entries.values():
            e.delete(0, tk.END)
        status.config(text=f"Saved: {count()} entries")

    button = tk.Button(frame, name="save_entry", text="Save Entry", command=save, width=14)
    button.grid(row=3, column=1, sticky="e", pady=8)
    status.grid(row=4, column=0, columnspan=2, sticky="w")
    status.config(text=f"Saved: {count()} entries")

    def write_coords() -> None:
        root.update_idletasks()
        widgets = {"account": entries["account"], "amount": entries["amount"], "memo": entries["memo"], "save_entry": button, "status": status}
        data = {name: {"x": w.winfo_rootx(), "y": w.winfo_rooty(), "w": w.winfo_width(), "h": w.winfo_height()} for name, w in widgets.items()}
        Path(args.coords).write_text(json.dumps(data), encoding="utf-8")

    if args.coords:
        root.after(600, write_coords)
    if not args.coords:  # test runs keep it on top so nothing else takes input
        root.after(1500, lambda: root.attributes("-topmost", False))
    root.mainloop()


if __name__ == "__main__":
    main()
