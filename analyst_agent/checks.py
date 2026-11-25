"""Machine-checkable success conditions. No check, no step.

Each check is a small dict, e.g.
  {"type": "file_exists", "path": "{out}/mismatches.csv"}
  {"type": "csv_rows", "path": "...", "min": 1, "max": 500}
  {"type": "csv_sum_matches", "path": "...", "column": "amount", "source": "...", "source_column": "amount"}
  {"type": "model", "criteria": "Commentary mentions every region"}   # judged by the verifier

Deterministic checks run in plain Python (csv module, no pandas needed).
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass
class CheckOutcome:
    name: str
    passed: bool
    detail: str
    kind: str = "deterministic"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _rows(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _num(v: str) -> float:
    return float(str(v).replace(",", "").strip() or 0)


def _file_exists(c: dict, base: Path) -> CheckOutcome:
    p = base / c["path"]
    ok = p.exists() and p.stat().st_size >= c.get("min_bytes", 1)
    return CheckOutcome(f"file exists: {c['path']}", ok, f"{p} {'found' if ok else 'missing or empty'}")


def _csv_rows(c: dict, base: Path) -> CheckOutcome:
    n = len(_rows(base / c["path"]))
    lo, hi = c.get("min", 0), c.get("max", math.inf)
    if "equals" in c:
        lo = hi = c["equals"]
    return CheckOutcome(f"row count of {c['path']} in [{lo}, {hi}]", lo <= n <= hi, f"{n} rows")


def _csv_has_columns(c: dict, base: Path) -> CheckOutcome:
    with open(base / c["path"], newline="", encoding="utf-8-sig") as f:
        header = next(csv.reader(f), [])
    missing = [col for col in c["columns"] if col not in header]
    return CheckOutcome(f"columns present in {c['path']}", not missing, f"missing: {missing}" if missing else f"header: {header}")


def _csv_sum_matches(c: dict, base: Path) -> CheckOutcome:
    got = sum(_num(r[c["column"]]) for r in _rows(base / c["path"]))
    if "expected" in c:
        want = float(c["expected"])
    else:
        want = sum(_num(r[c.get("source_column", c["column"])]) for r in _rows(base / c["source"]))
    tol = c.get("tolerance", 0.005)
    return CheckOutcome(f"total of {c['column']} matches source", abs(got - want) <= tol, f"output={got:.2f} source={want:.2f}")


def _text_contains(c: dict, base: Path) -> CheckOutcome:
    text = (base / c["path"]).read_text(encoding="utf-8", errors="replace")
    needles = c["text"] if isinstance(c["text"], list) else [c["text"]]
    missing = [t for t in needles if t not in text]
    return CheckOutcome(f"{c['path']} contains expected text", not missing, f"missing: {missing}" if missing else "all present")


def _json_field_equals(c: dict, base: Path) -> CheckOutcome:
    data = json.loads((base / c["path"]).read_text(encoding="utf-8"))
    value = data
    for part in c["field"].split("."):
        value = value[int(part)] if isinstance(value, list) else value.get(part)
    return CheckOutcome(f"{c['path']}:{c['field']} == {c['value']!r}", value == c["value"], f"value={value!r}")


CHECKS: dict[str, Callable[[dict, Path], CheckOutcome]] = {
    "file_exists": _file_exists,
    "csv_rows": _csv_rows,
    "csv_has_columns": _csv_has_columns,
    "csv_sum_matches": _csv_sum_matches,
    "text_contains": _text_contains,
    "json_field_equals": _json_field_equals,
}


def run_deterministic(checks: list[dict], base: Path) -> tuple[list[CheckOutcome], list[dict]]:
    """Run the checks code can decide. Returns (outcomes, checks left for the model verifier)."""
    outcomes, for_model = [], []
    for c in checks:
        kind = c.get("type")
        if kind == "model":
            for_model.append(c)
            continue
        fn = CHECKS.get(kind)
        if fn is None:
            outcomes.append(CheckOutcome(f"unknown check {kind}", False, "check type not supported"))
            continue
        try:
            outcomes.append(fn(c, base))
        except Exception as e:  # a broken check is a failed check
            outcomes.append(CheckOutcome(f"{kind} {c.get('path', '')}", False, f"error: {type(e).__name__}: {e}"))
    return outcomes, for_model
