"""Generate deterministic sample data for the pilot workflows.

  ERP and CRM exports for two periods (workflow 2: reconciliation)
  warehouse.sqlite with a sales table (workflow 7: ad-hoc warehouse question)

Known answers (used by the eval graders):
  2026-10: 7 mismatches    2026-11: 4 mismatches
"""

from __future__ import annotations

import csv
import random
import sqlite3
from pathlib import Path

HERE = Path(__file__).parent
CUSTOMERS = ["Acme Ltd", "Brightline", "Cobalt Foods", "Delta Retail", "Evergreen", "Fjord Logistics", "Granite Co", "Harbor Health"]


def write_csv(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def period(name: str, seed: int, n: int, amount_diffs: int, missing_crm: int, missing_erp: int, name_diffs: int) -> None:
    rng = random.Random(seed)
    erp, crm = [], []
    for i in range(n):
        inv = f"INV-{name.replace('-', '')}-{i + 1:04d}"
        cust = CUSTOMERS[i % len(CUSTOMERS)]
        amt = round(rng.uniform(200, 9000), 2)
        erp.append([inv, cust, f"{amt:.2f}", "posted"])
        crm.append([inv, cust, f"{amt:.2f}", "closed_won"])
    idx = list(range(n))
    rng.shuffle(idx)
    cursor = 0

    def take(k):
        nonlocal cursor
        out = idx[cursor : cursor + k]
        cursor += k
        return out

    for i in take(amount_diffs):
        crm[i][2] = f"{float(crm[i][2]) + rng.choice([-150.0, 75.5, 310.25]):.2f}"
    for i in take(name_diffs):
        crm[i][1] = crm[i][1].upper() + " INC"
    drop_crm = set(take(missing_crm))
    drop_erp = set(take(missing_erp))
    erp_rows = [r for i, r in enumerate(erp) if i not in drop_erp]
    crm_rows = [r for i, r in enumerate(crm) if i not in drop_crm]
    write_csv(HERE / f"erp_export_{name}.csv", ["invoice_id", "customer", "amount", "status"], erp_rows)
    write_csv(HERE / f"crm_export_{name}.csv", ["invoice_id", "account_name", "amount", "stage"], crm_rows)


def warehouse() -> None:
    path = HERE / "warehouse.sqlite"
    if path.exists():
        path.unlink()
    rng = random.Random(7)
    con = sqlite3.connect(path)
    con.execute("create table sales (order_id text primary key, order_date text, region text, product text, revenue real, churned integer)")
    regions = ["North", "South", "East", "West"]
    rows = []
    for i in range(400):
        month = 7 + i % 6  # Jul..Dec 2026
        rows.append((f"O{i:05d}", f"2026-{month:02d}-{1 + i % 28:02d}", regions[i % 4], rng.choice(["Core", "Plus", "Max"]), round(rng.uniform(50, 5000), 2), 1 if rng.random() < 0.12 else 0))
    con.executemany("insert into sales values (?,?,?,?,?,?)", rows)
    con.commit()
    con.close()


if __name__ == "__main__":
    period("2026-10", seed=10, n=40, amount_diffs=3, missing_crm=2, missing_erp=1, name_diffs=1)
    period("2026-11", seed=11, n=30, amount_diffs=2, missing_crm=1, missing_erp=1, name_diffs=0)
    warehouse()
    print("sample data written to", HERE)
