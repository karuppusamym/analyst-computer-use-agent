"""Playbook review: list playbooks and drafts, promote or reject drafts.

A draft is any file under playbooks/drafts/, or a playbook file whose JSON has
"status": "draft". Drafts are never run. Approving a draft validates it, stamps
the reviewer and moves it into playbooks/; rejecting moves it to
playbooks/drafts/rejected/. Unknown fields are kept as they are.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from ..playbook import Playbook, PlaybookError, playbook_from_dict

SUFFIXES = (".json", ".yaml", ".yml")
NOT_RUNNABLE = {"draft", "rejected", "pending_review", "proposed", "retired"}
AUTHOR_FIELDS = ("author", "created_by", "recorded_by", "drafted_by", "taught_by")


class ReviewError(Exception):
    pass


@dataclass
class PlaybookEntry:
    id: str  # path relative to the playbooks folder, posix style
    path: Path
    raw: dict | None
    playbook: Playbook | None
    error: str
    in_drafts: bool

    @property
    def status(self) -> str:
        st = str((self.raw or {}).get("status", "") or "").lower()
        if "/rejected/" in f"/{self.id}":
            return "rejected"
        if self.in_drafts and st in ("", "approved"):
            return "draft"
        return st or "approved"

    @property
    def is_draft(self) -> bool:
        return self.in_drafts or self.status in NOT_RUNNABLE

    @property
    def reviewable(self) -> bool:
        return self.status not in ("rejected", "approved", "retired") and self.path.suffix == ".json"

    @property
    def author(self) -> str:
        raw = self.raw or {}
        return next((str(raw[k]) for k in AUTHOR_FIELDS if raw.get(k)), "")


def _read_raw(p: Path) -> dict:
    text = p.read_text(encoding="utf-8")
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml  # optional
        except ImportError as e:
            raise PlaybookError("pyyaml is not installed") from e
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise PlaybookError("playbook file is not an object")
    return data


def _entry(root: Path, p: Path, in_drafts: bool) -> PlaybookEntry:
    rel = p.relative_to(root).as_posix()
    raw, pb, err = None, None, ""
    try:
        raw = _read_raw(p)
        pb = playbook_from_dict(raw, str(p))
    except Exception as e:  # noqa: BLE001 - show the problem to the reviewer
        err = f"{type(e).__name__}: {e}"
    return PlaybookEntry(rel, p, raw, pb, err, in_drafts)


def list_playbooks(folder: str | Path) -> list[PlaybookEntry]:
    root = Path(folder)
    out: list[PlaybookEntry] = []
    if not root.exists():
        return out
    for p in sorted(root.iterdir()):
        if p.is_file() and p.suffix in SUFFIXES:
            out.append(_entry(root, p, False))
    for sub, flag in ((root / "drafts", True), (root / "drafts" / "rejected", True)):
        if sub.is_dir():
            for p in sorted(sub.iterdir()):
                if p.is_file() and p.suffix in SUFFIXES:
                    out.append(_entry(root, p, flag))
    return out


def find_entry(folder: str | Path, entry_id: str) -> PlaybookEntry | None:
    for e in list_playbooks(folder):
        if e.id == entry_id:
            return e
    return None


def _write_json(p: Path, data: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)


def _check_reviewer(entry: PlaybookEntry, reviewer: str, reviewer_is_admin: bool) -> None:
    if entry.author and entry.author == reviewer and not reviewer_is_admin:
        raise ReviewError("you drafted this playbook; another reviewer must approve it")


def approve_draft(folder: str | Path, entry_id: str, reviewer: str, note: str = "", reviewer_is_admin: bool = False) -> Path:
    root = Path(folder)
    entry = find_entry(root, entry_id)
    if entry is None:
        raise ReviewError("no such playbook")
    if not entry.is_draft or not entry.reviewable:
        raise ReviewError(f"only JSON drafts can be approved (this one is {entry.status})")
    if entry.playbook is None:
        raise ReviewError(f"the draft does not load: {entry.error}")
    _check_reviewer(entry, reviewer, reviewer_is_admin)
    data = dict(entry.raw or {})
    data.update(status="approved", reviewed_by=reviewer, reviewed_at=time.strftime("%Y-%m-%dT%H:%M:%S"), review_note=note)
    dest = root / entry.path.name if entry.in_drafts else entry.path
    if entry.in_drafts:
        for other in list_playbooks(root):
            if other.in_drafts or other.path == dest:
                continue
            if other.playbook and other.playbook.name == entry.playbook.name and other.playbook.version >= entry.playbook.version:
                raise ReviewError(f"{other.id} already has {other.playbook.name} v{other.playbook.version}; raise the draft's version first")
        if dest.exists():
            existing = find_entry(root, dest.name)
            if not (existing and existing.playbook and existing.playbook.name == entry.playbook.name and existing.playbook.version < entry.playbook.version):
                raise ReviewError(f"{dest.name} already exists in the playbook folder")
    _write_json(dest, data)
    if entry.in_drafts:
        entry.path.unlink()
    return dest


def reject_draft(folder: str | Path, entry_id: str, reviewer: str, note: str = "") -> Path:
    root = Path(folder)
    entry = find_entry(root, entry_id)
    if entry is None:
        raise ReviewError("no such playbook")
    if not entry.is_draft or not entry.reviewable:
        raise ReviewError(f"only JSON drafts can be rejected (this one is {entry.status})")
    data = dict(entry.raw or {}) if entry.raw is not None else {"unparsed": entry.path.read_text(encoding="utf-8", errors="replace")}
    data.update(status="rejected", reviewed_by=reviewer, reviewed_at=time.strftime("%Y-%m-%dT%H:%M:%S"), review_note=note)
    dest = root / "drafts" / "rejected" / entry.path.name
    if dest.exists():
        dest = dest.with_name(f"{dest.stem}-{time.strftime('%Y%m%d%H%M%S')}{dest.suffix}")
    _write_json(dest, data)
    entry.path.unlink()
    return dest
