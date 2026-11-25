"""Approval inbox and clarifying-question box for portal runs.

A run thread calls WebApprover.request() (or the ask callback); that queues an
item the portal shows and then blocks until a person decides or the timeout
expires. A timeout is always a decline: nothing is ever auto-approved.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from ..policy import ApprovalDecision, ApprovalRequest


@dataclass
class PendingApproval:
    id: str
    session_id: str
    requested_by: str
    req: ApprovalRequest
    created_at: float
    timeout_s: float
    decision: ApprovalDecision | None = None
    _event: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def deadline(self) -> float:
        return self.created_at + self.timeout_s


class ApprovalInbox:
    def __init__(self, on_decided: Callable[[PendingApproval], None] | None = None, keep_history: int = 200):
        self._items: dict[str, PendingApproval] = {}
        self._history: list[PendingApproval] = []
        self._lock = threading.Lock()
        self._on_decided = on_decided
        self._keep = keep_history

    def submit(self, session_id: str, requested_by: str, req: ApprovalRequest, timeout_s: float) -> ApprovalDecision:
        item = PendingApproval(secrets.token_hex(8), session_id, requested_by, req, time.time(), float(timeout_s))
        with self._lock:
            self._items[item.id] = item
        item._event.wait(timeout=max(0.0, item.timeout_s))
        with self._lock:
            if item.decision is None:
                item.decision = ApprovalDecision(False, "timeout", f"no decision within {int(item.timeout_s)} s; declined (never auto-approved)")
            self._finish(item)
        if self._on_decided:
            self._on_decided(item)
        return item.decision

    def _finish(self, item: PendingApproval) -> None:
        self._items.pop(item.id, None)
        self._history.append(item)
        del self._history[: -self._keep]

    def pending(self, session_id: str | None = None) -> list[PendingApproval]:
        with self._lock:
            items = [i for i in self._items.values() if session_id is None or i.session_id == session_id]
        return sorted(items, key=lambda i: i.created_at)

    def history(self, limit: int = 50) -> list[PendingApproval]:
        with self._lock:
            return list(reversed(self._history[-limit:]))

    def get(self, item_id: str) -> PendingApproval | None:
        with self._lock:
            return self._items.get(item_id)

    def decide(self, item_id: str, approved: bool, by: str, note: str = "") -> PendingApproval | None:
        with self._lock:
            item = self._items.get(item_id)
            if item is None or item.decision is not None:
                return None
            item.decision = ApprovalDecision(bool(approved), by, note or "decided in portal")
        item._event.set()
        return item

    def cancel_session(self, session_id: str, by: str, note: str) -> int:
        n = 0
        for item in self.pending(session_id):
            if self.decide(item.id, False, by, note):
                n += 1
        return n


class WebApprover:
    """Approver for one portal run: queues each request in the shared inbox and waits."""

    def __init__(self, inbox: ApprovalInbox, session_id: str, requested_by: str, timeout_s: float):
        self.inbox = inbox
        self.session_id = session_id
        self.requested_by = requested_by
        self.timeout_s = timeout_s

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        return self.inbox.submit(self.session_id, self.requested_by, req, self.timeout_s)


@dataclass
class PendingQuestions:
    session_id: str
    asked_by: str
    questions: list[str]
    created_at: float
    timeout_s: float
    answers: dict[str, str] | None = None
    answered_by: str = ""
    _event: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def deadline(self) -> float:
        return self.created_at + self.timeout_s


class QuestionBox:
    """Clarifying questions from the planner, one open set per session."""

    def __init__(self):
        self._items: dict[str, PendingQuestions] = {}
        self._lock = threading.Lock()

    def asker(self, session_id: str, user: str, timeout_s: float) -> Callable[[list[str]], dict[str, str] | None]:
        def ask(questions: list[str]) -> dict[str, str] | None:
            item = PendingQuestions(session_id, user, list(questions), time.time(), float(timeout_s))
            with self._lock:
                self._items[session_id] = item
            item._event.wait(timeout=max(0.0, item.timeout_s))
            with self._lock:
                self._items.pop(session_id, None)
            return item.answers

        return ask

    def get(self, session_id: str) -> PendingQuestions | None:
        with self._lock:
            return self._items.get(session_id)

    def all(self) -> list[PendingQuestions]:
        with self._lock:
            return list(self._items.values())

    def answer(self, session_id: str, answers: dict[str, str] | None, by: str) -> bool:
        with self._lock:
            item = self._items.get(session_id)
            if item is None or item._event.is_set():
                return False
            item.answers = answers
            item.answered_by = by
        item._event.set()
        return True
