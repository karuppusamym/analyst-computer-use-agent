"""Approval inbox and clarifying-question box for portal runs.

A run thread calls WebApprover.request() (or the ask callback); that queues an
item the portal shows and then blocks until a person decides or the timeout
expires. A timeout is always a decline: nothing is ever auto-approved.

With a PendingStore, every item is written to disk before it is shown and its
decision is written before the run thread is released, so a portal restart
never loses a decision. Items left pending by a dead portal are closed as
orphaned (declined) when the next portal starts, except a plan approval that
carries a plan fingerprint: the next portal "parks" it (see park()). Approving a
parked plan resumes the session, and the resumed run reuses the approval only if
its plan has the same fingerprint (WebApprover.carried); otherwise it asks again.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from ..policy import ApprovalDecision, ApprovalRequest
from .state import PendingStore


@dataclass
class PendingApproval:
    id: str
    session_id: str
    requested_by: str
    req: ApprovalRequest
    created_at: float
    timeout_s: float
    decision: ApprovalDecision | None = None
    outcome: str = ""  # approved / declined / timeout / orphaned, once decided
    parked_at: float | None = None  # set for a plan approval carried over a portal restart (no run thread waits on it)
    _event: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def parked(self) -> bool:
        return self.parked_at is not None

    @property
    def deadline(self) -> float:
        return (self.parked_at if self.parked_at is not None else self.created_at) + self.timeout_s


def _outcome(d: ApprovalDecision) -> str:
    return "approved" if d.approved else ("timeout" if d.by == "timeout" else "declined")


class ApprovalInbox:
    def __init__(self, on_decided: Callable[[PendingApproval], None] | None = None, keep_history: int = 200, store: PendingStore | None = None):
        self._items: dict[str, PendingApproval] = {}
        self._history: list[PendingApproval] = []
        self._lock = threading.Lock()
        self._on_decided = on_decided
        self._keep = keep_history
        self.store = store

    def _persist_close(self, item: PendingApproval) -> bool:
        if self.store is None:
            return True
        d = item.decision
        return self.store.close("approval", item.id, item.outcome, d.by, d.note, approved=d.approved)

    def submit(self, session_id: str, requested_by: str, req: ApprovalRequest, timeout_s: float) -> ApprovalDecision:
        item = PendingApproval(secrets.token_hex(8), session_id, requested_by, req, time.time(), float(timeout_s))
        if self.store is not None:
            try:
                self.store.open("approval", item.id, {
                    "session_id": session_id, "requested_by": requested_by, "created_at": item.created_at, "timeout_s": item.timeout_s,
                    "step_id": req.step_id, "action_class": req.action_class, "summary": req.summary, "preview": req.preview, "approver": req.approver,
                    **({"amount": req.amount} if req.amount is not None else {}),
                    **({"fingerprint": req.fingerprint} if req.fingerprint else {}),
                })
            except OSError as e:  # fail closed: a request that cannot be recorded is declined
                item.decision = ApprovalDecision(False, "portal", f"could not record the request ({e}); declined")
                item.outcome = "declined"
                with self._lock:
                    self._finish(item)
                if self._on_decided:
                    self._on_decided(item)
                return item.decision
        with self._lock:
            self._items[item.id] = item
        item._event.wait(timeout=max(0.0, item.timeout_s))
        with self._lock:
            if item.decision is None:
                item.decision = ApprovalDecision(False, "timeout", f"no decision within {int(item.timeout_s)} s; declined (never auto-approved)")
                item.outcome = "timeout"
                try:
                    self._persist_close(item)
                except OSError:
                    pass  # a decline needs no durable record to be safe
            self._finish(item)
        if self._on_decided:
            self._on_decided(item)
        return item.decision

    def park(self, rec: dict, timeout_s: float) -> PendingApproval:
        """Show a plan approval left pending by an earlier portal again. No run thread waits on it:
        approving it resumes the session (the portal does that), rejecting it or letting it time out
        declines it. The store record must already be adopted by this instance."""
        req = ApprovalRequest(str(rec.get("step_id", "")), str(rec.get("action_class", "")), str(rec.get("summary", "")), str(rec.get("preview", "")), str(rec.get("approver", "")),
                              None if rec.get("amount") is None else str(rec.get("amount")), str(rec.get("fingerprint") or "") or None)
        item = PendingApproval(str(rec["id"]), str(rec.get("session_id", "")), str(rec.get("requested_by", "")), req, float(rec.get("created_at") or time.time()), float(timeout_s), parked_at=time.time())
        with self._lock:
            self._items[item.id] = item
        return item

    def _expire_parked(self) -> None:
        """Parked items have no waiting thread, so their time-out is applied when the inbox is read."""
        now = time.time()
        done = []
        with self._lock:
            for item in list(self._items.values()):
                if item.parked and item.decision is None and now > item.deadline:
                    item.decision = ApprovalDecision(False, "timeout", f"no decision within {int(item.timeout_s)} s after the portal restarted; declined (never auto-approved)")
                    item.outcome = "timeout"
                    try:
                        self._persist_close(item)
                    except OSError:
                        pass
                    self._finish(item)
                    done.append(item)
        for item in done:
            if self._on_decided:
                self._on_decided(item)

    def _finish(self, item: PendingApproval) -> None:
        self._items.pop(item.id, None)
        self._history.append(item)
        del self._history[: -self._keep]

    def pending(self, session_id: str | None = None) -> list[PendingApproval]:
        self._expire_parked()
        with self._lock:
            items = [i for i in self._items.values() if session_id is None or i.session_id == session_id]
        return sorted(items, key=lambda i: i.created_at)

    def history(self, limit: int = 50) -> list[PendingApproval]:
        with self._lock:
            return list(reversed(self._history[-limit:]))

    def get(self, item_id: str) -> PendingApproval | None:
        self._expire_parked()
        with self._lock:
            return self._items.get(item_id)

    def decide(self, item_id: str, approved: bool, by: str, note: str = "") -> PendingApproval | None:
        with self._lock:
            item = self._items.get(item_id)
            if item is None or item.decision is not None:
                return None
            item.decision = ApprovalDecision(bool(approved), by, note or "decided in portal")
            item.outcome = _outcome(item.decision)
            try:
                closed = self._persist_close(item)  # durable before the run thread is released
            except OSError:
                item.decision, item.outcome = None, ""
                raise
            if not closed:  # another portal instance already closed it on disk
                item.decision, item.outcome = None, ""
                return None
            if item.parked:
                self._finish(item)  # no run thread will do it
        item._event.set()
        if item.parked and self._on_decided:
            self._on_decided(item)
        return item

    def cancel_session(self, session_id: str, by: str, note: str) -> int:
        n = 0
        for item in self.pending(session_id):
            if self.decide(item.id, False, by, note):
                n += 1
        return n

    def load_history(self, records: list[dict]) -> None:
        """Closed approval records from disk (earlier portal runs) for the 'Recent decisions' table."""
        items = []
        for r in records:
            if r.get("kind") != "approval" or r.get("status") != "closed":
                continue
            req = ApprovalRequest(str(r.get("step_id", "")), str(r.get("action_class", "")), str(r.get("summary", "")), str(r.get("preview", "")), str(r.get("approver", "")), None if r.get("amount") is None else str(r.get("amount")))
            d = ApprovalDecision(bool(r.get("approved")), str(r.get("by", "")), str(r.get("note", "")), float(r.get("decided_at") or 0))
            items.append(PendingApproval(r["id"], str(r.get("session_id", "")), str(r.get("requested_by", "")), req, float(r.get("created_at") or 0), float(r.get("timeout_s") or 0), d, str(r.get("outcome", ""))))
        items.sort(key=lambda i: i.decision.decided_at)
        with self._lock:
            known = {i.id for i in self._history}
            self._history = [i for i in items if i.id not in known][-self._keep :] + self._history
            del self._history[: -self._keep]


class WebApprover:
    """Approver for one portal run: queues each request in the shared inbox and waits.

    carried: a plan approval decided after a portal restart ({"fingerprint", "by", "request_id",
    "note"}). It answers the run's first approval request only if that is the plan and its
    fingerprint is exactly the approved one; anything else is logged and goes to the inbox.
    It is used at most once."""

    user_source = "portal"  # the run's user signed in to the portal (vault team:/group: sharing uses SSO groups)

    def __init__(self, inbox: ApprovalInbox, session_id: str, requested_by: str, timeout_s: float, carried: dict | None = None, on_event: Callable[..., None] | None = None):
        self.inbox = inbox
        self.session_id = session_id
        self.requested_by = requested_by
        self.timeout_s = timeout_s
        self.carried = dict(carried) if carried else None
        self.on_event = on_event or (lambda *a, **k: None)

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        c, self.carried = self.carried, None
        if c is not None:
            want = str(c.get("fingerprint") or "")
            got = str(req.fingerprint or "")
            info = {"request_id": c.get("request_id"), "approved_by": c.get("by"), "step": req.step_id}
            if req.step_id == "plan" and req.action_class == "plan" and want and got and hmac.compare_digest(want, got):
                self.on_event("plan_approval_reused", fingerprint=got, **info)
                return ApprovalDecision(True, str(c.get("by") or ""), f"approved after a portal restart (request {c.get('request_id')}); the plan is unchanged" + (f"; {c['note']}" if c.get("note") else ""))
            self.on_event("plan_approval_mismatch", expected=want, got=got or None, reason="the plan changed since it was approved" if req.step_id == "plan" else "the first request was not the plan", **info)
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
    id: str = field(default_factory=lambda: secrets.token_hex(8))
    closed: bool = False
    _event: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def deadline(self) -> float:
        return self.created_at + self.timeout_s


class QuestionBox:
    """Clarifying questions from the planner, one open set per session."""

    def __init__(self, store: PendingStore | None = None):
        self._items: dict[str, PendingQuestions] = {}
        self._lock = threading.Lock()
        self.store = store

    def asker(self, session_id: str, user: str, timeout_s: float) -> Callable[[list[str]], dict[str, str] | None]:
        def ask(questions: list[str]) -> dict[str, str] | None:
            item = PendingQuestions(session_id, user, list(questions), time.time(), float(timeout_s))
            if self.store is not None:
                try:
                    self.store.open("question", item.id, {"session_id": session_id, "asked_by": user, "questions": item.questions, "created_at": item.created_at, "timeout_s": item.timeout_s})
                except OSError:
                    return None  # unanswered: the run stops with needs_input
            with self._lock:
                self._items[session_id] = item
            item._event.wait(timeout=max(0.0, item.timeout_s))
            with self._lock:
                if not item.closed:
                    item.closed = True
                    item.answers = None
                    if self.store is not None:
                        try:
                            self.store.close("question", item.id, "timeout", "timeout", f"no answers within {int(item.timeout_s)} s")
                        except OSError:
                            pass
                if self._items.get(session_id) is item:
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
            if item is None or item.closed:
                return False
            if self.store is not None:
                # Who answered is durable before the run thread continues; the answers themselves
                # go into the run's parameters and audit log, not into portal_state.
                if not self.store.close("question", item.id, "answered" if answers else "declined", by, "" if answers else "declined in portal"):
                    return False
            item.closed = True
            item.answers = answers
            item.answered_by = by
        item._event.set()
        return True
