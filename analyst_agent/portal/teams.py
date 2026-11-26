"""Teams for session visibility and approval rights (config `portal.teams`).

    "teams": {
      "finance": {
        "members": ["alice", "bob"],
        "reviewers": ["rita", {"name": "rob", "action_classes": ["plan", "send"], "max_amount": 5000}],
        "playbooks": ["erp-crm-reconciliation", "budget-*"],
        "sso_groups": ["fin-analysts"],            # SSO groups whose users are members
        "sso_reviewer_groups": ["fin-approvers"],  # SSO groups whose users are reviewers
        "reviewer_limits": {"action_classes": ["plan", "submit"], "max_amount": 1000}
      }
    }

- Members and reviewers of a team are all "in" the team: each sees the others' sessions.
  Membership = the names listed in the config, plus (with SSO sign-in only) users whose
  current SSO groups are listed in `sso_groups` / `sso_reviewer_groups`.
- A reviewer may decide an approval only if the session's playbook is in the playbooks list
  of a team where they are a reviewer (fnmatch patterns; "*" = any playbook, including sessions
  with no playbook). With no teams configured, every reviewer may decide (the old rule).
- A reviewer may only *approve* within their limits: `action_classes` (the request's
  action_class must be listed) and `max_amount` (a request that carries an amount must be at
  most this; an amount that is not a number is refused). A reviewer entry given as a dict
  sets its own limits; plain names and group reviewers get the team's `reviewer_limits`.
  No limits = unlimited (the old rule). Rejecting is always allowed where deciding is.
- Admins are not limited by teams.
"""

from __future__ import annotations

import fnmatch
import json
import threading
import time
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Iterable

MAX_GROUPS = 100


def _names(v: Any) -> set[str]:
    return {str(x) for x in v} if isinstance(v, (list, tuple, set)) else set()


def parse_amount(value: Any) -> Decimal:
    """'12,500.00', '12 500', '-300', 4000 -> Decimal. Raises ValueError for anything else."""
    if isinstance(value, bool):
        raise ValueError("not a number")
    text = str(value).strip().replace(",", "").replace("_", "").replace(" ", "")
    try:
        d = Decimal(text)
    except InvalidOperation as e:
        raise ValueError(f"{value!r} is not a number") from e
    if not d.is_finite():
        raise ValueError(f"{value!r} is not a finite number")
    return d


def fmt_amount(d: Decimal) -> str:
    return f"{d:,}"


@dataclass(frozen=True)
class ReviewerLimits:
    action_classes: frozenset[str] | None = None  # None = any action class
    max_amount: Decimal | None = None  # None = no amount limit
    error: str = ""  # a broken limit in the config: approve nothing (fail closed)

    @property
    def unlimited(self) -> bool:
        return self.action_classes is None and self.max_amount is None and not self.error

    def refusal(self, action_class: str, amount: Any) -> str:
        """Why these limits do not allow approving this request ("" = allowed)."""
        if self.error:
            return f"your reviewer limits in the config are invalid ({self.error})"
        if self.action_classes is not None and action_class not in self.action_classes:
            allowed = ", ".join(sorted(self.action_classes)) or "nothing"
            return f"your reviewer limits allow only {allowed}; this request is '{action_class}'"
        if self.max_amount is not None and amount not in (None, ""):
            try:
                a = parse_amount(amount)
            except ValueError:
                return f"the amount {str(amount)!r} is not a number, and you have an amount limit"
            if abs(a) > self.max_amount:
                return f"the amount {fmt_amount(a)} is above your limit of {fmt_amount(self.max_amount)}"
        return ""

    def describe(self) -> str:
        if self.error:
            return f"invalid: {self.error}"
        parts = []
        if self.action_classes is not None:
            parts.append("action classes " + (", ".join(sorted(self.action_classes)) or "(none)"))
        if self.max_amount is not None:
            parts.append(f"max amount {fmt_amount(self.max_amount)}")
        return "; ".join(parts) or "unlimited"


def _limits(raw: Any, inherit: ReviewerLimits | None = None) -> ReviewerLimits:
    base = inherit or ReviewerLimits()
    if not isinstance(raw, dict):
        return base
    acs, mx, err = base.action_classes, base.max_amount, base.error
    if "action_classes" in raw:
        v = raw["action_classes"]
        if isinstance(v, str):
            v = [v]
        if isinstance(v, (list, tuple)):
            acs = frozenset(str(x) for x in v)
        else:
            err = "action_classes must be a list"
    if "max_amount" in raw and raw["max_amount"] is not None:
        try:
            mx = parse_amount(raw["max_amount"])
            if mx < 0:
                raise ValueError("negative")
        except ValueError:
            err = f"max_amount {raw['max_amount']!r} is not a non-negative number"
    return ReviewerLimits(acs, mx, err)


@dataclass
class Team:
    name: str
    members: set[str] = field(default_factory=set)
    reviewers: dict[str, ReviewerLimits] = field(default_factory=dict)
    playbooks: set[str] = field(default_factory=set)
    sso_groups: set[str] = field(default_factory=set)
    sso_reviewer_groups: set[str] = field(default_factory=set)
    group_limits: ReviewerLimits = field(default_factory=ReviewerLimits)

    def covers(self, playbook: str | None) -> bool:
        return "*" in self.playbooks or (playbook is not None and any(fnmatch.fnmatchcase(playbook, pat) for pat in self.playbooks))


@dataclass(frozen=True)
class ReviewRights:
    """What a reviewer may do with one pending approval."""

    decide: bool  # may see the request as theirs and reject it
    approve: bool
    reason: str = ""  # why not, when approve is False


class Teams:
    def __init__(self, cfg: Any, groups_of: Callable[[str], Iterable[str]] | None = None):
        """groups_of(user) gives another user's last-seen SSO groups (None: no SSO group mapping)."""
        self.teams: dict[str, Team] = {}
        self.groups_of = groups_of
        self.warnings: list[str] = []
        for name, t in (cfg or {}).items() if isinstance(cfg, dict) else []:
            if not isinstance(t, dict):
                continue
            team = Team(str(name), _names(t.get("members")), {}, _names(t.get("playbooks")), _names(t.get("sso_groups")), _names(t.get("sso_reviewer_groups")))
            team.group_limits = _limits(t.get("reviewer_limits"))
            if team.group_limits.error:
                self.warnings.append(f"team {name}: reviewer_limits: {team.group_limits.error}; those reviewers approve nothing")
            raw_reviewers = t.get("reviewers")
            for r in raw_reviewers if isinstance(raw_reviewers, (list, tuple)) else []:
                if isinstance(r, dict):
                    rname = str(r.get("name") or r.get("user") or "").strip()
                    if not rname:
                        self.warnings.append(f"team {name}: a reviewer entry has no name; ignored")
                        continue
                    lim = _limits(r, team.group_limits)
                    if lim.error:
                        self.warnings.append(f"team {name}: reviewer {rname}: {lim.error}; they approve nothing in this team")
                    team.reviewers[rname] = lim
                else:
                    team.reviewers[str(r)] = team.group_limits
            self.teams[team.name] = team

    @property
    def configured(self) -> bool:
        return bool(self.teams)

    def known_groups(self) -> set[str]:
        """Every SSO group name the team config refers to (only these are kept in sessions)."""
        out: set[str] = set()
        for t in self.teams.values():
            out |= t.sso_groups | t.sso_reviewer_groups
        return out

    def _groups(self, user: str, groups: Iterable[str] | None) -> set[str]:
        if groups is not None:
            return {str(g) for g in groups}
        if self.groups_of is None:
            return set()
        try:
            return {str(g) for g in self.groups_of(user) or ()}
        except Exception:  # noqa: BLE001 - a broken lookup means no group membership
            return set()

    def _reviewer_limits(self, t: Team, user: str, groups: set[str]) -> ReviewerLimits | None:
        if user in t.reviewers:
            return t.reviewers[user]  # an explicit entry wins over group membership
        if self.groups_of is not None and groups & t.sso_reviewer_groups:
            return t.group_limits
        return None

    def teams_of(self, user: str, groups: Iterable[str] | None = None) -> list[str]:
        g = self._groups(user, groups) if self.groups_of is not None else set()
        return [n for n, t in self.teams.items() if user in t.members or user in t.reviewers or (g & (t.sso_groups | t.sso_reviewer_groups))]

    def share_team(self, a: str | None, b: str | None, a_groups: Iterable[str] | None = None) -> bool:
        if not a or not b:
            return False
        return bool(set(self.teams_of(a, a_groups)) & set(self.teams_of(b)))

    def may_review(self, user: str, playbook: str | None, groups: Iterable[str] | None = None) -> bool:
        """May this reviewer decide approvals for a session running `playbook` (None = planner-built)?"""
        if not self.configured:
            return True
        g = self._groups(user, groups)
        return any(t.covers(playbook) and self._reviewer_limits(t, user, g) is not None for t in self.teams.values())

    def rights(self, user: str, playbook: str | None, action_class: str, amount: Any = None, groups: Iterable[str] | None = None) -> ReviewRights:
        """Playbook rule first (decide at all), then the reviewer's limits (approve)."""
        if not self.configured:
            return ReviewRights(True, True)
        g = self._groups(user, groups)
        reasons = []
        for t in self.teams.values():
            if not t.covers(playbook):
                continue
            lim = self._reviewer_limits(t, user, g)
            if lim is None:
                continue
            why = lim.refusal(action_class, amount)
            if not why:
                return ReviewRights(True, True)
            reasons.append(why)
        if reasons:
            return ReviewRights(True, False, "; ".join(dict.fromkeys(reasons)))
        return ReviewRights(False, False, "your team does not review this playbook")

    # ------------------------------------------------------------------ config checks
    def unknown_users(self, known: Iterable[str]) -> list[str]:
        """Team members/reviewers that are not in the local user store (warnings, never fatal)."""
        have = set(known)
        out = []
        for t in self.teams.values():
            for who, what in [(m, "member") for m in sorted(t.members)] + [(r, "reviewer") for r in sorted(t.reviewers)]:
                if who not in have:
                    out.append(f"team {t.name}: {what} {who} is not in the local user store")
        return out

    def describe(self) -> list[str]:
        lines = []
        for t in self.teams.values():
            lines.append(f"team {t.name}")
            lines.append(f"  playbooks: {', '.join(sorted(t.playbooks)) or '(none: decides nothing)'}")
            lines.append(f"  members: {', '.join(sorted(t.members)) or '-'}")
            for r, lim in sorted(t.reviewers.items()):
                lines.append(f"  reviewer {r}: {lim.describe()}")
            if t.sso_groups:
                lines.append(f"  member SSO groups: {', '.join(sorted(t.sso_groups))}")
            if t.sso_reviewer_groups:
                lines.append(f"  reviewer SSO groups: {', '.join(sorted(t.sso_reviewer_groups))} ({t.group_limits.describe()})")
        return lines


class SsoGroupDirectory:
    """Last-seen SSO groups per user (workspace/portal_sso_groups.json).

    Written by the portal when someone signs in with OIDC, or when the trusted proxy sends
    a changed groups header. Used to find the teams of *other* users (a session owner),
    whose own sign-in is not part of the current request. Only groups the team config
    refers to are kept.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("users"), dict):
                self._data = {str(k): v for k, v in raw["users"].items() if isinstance(v, dict)}
        except (OSError, ValueError):
            pass

    def get(self, user: str) -> list[str]:
        with self._lock:
            return list((self._data.get(user) or {}).get("groups") or [])

    def record(self, user: str, groups: Iterable[str], source: str) -> bool:
        gs = sorted({str(g) for g in groups})[:MAX_GROUPS]
        with self._lock:
            if (self._data.get(user) or {}).get("groups") == gs:
                return False
            self._data[user] = {"groups": gs, "source": source, "at": time.time()}
            from .state import atomic_write_json

            try:
                atomic_write_json(self.path, {"users": self._data})
            except OSError:
                pass  # the in-memory copy still applies for this portal process
        return True
