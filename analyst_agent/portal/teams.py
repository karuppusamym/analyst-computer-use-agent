"""Teams for session visibility and approval rights (config `portal.teams`).

    "teams": {"finance": {"members": ["alice", "bob"], "reviewers": ["rita"], "playbooks": ["erp-crm-reconciliation"]}}

- Members and reviewers of a team are all "in" the team: each sees the others' sessions.
- A reviewer may decide an approval only if the session's playbook is in the playbooks list
  of a team where they are listed under `reviewers` (fnmatch patterns; "*" = any playbook, including sessions
  with no playbook). With no teams configured, every reviewer may decide (the old rule).
- Admins are not limited by teams.
"""

from __future__ import annotations

import fnmatch
from typing import Any


def _names(v: Any) -> set[str]:
    return {str(x) for x in v} if isinstance(v, (list, tuple, set)) else set()


class Teams:
    def __init__(self, cfg: Any):
        self.teams: dict[str, dict[str, set[str]]] = {}
        for name, t in (cfg or {}).items() if isinstance(cfg, dict) else []:
            if isinstance(t, dict):
                self.teams[str(name)] = {"members": _names(t.get("members")), "reviewers": _names(t.get("reviewers")), "playbooks": _names(t.get("playbooks"))}

    @property
    def configured(self) -> bool:
        return bool(self.teams)

    def teams_of(self, user: str) -> list[str]:
        return [n for n, t in self.teams.items() if user in t["members"] or user in t["reviewers"]]

    def share_team(self, a: str | None, b: str | None) -> bool:
        if not a or not b:
            return False
        return bool(set(self.teams_of(a)) & set(self.teams_of(b)))

    def may_review(self, user: str, playbook: str | None) -> bool:
        """May this reviewer decide approvals for a session running `playbook` (None = planner-built)?"""
        if not self.configured:
            return True
        for t in self.teams.values():
            if user in t["reviewers"] and ("*" in t["playbooks"] or (playbook is not None and any(fnmatch.fnmatchcase(playbook, pat) for pat in t["playbooks"]))):
                return True
        return False
