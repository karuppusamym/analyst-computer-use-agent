"""Analyst Computer-Use Agent - Phase 1 prototype harness.

Implements the design in "Analyst Computer-Use Agent - Product Design":
planner / executor / verifier roles, a tool-tier router (connectors > code >
browser DOM > desktop UI Automation > desktop pixels), playbooks, approval
gates, an append-only audit store and checkpoints.

The core runs on the Python standard library only. Optional packages
(anthropic, pyyaml, playwright, pywinauto, pandas, Pillow) are used when
present and their tiers report "unavailable" when absent.
"""

__version__ = "0.1.0"
