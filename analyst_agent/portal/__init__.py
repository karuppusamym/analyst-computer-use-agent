"""Web portal: task chat, sessions, live view, approval inbox and playbook review.

Standard library only (http.server). Start it with:

    python -m analyst_agent portal [--host 127.0.0.1] [--port 8765]
"""

from .approvals import ApprovalInbox, QuestionBox, WebApprover
from .auth import Authenticator, AuthError, Identity, UserStore
from .server import PortalApp, make_server

__all__ = ["ApprovalInbox", "AuthError", "Authenticator", "Identity", "PortalApp", "QuestionBox", "UserStore", "WebApprover", "make_server"]
