"""Shared policy checker for all integrations."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from ..audit import AuditStore
from ..exceptions import PolicyViolationError
from ..policy import PolicyEngine
from ..types import ActionExecutionResult, PolicyResult, PolicyStatus


def _get_agent_policy_dir(agent: str) -> Optional[str]:
    """Return ~/.agsec/agents/{agent}/ if it exists."""
    path = os.path.join(os.path.expanduser("~"), ".agsec", "agents", agent)
    if os.path.isdir(path):
        return path
    return None


def _find_project_policy_dir(start_dir: Optional[str] = None) -> Optional[str]:
    """Find project-level policies/ directory by walking up."""
    env_dir = os.environ.get("AGSEC_POLICY_DIR")
    if env_dir and os.path.isdir(env_dir):
        return os.path.abspath(env_dir)

    start = os.path.abspath(start_dir or os.getcwd())
    current = start
    for _ in range(20):
        for candidate in ("policies", os.path.join(".agsec", "policies")):
            path = os.path.join(current, candidate)
            if os.path.isdir(path):
                return path
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


class PolicyChecker:
    """Reusable policy checker for all integrations.

    Loads project-level policies + optional agent-level overlay.
    Deny from either layer wins (IAM semantics).
    """

    def __init__(
        self,
        policy_dir: Optional[str] = None,
        agent: Optional[str] = None,
        audit: bool = True,
    ):
        self.engine = PolicyEngine()
        self._audit_store = None
        self._loaded = False
        self._policy_dir = policy_dir
        self._agent = agent
        self._audit_enabled = audit

    def _ensure_loaded(self) -> None:
        """Lazy-load policies on first check."""
        if self._loaded:
            return

        # 1. Project-level policies
        project_dir = self._policy_dir or _find_project_policy_dir()
        if project_dir:
            try:
                self.engine.load_from_directory(project_dir)
            except (ValueError, FileNotFoundError):
                pass

        # 2. Agent-level overlay
        if self._agent:
            agent_dir = _get_agent_policy_dir(self._agent)
            if agent_dir:
                try:
                    self.engine.load_from_directory(agent_dir)
                except (ValueError, FileNotFoundError):
                    pass

        # 3. Audit store
        if self._audit_enabled:
            try:
                agsec_dir = os.path.join(os.path.expanduser("~"), ".agsec")
                os.makedirs(agsec_dir, exist_ok=True)
                db_path = os.environ.get(
                    "AGSEC_AUDIT_DB", os.path.join(agsec_dir, "audit.db")
                )
                self._audit_store = AuditStore(db_path)
            except Exception:
                pass

        self._loaded = True

    def check(
        self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> PolicyResult:
        """Check policy. Returns PolicyResult."""
        self._ensure_loaded()
        result = self.engine.evaluate(action, params, context)
        self._log(action, params, result, context)
        return result

    async def acheck(
        self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> PolicyResult:
        """Async check. Same logic, non-blocking compatible."""
        return self.check(action, params, context)

    def check_or_raise(
        self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> PolicyResult:
        """Check policy. Raises PolicyViolationError if blocked."""
        result = self.check(action, params, context)
        if result.status == PolicyStatus.BLOCK:
            raise PolicyViolationError(
                result.reason, action, result.status.value,
                policy_id=result.metadata.get("sid"),
            )
        if result.status == PolicyStatus.REVIEW:
            raise PolicyViolationError(
                f"[REVIEW REQUIRED] {result.reason}", action, result.status.value,
                policy_id=result.metadata.get("sid"),
            )
        return result

    async def acheck_or_raise(
        self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> PolicyResult:
        """Async version of check_or_raise."""
        return self.check_or_raise(action, params, context)

    def _log(
        self, action: str, params: Dict[str, Any], result: PolicyResult,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log to audit store (swallow errors)."""
        if not self._audit_store:
            return
        try:
            exec_result = ActionExecutionResult(
                action=action, params=params, result=None, policy=result,
            )
            self._audit_store.log_execution(exec_result, context)
        except Exception:
            pass
