from __future__ import annotations

from typing import Any, Dict, Optional

from .base import AgsecError


class PolicyError(AgsecError):
    """Base class for policy-related errors."""
    pass


class PolicyParseError(PolicyError):
    def __init__(self, policy_path: str, parse_error: str, line: Optional[int] = None, column: Optional[int] = None):
        super().__init__(
            f"Failed to parse policy {policy_path}: {parse_error}",
            code="POLICY_PARSE_ERROR",
            details={"policy_path": policy_path, "parse_error": parse_error, "line": line, "column": column}
        )


class InvalidPolicyError(PolicyError):
    def __init__(self, policy_id: str, reason: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Invalid policy '{policy_id}': {reason}",
            code="INVALID_POLICY",
            details={"policy_id": policy_id, "reason": reason, **(details or {})}
        )


class PolicyConflictError(PolicyError):
    def __init__(self, action: str, conflicting_policies: list[str], reason: str):
        super().__init__(
            f"Policy conflict for action '{action}': {reason}",
            code="POLICY_CONFLICT",
            details={"action": action, "conflicting_policies": conflicting_policies, "reason": reason}
        )


class PolicyTimeoutError(PolicyError):
    def __init__(self, action: str, timeout_seconds: float):
        super().__init__(
            f"Policy evaluation timed out for action '{action}' after {timeout_seconds}s",
            code="POLICY_TIMEOUT",
            details={"action": action, "timeout_seconds": timeout_seconds}
        )


class PolicyViolationError(PolicyError):
    def __init__(self, reason: str, action: str, policy_status: str, policy_id: Optional[str] = None, rule_id: Optional[str] = None):
        super().__init__(
            f"Policy violation: {reason}",
            code="POLICY_VIOLATION",
            details={"action": action, "policy_status": policy_status, "reason": reason, "policy_id": policy_id, "rule_id": rule_id}
        )


class ActionExecutionError(AgsecError):
    """Raised when action execution fails."""
    def __init__(self, action: str, original_error: Exception, params: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Action '{action}' execution failed: {str(original_error)}",
            code="ACTION_EXECUTION_ERROR",
            details={"action": action, "original_error": str(original_error), "error_type": type(original_error).__name__, "params": params}
        )
        self.original_error = original_error
