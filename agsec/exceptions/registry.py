from __future__ import annotations

from typing import Any, Dict, Optional

from .base import AgsecError


class RegistryError(AgsecError):
    """Base class for action registry errors."""
    pass


class ActionNotFoundError(RegistryError):
    def __init__(self, action: str, available_actions: Optional[list[str]] = None):
        super().__init__(
            f"Action '{action}' not registered",
            code="ACTION_NOT_FOUND",
            details={"action": action, "available_actions": available_actions}
        )


class DuplicateActionError(RegistryError):
    def __init__(self, action: str):
        super().__init__(
            f"Action '{action}' is already registered",
            code="DUPLICATE_ACTION",
            details={"action": action}
        )


class InvalidActionError(RegistryError):
    def __init__(self, action: str, reason: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Invalid action '{action}': {reason}",
            code="INVALID_ACTION",
            details={"action": action, "reason": reason, **(details or {})}
        )


class RegistryFullError(RegistryError):
    def __init__(self, max_actions: int, current_count: int):
        super().__init__(
            f"Registry capacity exceeded: {current_count}/{max_actions} actions",
            code="REGISTRY_FULL",
            details={"max_actions": max_actions, "current_count": current_count}
        )
