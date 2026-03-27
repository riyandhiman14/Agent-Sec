from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class PolicyStatus(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"


@dataclass
class PolicyResult:
    status: PolicyStatus
    reason: str = ""
    metadata: Dict[str, Any] = None


@dataclass
class ActionExecutionResult:
    action: str
    params: Dict[str, Any]
    result: Any
    policy: PolicyResult
