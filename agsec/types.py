from __future__ import annotations

from dataclasses import dataclass, field
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
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionExecutionResult:
    action: str
    params: Dict[str, Any]
    result: Any
    policy: PolicyResult
