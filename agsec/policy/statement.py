from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..types import PolicyStatus


@dataclass
class Statement:
    sid: str = ""
    effect: PolicyStatus = PolicyStatus.ALLOW
    actions: List[str] = field(default_factory=lambda: ["*"])
    conditions: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    match: str = "all"  # "all" or "any" for condition evaluation
