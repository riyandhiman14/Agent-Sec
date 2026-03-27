from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .exceptions import PolicyViolationError
from .types import PolicyResult, PolicyStatus

PolicyRule = Callable[[str, Dict[str, Any], Optional[Dict[str, Any]]], Optional[PolicyResult]]


class PolicyEngine:
    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self.rules = rules or []

    def add_rule(self, rule: PolicyRule) -> None:
        self.rules.append(rule)

    def evaluate(self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> PolicyResult:
        context = context or {}

        for rule in self.rules:
            decision = rule(action, params, context)
            if decision is not None:
                if not isinstance(decision, PolicyResult):
                    raise PolicyViolationError(f"Policy rule returned invalid type: {type(decision)}")
                return decision

        return PolicyResult(status=PolicyStatus.ALLOW, reason="default allow")
