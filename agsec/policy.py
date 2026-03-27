from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

import yaml

from .exceptions import PolicyViolationError
from .types import PolicyResult, PolicyStatus

PolicyRule = Callable[[str, Dict[str, Any], Optional[Dict[str, Any]]], Optional[PolicyResult]]


def _evaluate_condition(value: Any, condition: Any) -> bool:
    if isinstance(condition, dict):
        op = condition.get("op")
        expected = condition.get("value")

        if op is None or expected is None:
            raise ValueError("Condition must have 'op' and 'value'")

        if op == "==":
            return value == expected
        if op == "!=":
            return value != expected
        if op == ">":
            return value > expected
        if op == "<":
            return value < expected
        if op == ">=":
            return value >= expected
        if op == "<=":
            return value <= expected
        if op == "in":
            return value in expected
        if op == "not_in":
            return value not in expected
        raise ValueError(f"Unsupported condition operator: {op}")

    # Scalar condition is treated as equals.
    return value == condition


def _resolve_condition_value(key: str, params: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Any:
    if key.startswith("params."):
        return params.get(key.split(".", 1)[1])
    if key.startswith("context."):
        if context is None:
            return None
        return context.get(key.split(".", 1)[1])

    if key in params:
        return params[key]
    if context and key in context:
        return context[key]
    return None


def _build_rule_from_definition(definition: Dict[str, Any]) -> PolicyRule:
    action_name = definition.get("action")
    status = definition.get("status")
    reason = definition.get("reason", "")
    conditions = definition.get("conditions", {})
    match_type = definition.get("match", "all")
    priority = int(definition.get("priority", 0))

    if action_name is None or status is None:
        raise ValueError("Each policy rule must include 'action' and 'status'")

    status_enum = PolicyStatus(status)

    def rule(action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[PolicyResult]:
        if action_name != "*" and action != action_name:
            return None

        if conditions:
            hits = []
            for key, cond in conditions.items():
                value = _resolve_condition_value(key, params, context)
                if value is None:
                    hits.append(False)
                    continue

                result = _evaluate_condition(value, cond)
                hits.append(bool(result))

            if match_type == "all" and not all(hits):
                return None
            if match_type == "any" and not any(hits):
                return None

        return PolicyResult(status=status_enum, reason=reason)

    setattr(rule, "priority", priority)
    return rule


class PolicyEngine:
    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self.rules = rules or []
        self._sort_rules()

    def add_rule(self, rule: PolicyRule) -> None:
        if not hasattr(rule, "priority"):
            setattr(rule, "priority", 0)
        self.rules.append(rule)
        self._sort_rules()

    def _sort_rules(self) -> None:
        self.rules.sort(key=lambda r: getattr(r, "priority", 0), reverse=True)

    def load_rules_from_yaml(self, yaml_text: str) -> None:
        parsed = yaml.safe_load(yaml_text)
        if not isinstance(parsed, dict):
            raise ValueError("YAML policy must contain a top-level mapping with 'rules'")

        rules = parsed.get("rules")
        if not isinstance(rules, list):
            raise ValueError("'rules' must be a list")

        for rule_def in rules:
            if not isinstance(rule_def, dict):
                raise ValueError("Each rule must be a mapping")
            self.add_rule(_build_rule_from_definition(rule_def))

    def load_rules_from_yaml_file(self, path: str) -> None:
        if not os.path.exists(path):
            raise FileNotFoundError(f"YAML policy file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        self.load_rules_from_yaml(text)

    def evaluate(self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> PolicyResult:
        context = context or {}

        for rule in self.rules:
            decision = rule(action, params, context)
            if decision is not None:
                if not isinstance(decision, PolicyResult):
                    raise PolicyViolationError(f"Policy rule returned invalid type: {type(decision)}")
                return decision

        return PolicyResult(status=PolicyStatus.ALLOW, reason="default allow")
