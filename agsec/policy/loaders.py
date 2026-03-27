from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from ..types import PolicyResult, PolicyStatus
from .conditions import _evaluate_condition
from .resolvers import _resolve_value
from .statement import Statement

# Effect aliases — IAM uses "deny", internal enum uses BLOCK
_EFFECT_MAP = {
    "allow": PolicyStatus.ALLOW,
    "deny": PolicyStatus.BLOCK,
    "block": PolicyStatus.BLOCK,
    "review": PolicyStatus.REVIEW,
}

PolicyRule = Callable[[str, Dict[str, Any], Optional[Dict[str, Any]]], Optional[PolicyResult]]


def _build_statement(definition: Dict[str, Any]) -> Statement:
    """Parse a YAML statement dict into a Statement object."""
    effect_str = str(definition.get("effect", "")).lower()
    effect = _EFFECT_MAP.get(effect_str)
    if effect is None:
        raise ValueError(
            f"Invalid effect '{effect_str}'. Must be one of: allow, deny, review"
        )

    actions = definition.get("actions", ["*"])
    if isinstance(actions, str):
        actions = [actions]

    return Statement(
        sid=definition.get("sid", ""),
        effect=effect,
        actions=actions,
        conditions=definition.get("conditions", {}),
        reason=definition.get("reason", ""),
        match=definition.get("match", "all"),
    )


def _build_rule_from_definition(definition: Dict[str, Any]) -> PolicyRule:
    """Build a callable rule from old-format YAML definition."""
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
                value = _resolve_value(key, params, context)
                if value is None and not (isinstance(cond, dict) and cond.get("op") in ("exists", "not_exists")):
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
