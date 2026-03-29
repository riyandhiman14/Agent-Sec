from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .resolvers import _resolve_value


def _evaluate_condition(value: Any, condition: Any) -> bool:
    """Evaluate a single condition against a resolved value."""
    if isinstance(condition, dict):
        op = condition.get("op")

        # Existence operators — don't need a value
        if op == "exists":
            return value is not None
        if op == "not_exists":
            return value is None

        expected = condition.get("value")

        if op is None:
            raise ValueError("Condition must have 'op'")

        # All other operators require a non-None value
        if value is None:
            return False

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
        if op == "contains":
            if isinstance(value, (list, tuple, set)):
                return expected in value
            return str(expected) in str(value)
        if op == "starts_with":
            return str(value).startswith(str(expected))
        if op == "ends_with":
            return str(value).endswith(str(expected))
        if op == "regex":
            pattern = str(expected)
            if len(pattern) > 500:
                return False  # Reject overly long patterns
            try:
                return bool(re.search(pattern, str(value)))
            except re.error:
                return False  # Invalid regex fails safely

        raise ValueError(f"Unsupported condition operator: {op}")

    # Scalar condition is treated as equals
    return value == condition


def _conditions_match(
    conditions: Dict[str, Any],
    params: Dict[str, Any],
    context: Optional[Dict[str, Any]],
    match_type: str = "all",
) -> bool:
    """Evaluate all conditions in a statement. Returns True if match_type logic is satisfied."""
    if not conditions:
        return True

    results = []
    for key, cond in conditions.items():
        value = _resolve_value(key, params, context)
        results.append(_evaluate_condition(value, cond))

    if match_type == "any":
        return any(results)
    return all(results)


def _action_matches(action: str, patterns: List[str]) -> bool:
    """Check if an action name matches any of the glob patterns."""
    from fnmatch import fnmatch

    for pattern in patterns:
        if pattern == "*":
            return True
        if fnmatch(action, pattern):
            return True
    return False
