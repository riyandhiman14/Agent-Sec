"""Fluent condition builder and rule helpers for inline policies.

Usage:
    from agsec.integrations.conditions import param, allow, deny, review

    param("amount") > 10000
    param("query").contains("DROP")
    deny("payment").when(param("amount") > 10000)
    allow("search", "calculator")
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..policy.statement import Statement
from ..types import PolicyStatus


class Condition:
    """A compiled condition ready for PolicyEngine."""

    def __init__(self, key: str, op: str, value: Any = None):
        self.key = key
        self.op = op
        self.value = value

    def to_dict(self) -> Dict[str, Any]:
        """Convert to the format PolicyEngine understands."""
        if self.op in ("exists", "not_exists"):
            return {self.key: {"op": self.op}}
        return {self.key: {"op": self.op, "value": self.value}}

    def __repr__(self) -> str:
        if self.value is None:
            return f"Condition({self.key} {self.op})"
        return f"Condition({self.key} {self.op} {self.value!r})"


class param:
    """Fluent builder for policy conditions.

    Supports Python operators and named methods for all agsec condition types.

    Examples:
        param("amount") > 10000              # greater than
        param("query").contains("DROP")       # substring match
        param("url").regex(r"evil\\.com")     # regex match
        param("role").is_in(["admin", "dev"]) # membership
        param("token").exists()               # field present
    """

    def __init__(self, key: str):
        # Auto-prefix with params. if not already namespaced
        if key.startswith(("params.", "context.")):
            self.key = key
        else:
            self.key = f"params.{key}"

    # Python operators
    def __gt__(self, value: Any) -> Condition:
        return Condition(self.key, ">", value)

    def __lt__(self, value: Any) -> Condition:
        return Condition(self.key, "<", value)

    def __ge__(self, value: Any) -> Condition:
        return Condition(self.key, ">=", value)

    def __le__(self, value: Any) -> Condition:
        return Condition(self.key, "<=", value)

    def __eq__(self, value: Any) -> Condition:
        return Condition(self.key, "==", value)

    def __ne__(self, value: Any) -> Condition:
        return Condition(self.key, "!=", value)

    # Named methods
    def contains(self, value: Any) -> Condition:
        return Condition(self.key, "contains", value)

    def starts_with(self, value: str) -> Condition:
        return Condition(self.key, "starts_with", value)

    def ends_with(self, value: str) -> Condition:
        return Condition(self.key, "ends_with", value)

    def regex(self, pattern: str) -> Condition:
        return Condition(self.key, "regex", pattern)

    def is_in(self, values: list) -> Condition:
        return Condition(self.key, "in", values)

    def not_in(self, values: list) -> Condition:
        return Condition(self.key, "not_in", values)

    def exists(self) -> Condition:
        return Condition(self.key, "exists")

    def not_exists(self) -> Condition:
        return Condition(self.key, "not_exists")


# ---------------------------------------------------------------------------
# Rule helpers — allow(), deny(), review()
# ---------------------------------------------------------------------------

_EFFECT_TO_STATUS = {
    "allow": PolicyStatus.ALLOW,
    "deny": PolicyStatus.BLOCK,
    "review": PolicyStatus.REVIEW,
}


class ToolRule:
    """One or more tools/names with an effect and optional conditions."""

    def __init__(self, *names: Any, effect: str):
        self.names: tuple = names
        self.effect: str = effect
        self.conditions: list = []

    def when(self, *conditions: Condition) -> "ToolRule":
        """Add conditions to this rule. Returns self for chaining."""
        for c in conditions:
            if not isinstance(c, Condition):
                raise TypeError(
                    f"when() expects Condition objects (from param()), got {type(c).__name__}"
                )
        self.conditions.extend(conditions)
        return self


def allow(*names: Any) -> ToolRule:
    """Mark tools/actions as allowed."""
    return ToolRule(*names, effect="allow")


def deny(*names: Any) -> ToolRule:
    """Mark tools/actions as denied (blocked)."""
    return ToolRule(*names, effect="deny")


def review(*names: Any) -> ToolRule:
    """Mark tools/actions as requiring human review."""
    return ToolRule(*names, effect="review")


def _get_tool_name(item: Any) -> str:
    """Extract a name string from a tool object or string."""
    if isinstance(item, str):
        return item
    # LangChain BaseTool or anything with a .name attribute
    if hasattr(item, "name"):
        return item.name
    return str(item)


def compile_rules(rules: List[ToolRule], action_prefix: str = "tool") -> List[Statement]:
    """Convert ToolRules into PolicyEngine Statement objects."""
    statements = []
    for rule in rules:
        effect = _EFFECT_TO_STATUS[rule.effect]
        tool_names = [f"{action_prefix}.{_get_tool_name(t)}" for t in rule.names]

        conditions = {}
        for cond in rule.conditions:
            conditions.update(cond.to_dict())

        sid_parts = [rule.effect.title()]
        if len(rule.names) == 1:
            sid_parts.append(_get_tool_name(rule.names[0]).title())
        else:
            sid_parts.append(f"{len(rule.names)}Tools")

        statements.append(Statement(
            sid="_".join(sid_parts),
            effect=effect,
            actions=tool_names,
            conditions=conditions,
            reason=f"{rule.effect} by inline policy",
        ))

    return statements
