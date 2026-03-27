"""Fluent condition builder for inline policies.

Usage:
    from agsec.integrations.conditions import param

    param("amount") > 10000
    param("query").contains("DROP")
    param("url").regex(r"^https://")
    param("email").ends_with("@company.com")
    param("token").exists()
"""

from __future__ import annotations

from typing import Any, Dict


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
