from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any, Callable, Dict, List, Optional

import yaml

from .exceptions import PolicyViolationError
from .types import PolicyResult, PolicyStatus

PolicyRule = Callable[[str, Dict[str, Any], Optional[Dict[str, Any]]], Optional[PolicyResult]]

# Effect aliases — IAM uses "deny", internal enum uses BLOCK
_EFFECT_MAP = {
    "allow": PolicyStatus.ALLOW,
    "deny": PolicyStatus.BLOCK,
    "block": PolicyStatus.BLOCK,
    "review": PolicyStatus.REVIEW,
}


# ---------------------------------------------------------------------------
# Statement dataclass (IAM-style policy unit)
# ---------------------------------------------------------------------------

@dataclass
class Statement:
    sid: str = ""
    effect: PolicyStatus = PolicyStatus.ALLOW
    actions: List[str] = field(default_factory=lambda: ["*"])
    conditions: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    match: str = "all"  # "all" or "any" for condition evaluation


# ---------------------------------------------------------------------------
# Value resolution — deep nested access
# ---------------------------------------------------------------------------

def _deep_get(obj: Any, keys: List[str]) -> Any:
    """Walk a nested dict by key path. Returns None if any segment is missing."""
    for key in keys:
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return None
    return obj


def _resolve_value(key: str, params: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Any:
    """Resolve a dotted key like 'params.user.address.country' from params or context."""
    parts = key.split(".")

    if parts[0] == "params":
        return _deep_get(params, parts[1:])
    if parts[0] == "context":
        return _deep_get(context or {}, parts[1:])

    # Legacy: bare key — try params first, then context
    result = _deep_get(params, parts)
    if result is not None:
        return result
    if context:
        return _deep_get(context, parts)
    return None


# ---------------------------------------------------------------------------
# Condition evaluation — expanded operators
# ---------------------------------------------------------------------------

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
            return bool(re.search(str(expected), str(value)))

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


# ---------------------------------------------------------------------------
# Action glob matching
# ---------------------------------------------------------------------------

def _action_matches(action: str, patterns: List[str]) -> bool:
    """Check if an action name matches any of the glob patterns."""
    for pattern in patterns:
        if pattern == "*":
            return True
        if fnmatch(action, pattern):
            return True
    return False


# ---------------------------------------------------------------------------
# Statement builder (from YAML)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Legacy rule builder (backward compat with old rules: format)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

class PolicyEngine:
    def __init__(
        self,
        rules: Optional[List[PolicyRule]] = None,
        default: str = "deny",
    ):
        # Legacy rules (callable, priority-sorted)
        self._legacy_rules: List[PolicyRule] = rules or []
        self._sort_rules()

        # IAM-style statements
        self._statements: List[Statement] = []

        # Default: deny for IAM mode, allow for bare/legacy mode
        # When no statements are loaded, default stays ALLOW for backward compat
        self._default_explicit = default
        self._default = _EFFECT_MAP.get(default, PolicyStatus.BLOCK)

        # Policy version from YAML
        self._version: Optional[str] = None

        # Track whether IAM format was loaded
        self._iam_loaded: bool = False

    # -- Legacy compat properties --

    @property
    def rules(self) -> List[PolicyRule]:
        return self._legacy_rules

    @rules.setter
    def rules(self, value: List[PolicyRule]) -> None:
        self._legacy_rules = value
        self._sort_rules()

    @property
    def statements(self) -> List[Statement]:
        return list(self._statements)

    @property
    def default(self) -> PolicyStatus:
        return self._default

    # -- Rule management (legacy) --

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a legacy callable rule."""
        if not hasattr(rule, "priority"):
            setattr(rule, "priority", 0)
        self._legacy_rules.append(rule)
        self._sort_rules()

    def _sort_rules(self) -> None:
        self._legacy_rules.sort(key=lambda r: getattr(r, "priority", 0), reverse=True)

    # -- Statement management (IAM) --

    def add_statement(self, statement: Statement) -> None:
        """Add an IAM-style statement."""
        self._statements.append(statement)

    # -- YAML loading --

    def load_rules_from_yaml(self, yaml_text: str) -> None:
        """Load policy from YAML. Detects format: 'statements' (IAM) or 'rules' (legacy)."""
        parsed = yaml.safe_load(yaml_text)
        if not isinstance(parsed, dict):
            raise ValueError("YAML policy must contain a top-level mapping")

        if "statements" in parsed:
            self._load_iam_format(parsed)
        elif "rules" in parsed:
            self._load_legacy_format(parsed)
        else:
            raise ValueError("YAML policy must contain 'statements' or 'rules'")

    def load_rules_from_yaml_file(self, path: str) -> None:
        """Load policy from a YAML file."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"YAML policy file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        self.load_rules_from_yaml(text)

    def _load_iam_format(self, parsed: Dict[str, Any]) -> None:
        """Parse IAM-style policy with statements."""
        self._version = parsed.get("version", "1.0")
        self._iam_loaded = True

        # Set default from YAML if present
        default_str = parsed.get("default", "deny")
        self._default = _EFFECT_MAP.get(default_str, PolicyStatus.BLOCK)

        statements = parsed.get("statements", [])
        if not isinstance(statements, list):
            raise ValueError("'statements' must be a list")

        for stmt_def in statements:
            if not isinstance(stmt_def, dict):
                raise ValueError("Each statement must be a mapping")
            self._statements.append(_build_statement(stmt_def))

    def _load_legacy_format(self, parsed: Dict[str, Any]) -> None:
        """Parse legacy rules: format."""
        # Legacy format defaults to ALLOW for backward compat
        if not self._statements:
            self._default = PolicyStatus.ALLOW

        rules = parsed.get("rules")
        if not isinstance(rules, list):
            raise ValueError("'rules' must be a list")

        for rule_def in rules:
            if not isinstance(rule_def, dict):
                raise ValueError("Each rule must be a mapping")
            self.add_rule(_build_rule_from_definition(rule_def))

    # -- Evaluation --

    def evaluate(
        self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> PolicyResult:
        """Evaluate policy for an action. Legacy rules first, then IAM statements, then default."""
        context = context or {}

        # 1. Legacy rules — priority-sorted, first match wins
        for rule in self._legacy_rules:
            decision = rule(action, params, context)
            if decision is not None:
                if not isinstance(decision, PolicyResult):
                    raise PolicyViolationError(
                        f"Policy rule returned invalid type: {type(decision)}", action, "error"
                    )
                return decision

        # 2. IAM statement evaluation
        if self._iam_loaded:
            return self._evaluate_iam(action, params, context)

        # 3. Default — ALLOW for bare/legacy engines (backward compat)
        default = PolicyStatus.ALLOW
        return PolicyResult(
            status=default,
            reason=f"default {default.value}",
            metadata={"matched_by": "default"},
        )

    def _evaluate_iam(
        self, action: str, params: Dict[str, Any], context: Dict[str, Any]
    ) -> PolicyResult:
        """IAM evaluation: explicit deny > review > allow > default."""
        matched_deny: List[Statement] = []
        matched_review: List[Statement] = []
        matched_allow: List[Statement] = []

        for stmt in self._statements:
            if not _action_matches(action, stmt.actions):
                continue
            if not _conditions_match(stmt.conditions, params, context, stmt.match):
                continue

            # Statement matches
            if stmt.effect == PolicyStatus.BLOCK:
                matched_deny.append(stmt)
            elif stmt.effect == PolicyStatus.REVIEW:
                matched_review.append(stmt)
            elif stmt.effect == PolicyStatus.ALLOW:
                matched_allow.append(stmt)

        # Explicit deny always wins
        if matched_deny:
            stmt = matched_deny[0]
            return PolicyResult(
                status=PolicyStatus.BLOCK,
                reason=stmt.reason or f"Denied by '{stmt.sid}'" if stmt.sid else "Denied by policy",
                metadata={"sid": stmt.sid, "matched_by": "explicit_deny"},
            )

        # Review trumps allow
        if matched_review:
            stmt = matched_review[0]
            return PolicyResult(
                status=PolicyStatus.REVIEW,
                reason=stmt.reason or f"Review required by '{stmt.sid}'" if stmt.sid else "Review required",
                metadata={"sid": stmt.sid, "matched_by": "explicit_review"},
            )

        # Explicit allow
        if matched_allow:
            stmt = matched_allow[0]
            return PolicyResult(
                status=PolicyStatus.ALLOW,
                reason=stmt.reason or f"Allowed by '{stmt.sid}'" if stmt.sid else "Allowed by policy",
                metadata={"sid": stmt.sid, "matched_by": "explicit_allow"},
            )

        # Default
        return PolicyResult(
            status=self._default,
            reason=f"No matching statement, default: {self._default.value}",
            metadata={"matched_by": "default"},
        )

    # -- Dry-run --

    def dry_run(
        self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> PolicyResult:
        """Evaluate policy without executing. Same as evaluate, clearly named for intent."""
        return self.evaluate(action, params, context)

    # -- Validation --

    def validate(self, yaml_text: str) -> List[str]:
        """Validate a policy YAML without loading it. Returns list of issues (empty = valid)."""
        issues: List[str] = []

        try:
            parsed = yaml.safe_load(yaml_text)
        except yaml.YAMLError as e:
            issues.append(f"Invalid YAML syntax: {e}")
            return issues

        if not isinstance(parsed, dict):
            issues.append("Policy must be a YAML mapping")
            return issues

        if "statements" not in parsed and "rules" not in parsed:
            issues.append("Policy must contain 'statements' or 'rules'")
            return issues

        # Validate version
        version = parsed.get("version")
        if version is not None and str(version) not in ("1.0", "1"):
            issues.append(f"Unsupported version: '{version}'. Expected '1.0'")

        # Validate default
        default = parsed.get("default")
        if default is not None and default not in ("allow", "deny", "review"):
            issues.append(f"Invalid default: '{default}'. Must be allow, deny, or review")

        # Validate statements
        if "statements" in parsed:
            statements = parsed["statements"]
            if not isinstance(statements, list):
                issues.append("'statements' must be a list")
                return issues

            sids = set()
            valid_ops = {"==", "!=", ">", "<", ">=", "<=", "in", "not_in",
                         "contains", "starts_with", "ends_with", "regex",
                         "exists", "not_exists"}

            for i, stmt in enumerate(statements):
                label = stmt.get("sid", f"statement[{i}]") if isinstance(stmt, dict) else f"statement[{i}]"

                if not isinstance(stmt, dict):
                    issues.append(f"{label}: must be a mapping")
                    continue

                # Effect
                effect = stmt.get("effect")
                if not effect:
                    issues.append(f"{label}: missing 'effect'")
                elif str(effect).lower() not in ("allow", "deny", "block", "review"):
                    issues.append(f"{label}: invalid effect '{effect}'")

                # Actions
                actions = stmt.get("actions")
                if actions is not None:
                    if isinstance(actions, str):
                        actions = [actions]
                    if not isinstance(actions, list) or not actions:
                        issues.append(f"{label}: 'actions' must be a non-empty list")

                # Duplicate SID
                sid = stmt.get("sid", "")
                if sid:
                    if sid in sids:
                        issues.append(f"Duplicate sid: '{sid}'")
                    sids.add(sid)

                # Conditions
                conditions = stmt.get("conditions", {})
                if isinstance(conditions, dict):
                    for key, cond in conditions.items():
                        if isinstance(cond, dict):
                            op = cond.get("op")
                            if op and op not in valid_ops:
                                issues.append(f"{label}: unsupported operator '{op}' in condition '{key}'")

                # Match type
                match = stmt.get("match")
                if match is not None and match not in ("all", "any"):
                    issues.append(f"{label}: 'match' must be 'all' or 'any'")

        # Validate legacy rules
        if "rules" in parsed:
            rules = parsed["rules"]
            if not isinstance(rules, list):
                issues.append("'rules' must be a list")
            else:
                for i, rule in enumerate(rules):
                    label = f"rule[{i}]"
                    if not isinstance(rule, dict):
                        issues.append(f"{label}: must be a mapping")
                        continue
                    if "action" not in rule:
                        issues.append(f"{label}: missing 'action'")
                    if "status" not in rule:
                        issues.append(f"{label}: missing 'status'")

        return issues
