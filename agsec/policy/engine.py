from __future__ import annotations

import glob
import os
from typing import Any, Dict, List, Optional

import yaml

from ..exceptions import PolicyViolationError
from ..types import PolicyResult, PolicyStatus
from .conditions import _action_matches, _conditions_match
from .loaders import PolicyRule, _EFFECT_MAP, _build_rule_from_definition, _build_statement
from .statement import Statement


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
        self._default_explicit = default
        self._default = _EFFECT_MAP.get(default, PolicyStatus.BLOCK)

        # Policy version from YAML
        self._version: Optional[str] = None

        # Track whether IAM format was loaded
        self._iam_loaded: bool = False

        # Track whether default was explicitly set by YAML
        self._default_set_by_yaml: bool = False

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

    def load_from_file(self, path: str) -> None:
        """Load a single policy YAML file. Merges into existing statements."""
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Policy file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            text = f.read()

        parsed = yaml.safe_load(text)
        if not isinstance(parsed, dict):
            raise ValueError(f"Policy file '{path}' must contain a YAML mapping")

        policy_name = os.path.splitext(os.path.basename(path))[0]

        if "statements" in parsed:
            self._load_iam_format(parsed)
            # Tag loaded statements with source file
            for stmt in self._statements:
                if not stmt.sid:
                    stmt.sid = policy_name
                stmt.source = path
        elif "rules" in parsed:
            self._load_legacy_format(parsed)
        else:
            raise ValueError(f"Policy file '{path}' must contain 'statements' or 'rules'")

    def load_from_directory(self, directory: str) -> List[str]:
        """Load all .yaml/.yml policy files from a directory. Returns list of loaded files.

        Files are loaded in alphabetical order. Each file's statements are merged
        into the engine. The first file's 'default' setting wins.
        """
        directory = os.path.abspath(directory)
        if not os.path.isdir(directory):
            raise FileNotFoundError(f"Policy directory not found: {directory}")

        files = sorted(
            glob.glob(os.path.join(directory, "*.yaml"))
            + glob.glob(os.path.join(directory, "*.yml"))
        )

        if not files:
            raise ValueError(f"No .yaml or .yml files found in: {directory}")

        loaded = []
        for path in files:
            self.load_from_file(path)
            loaded.append(path)

        return loaded

    def _load_iam_format(self, parsed: Dict[str, Any]) -> None:
        """Parse IAM-style policy with statements."""
        self._version = parsed.get("version", "1.0")
        self._iam_loaded = True

        # Set default from YAML if present
        default_str = parsed.get("default", "deny")
        self._default = _EFFECT_MAP.get(default_str, PolicyStatus.BLOCK)
        self._default_set_by_yaml = True

        statements = parsed.get("statements", [])
        if not isinstance(statements, list):
            raise ValueError("'statements' must be a list")

        for stmt_def in statements:
            if not isinstance(stmt_def, dict):
                raise ValueError("Each statement must be a mapping")
            self._statements.append(_build_statement(stmt_def))

    def _load_legacy_format(self, parsed: Dict[str, Any]) -> None:
        """Parse legacy rules: format."""
        # Legacy format defaults to ALLOW for backward compat,
        # but only if no IAM format has already set the default
        if not self._default_set_by_yaml and not self._iam_loaded:
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

    def validate_file(self, path: str) -> List[str]:
        """Validate a single policy YAML file. Returns list of issues."""
        if not os.path.isfile(path):
            return [f"File not found: {path}"]

        with open(path, "r", encoding="utf-8") as f:
            text = f.read()

        issues = self.validate(text)
        return [f"{os.path.basename(path)}: {i}" for i in issues]

    def validate_directory(self, directory: str) -> Dict[str, List[str]]:
        """Validate all policy files in a directory. Returns {filename: [issues]}."""
        directory = os.path.abspath(directory)
        if not os.path.isdir(directory):
            return {"_error": [f"Directory not found: {directory}"]}

        files = sorted(
            glob.glob(os.path.join(directory, "*.yaml"))
            + glob.glob(os.path.join(directory, "*.yml"))
        )

        results: Dict[str, List[str]] = {}
        for path in files:
            name = os.path.basename(path)
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
            issues = self.validate(text)
            if issues:
                results[name] = issues

        return results

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

        version = parsed.get("version")
        if version is not None and str(version) not in ("1.0", "1"):
            issues.append(f"Unsupported version: '{version}'. Expected '1.0'")

        default = parsed.get("default")
        if default is not None and default not in ("allow", "deny", "review"):
            issues.append(f"Invalid default: '{default}'. Must be allow, deny, or review")

        if "statements" in parsed:
            issues.extend(self._validate_statements(parsed["statements"]))

        if "rules" in parsed:
            issues.extend(self._validate_legacy_rules(parsed["rules"]))

        return issues

    def _validate_statements(self, statements: Any) -> List[str]:
        issues: List[str] = []
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

            effect = stmt.get("effect")
            if not effect:
                issues.append(f"{label}: missing 'effect'")
            elif str(effect).lower() not in ("allow", "deny", "block", "review"):
                issues.append(f"{label}: invalid effect '{effect}'")

            actions = stmt.get("actions")
            if actions is not None:
                if isinstance(actions, str):
                    actions = [actions]
                if not isinstance(actions, list) or not actions:
                    issues.append(f"{label}: 'actions' must be a non-empty list")

            sid = stmt.get("sid", "")
            if sid:
                if sid in sids:
                    issues.append(f"Duplicate sid: '{sid}'")
                sids.add(sid)

            conditions = stmt.get("conditions", {})
            if isinstance(conditions, dict):
                for key, cond in conditions.items():
                    if isinstance(cond, dict):
                        op = cond.get("op")
                        if op and op not in valid_ops:
                            issues.append(f"{label}: unsupported operator '{op}' in condition '{key}'")

            match = stmt.get("match")
            if match is not None and match not in ("all", "any"):
                issues.append(f"{label}: 'match' must be 'all' or 'any'")

        return issues

    def _validate_legacy_rules(self, rules: Any) -> List[str]:
        issues: List[str] = []
        if not isinstance(rules, list):
            issues.append("'rules' must be a list")
            return issues

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
