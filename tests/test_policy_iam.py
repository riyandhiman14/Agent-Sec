"""Tests for IAM-style policy engine."""

import asyncio
import os

import pytest

from agsec import ControlLayer, PolicyEngine, PolicyResult, PolicyStatus
from agsec.exceptions import PolicyViolationError
from agsec.policy import Statement, _action_matches, _evaluate_condition, _resolve_value


def _write_policy(tmp_path, filename, content):
    """Helper to write a policy YAML file and return its path."""
    path = tmp_path / filename
    path.write_text(content)
    return str(path)


def _make_policy_dir(tmp_path, files):
    """Helper to create a policy directory with multiple files. Returns dir path."""
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    for name, content in files.items():
        (policy_dir / name).write_text(content)
    return str(policy_dir)


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestDeepResolve:
    def test_params_single_level(self):
        assert _resolve_value("params.amount", {"amount": 100}, {}) == 100

    def test_params_deep_nested(self):
        params = {"user": {"address": {"country": "US"}}}
        assert _resolve_value("params.user.address.country", params, {}) == "US"

    def test_params_missing_intermediate(self):
        params = {"user": {"name": "Bob"}}
        assert _resolve_value("params.user.address.country", params, {}) is None

    def test_context_single_level(self):
        assert _resolve_value("context.role", {}, {"role": "admin"}) == "admin"

    def test_context_deep_nested(self):
        ctx = {"request": {"headers": {"origin": "example.com"}}}
        assert _resolve_value("context.request.headers.origin", {}, ctx) == "example.com"

    def test_bare_key_params_first(self):
        assert _resolve_value("amount", {"amount": 50}, {"amount": 99}) == 50

    def test_bare_key_falls_to_context(self):
        assert _resolve_value("role", {}, {"role": "admin"}) == "admin"

    def test_bare_key_missing(self):
        assert _resolve_value("missing", {}, {}) is None


class TestOperators:
    def test_equals(self):
        assert _evaluate_condition("foo", {"op": "==", "value": "foo"}) is True
        assert _evaluate_condition("foo", {"op": "==", "value": "bar"}) is False

    def test_not_equals(self):
        assert _evaluate_condition("foo", {"op": "!=", "value": "bar"}) is True

    def test_greater_than(self):
        assert _evaluate_condition(10, {"op": ">", "value": 5}) is True
        assert _evaluate_condition(3, {"op": ">", "value": 5}) is False

    def test_less_than(self):
        assert _evaluate_condition(3, {"op": "<", "value": 5}) is True

    def test_gte_lte(self):
        assert _evaluate_condition(5, {"op": ">=", "value": 5}) is True
        assert _evaluate_condition(5, {"op": "<=", "value": 5}) is True

    def test_in(self):
        assert _evaluate_condition("a", {"op": "in", "value": ["a", "b"]}) is True
        assert _evaluate_condition("c", {"op": "in", "value": ["a", "b"]}) is False

    def test_not_in(self):
        assert _evaluate_condition("c", {"op": "not_in", "value": ["a", "b"]}) is True

    def test_contains_string(self):
        assert _evaluate_condition("hello world", {"op": "contains", "value": "world"}) is True
        assert _evaluate_condition("hello", {"op": "contains", "value": "xyz"}) is False

    def test_contains_list(self):
        assert _evaluate_condition(["a", "b", "c"], {"op": "contains", "value": "b"}) is True
        assert _evaluate_condition(["a", "b"], {"op": "contains", "value": "z"}) is False

    def test_starts_with(self):
        assert _evaluate_condition("payment.process", {"op": "starts_with", "value": "payment"}) is True
        assert _evaluate_condition("db.read", {"op": "starts_with", "value": "payment"}) is False

    def test_ends_with(self):
        assert _evaluate_condition("user@example.com", {"op": "ends_with", "value": ".com"}) is True

    def test_regex(self):
        assert _evaluate_condition("abc-123", {"op": "regex", "value": r"^[a-z]+-\d+$"}) is True
        assert _evaluate_condition("ABC", {"op": "regex", "value": r"^\d+$"}) is False

    def test_exists(self):
        assert _evaluate_condition("something", {"op": "exists"}) is True
        assert _evaluate_condition(None, {"op": "exists"}) is False

    def test_not_exists(self):
        assert _evaluate_condition(None, {"op": "not_exists"}) is True
        assert _evaluate_condition("something", {"op": "not_exists"}) is False

    def test_none_value_returns_false(self):
        assert _evaluate_condition(None, {"op": "==", "value": "foo"}) is False
        assert _evaluate_condition(None, {"op": ">", "value": 5}) is False

    def test_scalar_equals(self):
        assert _evaluate_condition("foo", "foo") is True
        assert _evaluate_condition("foo", "bar") is False

    def test_unsupported_op_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            _evaluate_condition("foo", {"op": "xor", "value": "bar"})


class TestGlobMatching:
    def test_star_matches_all(self):
        assert _action_matches("anything", ["*"]) is True

    def test_suffix_glob(self):
        assert _action_matches("payment.process", ["payment.*"]) is True
        assert _action_matches("db.read", ["payment.*"]) is False

    def test_prefix_glob(self):
        assert _action_matches("db.delete", ["*.delete"]) is True
        assert _action_matches("db.read", ["*.delete"]) is False

    def test_exact_match(self):
        assert _action_matches("send_email", ["send_email"]) is True
        assert _action_matches("send_sms", ["send_email"]) is False

    def test_multiple_patterns(self):
        assert _action_matches("cache.clear", ["db.*", "cache.*"]) is True
        assert _action_matches("email.send", ["db.*", "cache.*"]) is False


# ---------------------------------------------------------------------------
# IAM policy evaluation (file-based)
# ---------------------------------------------------------------------------


class TestIAMEvaluation:
    def test_default_deny(self, tmp_path):
        path = _write_policy(tmp_path, "deny.yaml", """
version: "1.0"
default: deny
statements: []
""")
        engine = PolicyEngine()
        engine.load_from_file(path)
        result = engine.evaluate("anything", {})
        assert result.status == PolicyStatus.BLOCK
        assert result.metadata["matched_by"] == "default"

    def test_default_allow(self, tmp_path):
        path = _write_policy(tmp_path, "allow.yaml", """
version: "1.0"
default: allow
statements: []
""")
        engine = PolicyEngine()
        engine.load_from_file(path)
        result = engine.evaluate("anything", {})
        assert result.status == PolicyStatus.ALLOW

    def test_explicit_allow(self, tmp_path):
        path = _write_policy(tmp_path, "read.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowRead"
    effect: allow
    actions: ["db.read"]
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("db.read", {})
        assert result.status == PolicyStatus.ALLOW
        assert result.metadata["sid"] == "AllowRead"

    def test_unmatched_action_gets_default_deny(self, tmp_path):
        path = _write_policy(tmp_path, "read_only.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowRead"
    effect: allow
    actions: ["db.read"]
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("db.delete", {})
        assert result.status == PolicyStatus.BLOCK
        assert result.metadata["matched_by"] == "default"

    def test_deny_wins_over_allow(self, tmp_path):
        path = _write_policy(tmp_path, "deny_wins.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowAll"
    effect: allow
    actions: ["*"]
  - sid: "DenyDelete"
    effect: deny
    actions: ["*.delete"]
    reason: "Destructive ops blocked"
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("db.delete", {})
        assert result.status == PolicyStatus.BLOCK
        assert "Destructive" in result.reason
        assert result.metadata["sid"] == "DenyDelete"
        assert result.metadata["matched_by"] == "explicit_deny"

    def test_deny_wins_over_review(self, tmp_path):
        path = _write_policy(tmp_path, "deny_review.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "ReviewPayments"
    effect: review
    actions: ["payment.*"]
  - sid: "DenyAll"
    effect: deny
    actions: ["payment.refund"]
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("payment.refund", {})
        assert result.status == PolicyStatus.BLOCK

    def test_review_wins_over_allow(self, tmp_path):
        path = _write_policy(tmp_path, "review_allow.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowPayments"
    effect: allow
    actions: ["payment.*"]
  - sid: "ReviewLarge"
    effect: review
    actions: ["payment.*"]
    conditions:
      params.amount:
        op: ">"
        value: 5000
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("payment.charge", {"amount": 100})
        assert result.status == PolicyStatus.ALLOW

        result = engine.evaluate("payment.charge", {"amount": 10000})
        assert result.status == PolicyStatus.REVIEW

    def test_conditions_with_deep_params(self, tmp_path):
        path = _write_policy(tmp_path, "deep.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "BlockForeignPayments"
    effect: deny
    actions: ["payment.*"]
    conditions:
      params.recipient.country:
        op: "!="
        value: "US"
  - sid: "AllowPayments"
    effect: allow
    actions: ["payment.*"]
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("payment.send", {"recipient": {"country": "US"}})
        assert result.status == PolicyStatus.ALLOW

        result = engine.evaluate("payment.send", {"recipient": {"country": "RU"}})
        assert result.status == PolicyStatus.BLOCK

    def test_conditions_with_context(self, tmp_path):
        path = _write_policy(tmp_path, "context.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowAdmin"
    effect: allow
    actions: ["*"]
    conditions:
      context.user_role:
        op: "=="
        value: "admin"
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("db.drop", {}, {"user_role": "admin"})
        assert result.status == PolicyStatus.ALLOW

        result = engine.evaluate("db.drop", {}, {"user_role": "guest"})
        assert result.status == PolicyStatus.BLOCK

    def test_match_any_conditions(self, tmp_path):
        path = _write_policy(tmp_path, "any.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "BlockSuspicious"
    effect: deny
    actions: ["*"]
    match: any
    conditions:
      context.ip_blocked:
        op: "=="
        value: true
      context.rate_exceeded:
        op: "=="
        value: true
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("api.call", {}, {"ip_blocked": True, "rate_exceeded": False})
        assert result.status == PolicyStatus.BLOCK

        result = engine.evaluate("api.call", {}, {"ip_blocked": False, "rate_exceeded": False})
        assert result.status == PolicyStatus.BLOCK  # default deny

    def test_exists_operator_in_policy(self, tmp_path):
        path = _write_policy(tmp_path, "auth.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "RequireAuth"
    effect: deny
    actions: ["*"]
    conditions:
      context.auth_token:
        op: "not_exists"
    reason: "Authentication required"
  - sid: "AllowAuthenticated"
    effect: allow
    actions: ["*"]
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("api.call", {}, {})
        assert result.status == PolicyStatus.BLOCK
        assert "Authentication" in result.reason

        result = engine.evaluate("api.call", {}, {"auth_token": "abc123"})
        assert result.status == PolicyStatus.ALLOW

    def test_regex_operator_in_policy(self, tmp_path):
        path = _write_policy(tmp_path, "regex.yaml", r"""
version: "1.0"
default: deny
statements:
  - sid: "AllowInternalEmails"
    effect: allow
    actions: ["email.send"]
    conditions:
      params.to:
        op: "regex"
        value: ".*@company\\.com$"
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("email.send", {"to": "bob@company.com"})
        assert result.status == PolicyStatus.ALLOW

        result = engine.evaluate("email.send", {"to": "hacker@evil.com"})
        assert result.status == PolicyStatus.BLOCK

    def test_multiple_actions_per_statement(self, tmp_path):
        path = _write_policy(tmp_path, "multi.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowReadOps"
    effect: allow
    actions: ["db.read", "db.list", "cache.*"]
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        assert engine.evaluate("db.read", {}).status == PolicyStatus.ALLOW
        assert engine.evaluate("db.list", {}).status == PolicyStatus.ALLOW
        assert engine.evaluate("cache.get", {}).status == PolicyStatus.ALLOW
        assert engine.evaluate("db.write", {}).status == PolicyStatus.BLOCK


# ---------------------------------------------------------------------------
# Directory loading
# ---------------------------------------------------------------------------


class TestDirectoryLoading:
    def test_load_from_directory(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, {
            "01_base.yaml": """
version: "1.0"
default: deny
statements:
  - sid: "AllowRead"
    effect: allow
    actions: ["db.read"]
""",
            "02_payments.yaml": """
version: "1.0"
statements:
  - sid: "AllowPayments"
    effect: allow
    actions: ["payment.charge"]
  - sid: "ReviewLarge"
    effect: review
    actions: ["payment.charge"]
    conditions:
      params.amount:
        op: ">"
        value: 5000
""",
        })

        engine = PolicyEngine()
        loaded = engine.load_from_directory(policy_dir)
        assert len(loaded) == 2

        # Base policy allows db.read
        assert engine.evaluate("db.read", {}).status == PolicyStatus.ALLOW
        # Payments policy allows small payments
        assert engine.evaluate("payment.charge", {"amount": 100}).status == PolicyStatus.ALLOW
        # Large payments need review
        assert engine.evaluate("payment.charge", {"amount": 10000}).status == PolicyStatus.REVIEW
        # Unmatched defaults to deny
        assert engine.evaluate("db.delete", {}).status == PolicyStatus.BLOCK

    def test_load_from_directory_alphabetical_order(self, tmp_path):
        """First file's default wins."""
        policy_dir = _make_policy_dir(tmp_path, {
            "01_deny.yaml": """
version: "1.0"
default: deny
statements: []
""",
            "02_allow.yaml": """
version: "1.0"
default: allow
statements: []
""",
        })

        engine = PolicyEngine()
        engine.load_from_directory(policy_dir)
        # First file sets deny, second overrides to allow — last wins for default
        result = engine.evaluate("anything", {})
        # Both files loaded; last file's default: allow wins
        assert result.status == PolicyStatus.ALLOW

    def test_load_directory_not_found(self):
        engine = PolicyEngine()
        with pytest.raises(FileNotFoundError):
            engine.load_from_directory("/nonexistent/path")

    def test_load_empty_directory(self, tmp_path):
        policy_dir = tmp_path / "empty"
        policy_dir.mkdir()
        engine = PolicyEngine()
        with pytest.raises(ValueError, match="No .yaml"):
            engine.load_from_directory(str(policy_dir))

    def test_control_layer_with_policy_dir(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, {
            "base.yaml": """
version: "1.0"
default: deny
statements:
  - sid: "AllowTest"
    effect: allow
    actions: ["my_action"]
""",
        })

        control = ControlLayer(policy_dir=policy_dir)

        @control.register_action("my_action")
        def my_action():
            return "done"

        result = control.execute_sync("my_action", {})
        assert result.result == "done"

    def test_multi_file_deny_wins_across_files(self, tmp_path):
        """A deny in one file blocks even if another file allows."""
        policy_dir = _make_policy_dir(tmp_path, {
            "01_allow.yaml": """
version: "1.0"
default: deny
statements:
  - sid: "AllowAll"
    effect: allow
    actions: ["*"]
""",
            "02_deny_dangerous.yaml": """
version: "1.0"
statements:
  - sid: "DenyDrop"
    effect: deny
    actions: ["db.drop"]
    reason: "Never allow drop"
""",
        })

        engine = PolicyEngine()
        engine.load_from_directory(policy_dir)

        # Normal actions allowed
        assert engine.evaluate("db.read", {}).status == PolicyStatus.ALLOW
        # db.drop denied even though AllowAll says allow
        result = engine.evaluate("db.drop", {})
        assert result.status == PolicyStatus.BLOCK
        assert "Never allow drop" in result.reason


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    def test_bare_engine_defaults_to_allow(self):
        engine = PolicyEngine()
        result = engine.evaluate("anything", {})
        assert result.status == PolicyStatus.ALLOW

    def test_legacy_rules_from_file(self, tmp_path):
        path = _write_policy(tmp_path, "legacy.yaml", """
rules:
  - action: payment
    status: block
    reason: "blocked by legacy rule"
    conditions:
      amount:
        op: ">"
        value: 1000
""")
        engine = PolicyEngine()
        engine.load_from_file(path)

        result = engine.evaluate("payment", {"amount": 2000})
        assert result.status == PolicyStatus.BLOCK
        assert "blocked by legacy rule" in result.reason

        result = engine.evaluate("payment", {"amount": 100})
        assert result.status == PolicyStatus.ALLOW

    def test_legacy_callable_rules(self):
        engine = PolicyEngine()

        def block_all(action, params, context):
            return PolicyResult(status=PolicyStatus.BLOCK, reason="nope")

        engine.add_rule(block_all)
        result = engine.evaluate("anything", {})
        assert result.status == PolicyStatus.BLOCK

    def test_legacy_priority_ordering(self, tmp_path):
        path = _write_policy(tmp_path, "priority.yaml", """
rules:
  - action: test
    status: allow
    priority: 0
  - action: test
    status: block
    reason: "high priority block"
    priority: 100
""")
        engine = PolicyEngine()
        engine.load_from_file(path)
        result = engine.evaluate("test", {})
        assert result.status == PolicyStatus.BLOCK


# ---------------------------------------------------------------------------
# Policy validation
# ---------------------------------------------------------------------------


class TestValidation:
    def test_valid_policy(self, tmp_path):
        path = _write_policy(tmp_path, "valid.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowRead"
    effect: allow
    actions: ["db.read"]
""")
        engine = PolicyEngine()
        issues = engine.validate_file(path)
        assert issues == []

    def test_invalid_yaml_syntax(self):
        engine = PolicyEngine()
        issues = engine.validate("{{bad yaml")
        assert any("syntax" in i.lower() or "YAML" in i for i in issues)

    def test_missing_effect(self):
        engine = PolicyEngine()
        issues = engine.validate("""
statements:
  - sid: "NoEffect"
    actions: ["*"]
""")
        assert any("effect" in i.lower() for i in issues)

    def test_bad_operator(self):
        engine = PolicyEngine()
        issues = engine.validate("""
statements:
  - sid: "BadOp"
    effect: allow
    actions: ["*"]
    conditions:
      amount:
        op: "xor"
        value: 5
""")
        assert any("xor" in i for i in issues)

    def test_duplicate_sids(self):
        engine = PolicyEngine()
        issues = engine.validate("""
statements:
  - sid: "Dupe"
    effect: allow
    actions: ["a"]
  - sid: "Dupe"
    effect: deny
    actions: ["b"]
""")
        assert any("Duplicate" in i for i in issues)

    def test_invalid_default(self):
        engine = PolicyEngine()
        issues = engine.validate("""
default: maybe
statements:
  - sid: "Test"
    effect: allow
    actions: ["*"]
""")
        assert any("default" in i.lower() for i in issues)

    def test_no_statements_or_rules(self):
        engine = PolicyEngine()
        issues = engine.validate("foo: bar")
        assert any("statements" in i or "rules" in i for i in issues)

    def test_validate_directory(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, {
            "good.yaml": """
version: "1.0"
default: deny
statements:
  - sid: "OK"
    effect: allow
    actions: ["*"]
""",
            "bad.yaml": """
statements:
  - sid: "NoEffect"
    actions: ["*"]
""",
        })

        engine = PolicyEngine()
        results = engine.validate_directory(policy_dir)
        assert "good.yaml" not in results
        assert "bad.yaml" in results
        assert any("effect" in i.lower() for i in results["bad.yaml"])


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------


class TestDryRun:
    def test_dry_run_returns_policy_only(self, tmp_path):
        path = _write_policy(tmp_path, "dry.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowTest"
    effect: allow
    actions: ["test"]
""")
        engine = PolicyEngine()
        engine.load_from_file(path)
        result = engine.dry_run("test", {})
        assert result.status == PolicyStatus.ALLOW
        assert isinstance(result, PolicyResult)

    @pytest.mark.asyncio
    async def test_dry_run_on_control_layer(self, tmp_path):
        path = _write_policy(tmp_path, "dry.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowOps"
    effect: allow
    actions: ["my_action"]
""")
        control = ControlLayer(policy_path=path)
        executed = []

        @control.register_action("my_action")
        def my_action():
            executed.append(True)
            return "done"

        result = await control.dry_run("my_action", {})
        assert result.status == PolicyStatus.ALLOW
        assert executed == []  # Action was NOT executed

    def test_dry_run_sync_on_control_layer(self, tmp_path):
        path = _write_policy(tmp_path, "dry.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowOps"
    effect: allow
    actions: ["my_action"]
""")
        control = ControlLayer(policy_path=path)
        result = control.dry_run_sync("my_action", {})
        assert result.status == PolicyStatus.ALLOW


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------


class TestHooks:
    @pytest.mark.asyncio
    async def test_before_hook_fires(self):
        control = ControlLayer()
        calls = []

        @control.before_hook
        def log_before(action, params, context):
            calls.append(("before", action))

        @control.register_action("test")
        def test_action():
            return "ok"

        await control.execute("test", {})
        assert calls == [("before", "test")]

    @pytest.mark.asyncio
    async def test_after_hook_fires(self):
        control = ControlLayer()
        results = []

        @control.after_hook
        def log_after(exec_result):
            results.append(exec_result.result)

        @control.register_action("test")
        def test_action():
            return "ok"

        await control.execute("test", {})
        assert results == ["ok"]

    @pytest.mark.asyncio
    async def test_before_hook_exception_aborts(self):
        control = ControlLayer()

        @control.before_hook
        def deny(action, params, context):
            raise PermissionError("Hook denied")

        @control.register_action("test")
        def test_action():
            return "ok"

        with pytest.raises(PermissionError, match="Hook denied"):
            await control.execute("test", {})

    @pytest.mark.asyncio
    async def test_async_before_hook(self):
        control = ControlLayer()
        calls = []

        @control.before_hook
        async def async_log(action, params, context):
            await asyncio.sleep(0.01)
            calls.append(action)

        @control.register_action("test")
        def test_action():
            return "ok"

        await control.execute("test", {})
        assert calls == ["test"]

    @pytest.mark.asyncio
    async def test_add_hook_method(self):
        control = ControlLayer()
        calls = []

        def my_hook(action, params, context):
            calls.append(action)

        control.add_hook("before_execute", my_hook)

        @control.register_action("test")
        def test_action():
            return "ok"

        await control.execute("test", {})
        assert calls == ["test"]

    def test_add_hook_invalid_event(self):
        control = ControlLayer()
        with pytest.raises(ValueError, match="Unknown hook event"):
            control.add_hook("invalid_event", lambda: None)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_metadata_always_dict(self):
        result = PolicyResult(status=PolicyStatus.ALLOW)
        assert isinstance(result.metadata, dict)

    def test_metadata_has_sid(self, tmp_path):
        path = _write_policy(tmp_path, "meta.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "MyRule"
    effect: allow
    actions: ["test"]
""")
        engine = PolicyEngine()
        engine.load_from_file(path)
        result = engine.evaluate("test", {})
        assert result.metadata["sid"] == "MyRule"
        assert result.metadata["matched_by"] == "explicit_allow"

    def test_metadata_on_deny(self, tmp_path):
        path = _write_policy(tmp_path, "deny.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "DenyAll"
    effect: deny
    actions: ["*"]
""")
        engine = PolicyEngine()
        engine.load_from_file(path)
        result = engine.evaluate("anything", {})
        assert result.metadata["sid"] == "DenyAll"
        assert result.metadata["matched_by"] == "explicit_deny"

    def test_metadata_on_default(self, tmp_path):
        path = _write_policy(tmp_path, "empty.yaml", """
version: "1.0"
default: deny
statements: []
""")
        engine = PolicyEngine()
        engine.load_from_file(path)
        result = engine.evaluate("anything", {})
        assert result.metadata["matched_by"] == "default"


class TestInputNormalization:
    """Test that encoding bypasses are caught via input normalization."""

    def _make_engine(self, tmp_path):
        path = _write_policy(tmp_path, "policy.yaml", """
version: "1.0"
default: allow
statements:
  - sid: "BlockRM"
    effect: deny
    actions: ["bash.execute"]
    conditions:
      params.command:
        op: "regex"
        value: "\\\\brm\\\\s"
    reason: "rm blocked"
  - sid: "BlockDrop"
    effect: deny
    actions: ["bash.execute"]
    conditions:
      params.command:
        op: "regex"
        value: "(?i)DROP\\\\s+TABLE"
    reason: "DROP TABLE blocked"
""")
        engine = PolicyEngine()
        engine.load_from_file(path)
        return engine

    def test_base64_decoded_and_matched(self, tmp_path):
        engine = self._make_engine(tmp_path)
        # "rm -rf /" base64 = "cm0gLXJmIC8="
        result = engine.evaluate("bash.execute", {"command": "cm0gLXJmIC8="})
        assert result.status == PolicyStatus.BLOCK

    def test_unicode_escape_decoded(self, tmp_path):
        engine = self._make_engine(tmp_path)
        # D\u0052OP TABLE -> DROP TABLE
        result = engine.evaluate("bash.execute", {"command": "D\\u0052OP TABLE users"})
        assert result.status == PolicyStatus.BLOCK

    def test_hex_escape_decoded(self, tmp_path):
        engine = self._make_engine(tmp_path)
        # \x72\x6d = rm
        result = engine.evaluate("bash.execute", {"command": "\\x72\\x6d -rf /"})
        assert result.status == PolicyStatus.BLOCK

    def test_normal_string_unchanged(self, tmp_path):
        engine = self._make_engine(tmp_path)
        result = engine.evaluate("bash.execute", {"command": "ls -la"})
        assert result.status == PolicyStatus.ALLOW

    def test_non_base64_not_decoded(self, tmp_path):
        engine = self._make_engine(tmp_path)
        # "hello world" has spaces, not treated as base64
        result = engine.evaluate("bash.execute", {"command": "hello world"})
        assert result.status == PolicyStatus.ALLOW

    def test_normal_rm_still_blocked(self, tmp_path):
        engine = self._make_engine(tmp_path)
        result = engine.evaluate("bash.execute", {"command": "rm -rf /tmp"})
        assert result.status == PolicyStatus.BLOCK
