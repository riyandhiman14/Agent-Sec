"""Tests for LangChain fluent API integration.

Tests the condition builder, rule helpers, and guard() without requiring
langchain-core installed (tests PolicyChecker + conditions directly).
"""

import pytest

from agsec.exceptions import PolicyViolationError
from agsec.integrations._base import PolicyChecker
from agsec.integrations.conditions import Condition, param
from agsec.types import PolicyStatus


# ---------------------------------------------------------------------------
# Condition builder tests
# ---------------------------------------------------------------------------


class TestParam:
    def test_gt(self):
        c = param("amount") > 10000
        assert isinstance(c, Condition)
        assert c.key == "params.amount"
        assert c.op == ">"
        assert c.value == 10000

    def test_lt(self):
        c = param("amount") < 5
        assert c.op == "<"
        assert c.value == 5

    def test_gte(self):
        c = param("score") >= 90
        assert c.op == ">="

    def test_lte(self):
        c = param("score") <= 10
        assert c.op == "<="

    def test_eq(self):
        c = param("status") == "active"
        assert c.op == "=="
        assert c.value == "active"

    def test_ne(self):
        c = param("role") != "guest"
        assert c.op == "!="

    def test_contains(self):
        c = param("query").contains("DROP")
        assert c.op == "contains"
        assert c.value == "DROP"

    def test_starts_with(self):
        c = param("url").starts_with("https://")
        assert c.op == "starts_with"

    def test_ends_with(self):
        c = param("email").ends_with("@company.com")
        assert c.op == "ends_with"

    def test_regex(self):
        c = param("command").regex(r"rm\s+-rf")
        assert c.op == "regex"

    def test_is_in(self):
        c = param("country").is_in(["US", "UK"])
        assert c.op == "in"
        assert c.value == ["US", "UK"]

    def test_not_in(self):
        c = param("country").not_in(["KP", "IR"])
        assert c.op == "not_in"

    def test_exists(self):
        c = param("token").exists()
        assert c.op == "exists"

    def test_not_exists(self):
        c = param("token").not_exists()
        assert c.op == "not_exists"

    def test_auto_prefix(self):
        c = param("amount") > 0
        assert c.key == "params.amount"

    def test_explicit_prefix_preserved(self):
        c = param("context.user_role") == "admin"
        assert c.key == "context.user_role"


class TestConditionToDict:
    def test_simple(self):
        c = Condition("params.amount", ">", 100)
        assert c.to_dict() == {"params.amount": {"op": ">", "value": 100}}

    def test_exists(self):
        c = Condition("params.token", "exists")
        assert c.to_dict() == {"params.token": {"op": "exists"}}

    def test_not_exists(self):
        c = Condition("params.x", "not_exists")
        assert c.to_dict() == {"params.x": {"op": "not_exists"}}


# ---------------------------------------------------------------------------
# PolicyChecker tests (shared foundation)
# ---------------------------------------------------------------------------


def _make_policy_dir(tmp_path, content):
    d = tmp_path / "policies"
    d.mkdir()
    (d / "policy.yaml").write_text(content)
    return str(d)


class TestPolicyChecker:
    def test_check_allowed(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "AllowSearch"
    effect: allow
    actions: ["tool.search"]
""")
        checker = PolicyChecker(policy_dir=policy_dir, audit=False)
        result = checker.check("tool.search", {"query": "python docs"})
        assert result.status == PolicyStatus.ALLOW

    def test_check_blocked(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements: []
""")
        checker = PolicyChecker(policy_dir=policy_dir, audit=False)
        result = checker.check("tool.anything", {})
        assert result.status == PolicyStatus.BLOCK

    def test_check_or_raise_blocked(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "DenyAll"
    effect: deny
    actions: ["*"]
    reason: "Blocked"
""")
        checker = PolicyChecker(policy_dir=policy_dir, audit=False)
        with pytest.raises(PolicyViolationError):
            checker.check_or_raise("tool.search", {"query": "test"})

    def test_condition_on_params(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "BlockCredentialSearch"
    effect: deny
    actions: ["tool.search"]
    conditions:
      params.query:
        op: "contains"
        value: "credentials"
    reason: "Cannot search for credentials"
  - sid: "AllowSearch"
    effect: allow
    actions: ["tool.search"]
""")
        checker = PolicyChecker(policy_dir=policy_dir, audit=False)

        result = checker.check("tool.search", {"query": "python docs"})
        assert result.status == PolicyStatus.ALLOW

        result = checker.check("tool.search", {"query": "find credentials"})
        assert result.status == PolicyStatus.BLOCK

    def test_no_policies_allows_all(self):
        checker = PolicyChecker(policy_dir="/nonexistent", audit=False)
        result = checker.check("anything", {})
        assert result.status == PolicyStatus.ALLOW

    @pytest.mark.asyncio
    async def test_async_check(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "Allow"
    effect: allow
    actions: ["tool.search"]
""")
        checker = PolicyChecker(policy_dir=policy_dir, audit=False)
        result = await checker.acheck("tool.search", {})
        assert result.status == PolicyStatus.ALLOW


class TestAgentOverlay:
    def test_agent_deny_overrides_project_allow(self, tmp_path):
        project_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "AllowAll"
    effect: allow
    actions: ["*"]
""")
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        (agent_dir / "perms.yaml").write_text("""
version: "1.0"
statements:
  - sid: "DenyDB"
    effect: deny
    actions: ["tool.database"]
    reason: "Agent cannot access DB"
""")

        checker = PolicyChecker(policy_dir=str(project_dir), audit=False)
        checker._ensure_loaded()
        checker.engine.load_from_directory(str(agent_dir))

        assert checker.check("tool.search", {}).status == PolicyStatus.ALLOW
        assert checker.check("tool.database", {}).status == PolicyStatus.BLOCK
