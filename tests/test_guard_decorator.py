"""Tests for the @guard decorator."""

import asyncio

import pytest

from agsec import guard
from agsec.exceptions import PolicyViolationError


def _make_policy_dir(tmp_path, content):
    d = tmp_path / "policies"
    d.mkdir()
    (d / "policy.yaml").write_text(content)
    return str(d)


class TestGuardSync:
    def test_allowed(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "AllowEmail"
    effect: allow
    actions: ["email.send"]
""")

        @guard("email.send", policy_dir=policy_dir)
        def send_email(to, subject):
            return {"sent_to": to}

        result = send_email(to="bob@co.com", subject="hi")
        assert result == {"sent_to": "bob@co.com"}

    def test_blocked(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "BlockAll"
    effect: deny
    actions: ["*"]
    reason: "Blocked"
""")

        @guard("payment.charge", policy_dir=policy_dir)
        def charge(amount):
            return {"charged": amount}

        with pytest.raises(PolicyViolationError):
            charge(amount=100)

    def test_condition_match(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "BlockLarge"
    effect: deny
    actions: ["payment.charge"]
    conditions:
      params.amount:
        op: ">"
        value: 1000
    reason: "Too large"
  - sid: "AllowPayments"
    effect: allow
    actions: ["payment.charge"]
""")

        @guard("payment.charge", policy_dir=policy_dir)
        def charge(amount):
            return {"charged": amount}

        # Small payment allowed
        assert charge(amount=50) == {"charged": 50}

        # Large payment blocked
        with pytest.raises(PolicyViolationError):
            charge(amount=5000)

    def test_preserves_function_metadata(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: allow
statements: []
""")

        @guard("test.func", policy_dir=policy_dir)
        def my_function(x):
            """My docstring."""
            return x

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."


class TestGuardAsync:
    @pytest.mark.asyncio
    async def test_allowed(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "Allow"
    effect: allow
    actions: ["async.action"]
""")

        @guard("async.action", policy_dir=policy_dir)
        async def do_thing(value):
            await asyncio.sleep(0.01)
            return value * 2

        result = await do_thing(value=5)
        assert result == 10

    @pytest.mark.asyncio
    async def test_blocked(self, tmp_path):
        policy_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements: []
""")

        @guard("async.blocked", policy_dir=policy_dir)
        async def do_thing(value):
            return value

        with pytest.raises(PolicyViolationError):
            await do_thing(value=1)


class TestGuardAgentOverlay:
    def test_agent_overlay_deny_wins(self, tmp_path):
        # Project allows everything
        project_dir = _make_policy_dir(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "AllowAll"
    effect: allow
    actions: ["*"]
""")

        # Agent overlay denies payment
        agent_dir = tmp_path / "agent_policies"
        agent_dir.mkdir()
        (agent_dir / "perms.yaml").write_text("""
version: "1.0"
statements:
  - sid: "AgentDenyPayment"
    effect: deny
    actions: ["payment.*"]
    reason: "Agent not allowed to make payments"
""")

        # Manually set up the checker with both dirs
        from agsec.integrations._base import PolicyChecker
        checker = PolicyChecker(policy_dir=str(project_dir), audit=False)
        checker._ensure_loaded()
        checker.engine.load_from_directory(str(agent_dir))

        # Payment blocked by agent overlay
        result = checker.check("payment.charge", {"amount": 100})
        from agsec.types import PolicyStatus
        assert result.status == PolicyStatus.BLOCK

        # Other actions still allowed
        result = checker.check("email.send", {"to": "x"})
        assert result.status == PolicyStatus.ALLOW
