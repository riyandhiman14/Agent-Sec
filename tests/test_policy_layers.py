"""Tests for IAM-style layered policy evaluation."""

import pytest

from agsec.policy.engine import LayeredPolicyEngine, PolicyEngine
from agsec.policy.statement import Statement
from agsec.types import PolicyResult, PolicyStatus


def _engine_with_statements(*statements):
    """Create a PolicyEngine with IAM statements."""
    engine = PolicyEngine(default="deny")
    engine._iam_loaded = True
    for stmt in statements:
        engine.add_statement(stmt)
    return engine


def _allow(sid, actions, **conditions):
    return Statement(sid=sid, effect=PolicyStatus.ALLOW, actions=actions, conditions=conditions)


def _deny(sid, actions, **conditions):
    return Statement(sid=sid, effect=PolicyStatus.BLOCK, actions=actions, conditions=conditions)


def _review(sid, actions, **conditions):
    return Statement(sid=sid, effect=PolicyStatus.REVIEW, actions=actions, conditions=conditions)


class TestLayeredEvaluation:
    def test_project_deny_overrides_agent_allow(self):
        """Explicit deny at project layer blocks even if agent allows."""
        project = _engine_with_statements(
            _deny("DenyDelete", ["file.write"]),
        )
        agent = _engine_with_statements(
            _allow("AllowAll", ["*"]),
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("project", project)
        layered.add_layer("agent", agent)

        result = layered.evaluate("file.write", {"file_path": "/app/.env"})
        assert result.status == PolicyStatus.BLOCK
        assert result.metadata["layer"] == "project"

    def test_agent_deny_overrides_project_allow(self):
        """Explicit deny at agent layer blocks even if project allows."""
        project = _engine_with_statements(
            _allow("AllowWrite", ["file.write"]),
        )
        agent = _engine_with_statements(
            _deny("DenyWrite", ["file.write"]),
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("project", project)
        layered.add_layer("agent", agent)

        result = layered.evaluate("file.write", {})
        assert result.status == PolicyStatus.BLOCK
        assert result.metadata["layer"] == "agent"

    def test_both_allow_means_allow(self):
        """Action allowed only when ALL layers allow."""
        project = _engine_with_statements(
            _allow("AllowRead", ["file.read"]),
        )
        agent = _engine_with_statements(
            _allow("AllowRead", ["file.read"]),
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("project", project)
        layered.add_layer("agent", agent)

        result = layered.evaluate("file.read", {})
        assert result.status == PolicyStatus.ALLOW

    def test_project_implicit_deny_blocks(self):
        """If project has no matching allow, implicit deny blocks — even if agent allows."""
        project = _engine_with_statements(
            _allow("AllowRead", ["file.read"]),  # only allows read, not write
        )
        agent = _engine_with_statements(
            _allow("AllowAll", ["*"]),  # agent tries to allow everything
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("project", project)
        layered.add_layer("agent", agent)

        result = layered.evaluate("file.write", {})
        assert result.status == PolicyStatus.BLOCK  # project implicit deny wins
        assert result.metadata["layer"] == "project"

    def test_agent_cannot_widen_project_permissions(self):
        """KEY TEST: agent allow + project no-match = deny."""
        project = _engine_with_statements(
            _allow("AllowSafeOps", ["file.read", "file.glob"]),
        )
        agent = _engine_with_statements(
            _allow("AllowEverything", ["*"]),
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("project", project)
        layered.add_layer("agent", agent)

        # file.read — both allow → allowed
        result = layered.evaluate("file.read", {})
        assert result.status == PolicyStatus.ALLOW

        # bash.execute — project has no allow → blocked
        result = layered.evaluate("bash.execute", {"command": "rm -rf /"})
        assert result.status == PolicyStatus.BLOCK

    def test_no_layers_means_allow(self):
        """No layers configured = fail-open (no policies = no enforcement)."""
        layered = LayeredPolicyEngine()
        result = layered.evaluate("file.read", {})
        assert result.status == PolicyStatus.ALLOW
        assert result.metadata["matched_by"] == "no_layers"

    def test_review_in_any_layer_means_review(self):
        """Review at any layer forces review even if others allow."""
        project = _engine_with_statements(
            _allow("AllowFetch", ["web.fetch"]),
        )
        agent = _engine_with_statements(
            _review("ReviewFetch", ["web.fetch"]),
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("project", project)
        layered.add_layer("agent", agent)

        result = layered.evaluate("web.fetch", {"url": "https://example.com"})
        assert result.status == PolicyStatus.REVIEW
        assert result.metadata["layer"] == "agent"

    def test_layer_name_in_metadata(self):
        """Result metadata includes which layer made the decision."""
        project = _engine_with_statements(
            _deny("DenyBash", ["bash.execute"]),
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("project", project)

        result = layered.evaluate("bash.execute", {"command": "ls"})
        assert result.metadata["layer"] == "project"

    def test_single_layer_same_as_flat(self):
        """Single layer behaves identically to flat PolicyEngine."""
        engine = _engine_with_statements(
            _deny("DenyDelete", ["bash.execute"]),
            _allow("AllowBash", ["bash.execute"]),
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("project", engine)

        # deny wins (same as flat)
        result = layered.evaluate("bash.execute", {"command": "ls"})
        assert result.status == PolicyStatus.BLOCK

    def test_layers_property(self):
        """Can inspect layers."""
        engine1 = PolicyEngine()
        engine2 = PolicyEngine()

        layered = LayeredPolicyEngine()
        layered.add_layer("project", engine1)
        layered.add_layer("agent", engine2)

        assert len(layered.layers) == 2
        assert layered.layers[0][0] == "project"
        assert layered.layers[1][0] == "agent"

    def test_dry_run_same_as_evaluate(self):
        """dry_run() returns same result as evaluate()."""
        project = _engine_with_statements(
            _allow("AllowRead", ["file.read"]),
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("project", project)

        result1 = layered.evaluate("file.read", {})
        result2 = layered.dry_run("file.read", {})
        assert result1.status == result2.status

    def test_three_layers(self):
        """Three layers all must agree."""
        system = _engine_with_statements(
            _allow("AllowRead", ["file.read"]),
            _allow("AllowWrite", ["file.write"]),
        )
        project = _engine_with_statements(
            _allow("AllowRead", ["file.read"]),
            # no allow for file.write — implicit deny
        )
        agent = _engine_with_statements(
            _allow("AllowAll", ["*"]),
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("system", system)
        layered.add_layer("project", project)
        layered.add_layer("agent", agent)

        # file.read — all three allow
        result = layered.evaluate("file.read", {})
        assert result.status == PolicyStatus.ALLOW

        # file.write — project implicit deny blocks
        result = layered.evaluate("file.write", {})
        assert result.status == PolicyStatus.BLOCK
        assert result.metadata["layer"] == "project"

    def test_context_passed_to_all_layers(self):
        """Context is passed through to each layer's evaluation."""
        project = _engine_with_statements(
            Statement(
                sid="OnlyClaudeCode",
                effect=PolicyStatus.ALLOW,
                actions=["bash.execute"],
                conditions={"context.agent": {"op": "==", "value": "claude-code"}},
            ),
        )

        layered = LayeredPolicyEngine()
        layered.add_layer("project", project)

        # With matching context — allowed
        result = layered.evaluate("bash.execute", {}, {"agent": "claude-code"})
        assert result.status == PolicyStatus.ALLOW

        # With wrong context — implicit deny
        result = layered.evaluate("bash.execute", {}, {"agent": "sketchy-mcp"})
        assert result.status == PolicyStatus.BLOCK
