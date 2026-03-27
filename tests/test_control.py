import asyncio
import json
import os

import pytest

from agsec import AuditStore, ControlLayer, PolicyEngine, PolicyResult, PolicyStatus
from agsec.exceptions import PolicyViolationError


def _write_policy(tmp_path, filename, content):
    """Helper to write a policy YAML file and return its path."""
    path = tmp_path / filename
    path.write_text(content)
    return str(path)


@pytest.mark.asyncio
async def test_control_execute_allow(tmp_path):
    control = ControlLayer(policy_engine=PolicyEngine())

    @control.register_action("noop")
    def noop():
        return "ok"

    result = await control.execute("noop", {})
    assert result.result == "ok"
    assert result.policy.status == PolicyStatus.ALLOW


@pytest.mark.asyncio
async def test_control_execute_block(tmp_path):
    engine = PolicyEngine()

    def deny_all(action, params, context):
        return PolicyResult(status=PolicyStatus.BLOCK, reason="denied")

    engine.add_rule(deny_all)
    control = ControlLayer(policy_engine=engine)

    @control.register_action("noop")
    def noop():
        return "ok"

    with pytest.raises(PolicyViolationError):
        await control.execute("noop", {})


@pytest.mark.asyncio
async def test_policy_review(tmp_path):
    engine = PolicyEngine()

    def review_payment(action, params, context):
        if action == "payment" and params.get("amount") > 5000:
            return PolicyResult(status=PolicyStatus.REVIEW, reason="manual review required")
        return None

    engine.add_rule(review_payment)
    control = ControlLayer(policy_engine=engine)

    @control.register_action("payment")
    def payment(amount):
        return {"charged": amount}

    result = await control.execute("payment", {"amount": 6000})
    assert result.result is None
    assert result.policy.status == PolicyStatus.REVIEW


@pytest.mark.asyncio
async def test_policy_engine_load_yaml_block(tmp_path):
    path = _write_policy(tmp_path, "block.yaml", """
rules:
  - action: payment
    status: block
    reason: "Amount over limit"
    conditions:
      amount:
        op: ">"
        value: 10000
""")

    engine = PolicyEngine()
    engine.load_from_file(path)

    control = ControlLayer(policy_engine=engine)

    @control.register_action("payment")
    def payment(amount):
        return {"charged": amount}

    with pytest.raises(PolicyViolationError) as exc_info:
        await control.execute("payment", {"amount": 15000})
    assert "Amount over limit" in str(exc_info.value)


@pytest.mark.asyncio
async def test_control_layer_load_policy_file(tmp_path):
    path = _write_policy(tmp_path, "allow_email.yaml", """
version: "1.0"
default: deny
statements:
  - sid: "AllowEmail"
    effect: allow
    actions: ["send_email"]
    reason: "always allow"
""")

    control = ControlLayer(policy_path=path)

    @control.register_action("send_email")
    def send_email(to):
        return {"sent_to": to}

    result = await control.execute("send_email", {"to": "x@example.com"})
    assert result.result == {"sent_to": "x@example.com"}
    assert result.policy.status == PolicyStatus.ALLOW


@pytest.mark.asyncio
async def test_policy_engine_yaml_priority(tmp_path):
    path = _write_policy(tmp_path, "priority.yaml", """
rules:
  - action: payment
    status: allow
    priority: 0
  - action: payment
    status: block
    reason: "Higher priority block"
    priority: 100
""")

    engine = PolicyEngine()
    engine.load_from_file(path)

    control = ControlLayer(policy_engine=engine, audit_store=None)

    @control.register_action("payment")
    def payment(amount):
        return {"charged": amount}

    with pytest.raises(PolicyViolationError) as exc_info:
        await control.execute("payment", {"amount": 10})
    assert "Higher priority block" in str(exc_info.value)


@pytest.mark.asyncio
async def test_policy_engine_yaml_match_any(tmp_path):
    path = _write_policy(tmp_path, "match_any.yaml", """
rules:
  - action: data_export
    status: block
    match: any
    conditions:
      table:
        op: "=="
        value: "sensitive"
      export_type:
        op: "=="
        value: "external"
""")

    engine = PolicyEngine()
    engine.load_from_file(path)

    control = ControlLayer(policy_engine=engine, audit_store=None)

    @control.register_action("data_export")
    def data_export(table, export_type):
        return {"ok": True}

    # should block on table match
    with pytest.raises(PolicyViolationError):
        await control.execute("data_export", {"table": "sensitive", "export_type": "internal"})


@pytest.mark.asyncio
async def test_policy_engine_yaml_context_condition(tmp_path):
    path = _write_policy(tmp_path, "context.yaml", """
rules:
  - action: password_reset
    status: block
    conditions:
      context.user_role:
        op: "=="
        value: "guest"
""")

    engine = PolicyEngine()
    engine.load_from_file(path)

    control = ControlLayer(policy_engine=engine, audit_store=None)

    @control.register_action("password_reset")
    def password_reset(user_id):
        return {"reset": user_id}

    with pytest.raises(PolicyViolationError):
        await control.execute("password_reset", {"user_id": "u1"}, context={"user_role": "guest"})


@pytest.mark.asyncio
async def test_audit_store_logging(tmp_path):
    db_path = str(tmp_path / "test.db")
    audit = AuditStore(db_path)
    control = ControlLayer(audit_store=audit)

    @control.register_action("test_action")
    def test_action(value):
        return {"result": value * 2}

    result = await control.execute("test_action", {"value": 5})
    executions = audit.get_executions()
    assert len(executions) == 1
    assert executions[0]["action"] == "test_action"
    assert executions[0]["policy_status"] == "allow"
    assert json.loads(executions[0]["result"]) == {"result": 10}


@pytest.mark.asyncio
async def test_audit_store_block_logging(tmp_path):
    db_path = str(tmp_path / "test_block.db")
    audit = AuditStore(db_path)
    engine = PolicyEngine()
    engine.add_rule(lambda action, params, ctx: PolicyResult(status=PolicyStatus.BLOCK, reason="blocked"))
    control = ControlLayer(policy_engine=engine, audit_store=audit)

    @control.register_action("blocked_action")
    def blocked_action():
        return "should not run"

    with pytest.raises(PolicyViolationError):
        await control.execute("blocked_action", {})

    executions = audit.get_executions()
    assert len(executions) == 1
    assert executions[0]["action"] == "blocked_action"
    assert executions[0]["policy_status"] == "block"
    assert executions[0]["result"] is None


@pytest.mark.asyncio
async def test_audit_store_stats(tmp_path):
    db_path = str(tmp_path / "test_stats.db")
    audit = AuditStore(db_path)

    # Allow action
    control = ControlLayer(audit_store=audit)
    @control.register_action("allow_action")
    def allow_action():
        return "ok"
    await control.execute("allow_action", {})

    # Block action
    engine = PolicyEngine()
    engine.add_rule(lambda action, params, ctx: PolicyResult(status=PolicyStatus.BLOCK) if action == "block_action" else None)
    control_block = ControlLayer(policy_engine=engine, audit_store=audit)
    @control_block.register_action("block_action")
    def block_action():
        return "blocked"
    with pytest.raises(PolicyViolationError):
        await control_block.execute("block_action", {})

    stats = audit.get_execution_stats()
    assert stats["total_executions"] == 2
    assert stats["allowed"] == 1
    assert stats["blocked"] == 1


@pytest.mark.asyncio
async def test_async_action_support():
    """Test that async actions work correctly."""
    control = ControlLayer(policy_engine=PolicyEngine())

    @control.register_action("async_send_email")
    async def async_send_email(to: str, subject: str):
        await asyncio.sleep(0.01)
        return {"sent": True, "to": to, "subject": subject}

    result = await control.execute("async_send_email", {"to": "user@example.com", "subject": "Test"})
    assert result.result == {"sent": True, "to": "user@example.com", "subject": "Test"}
    assert result.policy.status == PolicyStatus.ALLOW


@pytest.mark.asyncio
async def test_sync_action_in_async_context():
    """Test that sync actions still work in async context."""
    control = ControlLayer(policy_engine=PolicyEngine())

    @control.register_action("sync_operation")
    def sync_operation(value: int):
        return value * 2

    result = await control.execute("sync_operation", {"value": 21})
    assert result.result == 42
    assert result.policy.status == PolicyStatus.ALLOW


def test_execute_sync_wrapper():
    control = ControlLayer(policy_engine=PolicyEngine())

    @control.register_action("sync_operation")
    def sync_operation(value: int):
        return value * 2

    result = control.execute_sync("sync_operation", {"value": 11})
    assert result.result == 22
    assert result.policy.status == PolicyStatus.ALLOW

    @control.register_action("async_operation")
    async def async_operation(value: int):
        await asyncio.sleep(0.01)
        return value * 3

    result2 = control.execute_sync("async_operation", {"value": 7})
    assert result2.result == 21
    assert result2.policy.status == PolicyStatus.ALLOW


def test_exception_hierarchy():
    """Test that exception types inherit from AgsecError and have proper structure."""
    from agsec.exceptions import (
        AgsecError,
        ConfigurationError,
        InvalidConfigError,
        ParameterValidationError,
        SecurityViolationError,
        DependencyError,
        TimeoutError,
        ValidationError,
        SecurityError,
        InitializationError,
        RuntimeError,
    )

    base_err = AgsecError("test message", "TEST_CODE", {"key": "value"})
    assert base_err.code == "TEST_CODE"
    assert base_err.details["key"] == "value"

    config_err = InvalidConfigError("/path/config.yaml", "invalid format", {"line": 10})
    assert config_err.code == "INVALID_CONFIG"
    assert config_err.details["config_path"] == "/path/config.yaml"
    assert config_err.details["line"] == 10
    assert isinstance(config_err, ConfigurationError)
    assert isinstance(config_err, AgsecError)

    param_err = ParameterValidationError("test_action", "amount", "invalid", "int", "not a number")
    assert param_err.code == "PARAMETER_VALIDATION_ERROR"
    assert param_err.details["action"] == "test_action"
    assert param_err.details["param"] == "amount"
    assert param_err.details["expected"] == "int"
    assert isinstance(param_err, ValidationError)

    sec_err = SecurityViolationError("unauthorized_access", {"user": "hacker", "resource": "admin"})
    assert sec_err.code == "SECURITY_VIOLATION"
    assert sec_err.details["violation_type"] == "unauthorized_access"
    assert sec_err.details["user"] == "hacker"
    assert isinstance(sec_err, SecurityError)

    dep_err = DependencyError("requests", "2.25.0", "2.20.0")
    assert dep_err.code == "DEPENDENCY_ERROR"
    assert dep_err.details["dependency"] == "requests"
    assert dep_err.details["version_required"] == "2.25.0"
    assert dep_err.details["version_found"] == "2.20.0"
    assert isinstance(dep_err, InitializationError)

    timeout_err = TimeoutError("policy_evaluation", 30.0)
    assert timeout_err.code == "TIMEOUT_ERROR"
    assert timeout_err.details["operation"] == "policy_evaluation"
    assert timeout_err.details["timeout_seconds"] == 30.0
    assert isinstance(timeout_err, RuntimeError)
