import logging

from agsec import ControlLayer, PolicyEngine, PolicyResult, PolicyStatus
from agsec.exceptions import PolicyViolationError


def test_control_execute_allow(monkeypatch):
    control = ControlLayer(policy_engine=PolicyEngine())

    @control.register_action("noop")
    def noop():
        return "ok"

    result = control.execute("noop", {})
    assert result.result == "ok"
    assert result.policy.status == PolicyStatus.ALLOW


def test_control_execute_block():
    engine = PolicyEngine()

    def deny_all(action, params, context):
        return PolicyResult(status=PolicyStatus.BLOCK, reason="denied")

    engine.add_rule(deny_all)
    control = ControlLayer(policy_engine=engine)

    @control.register_action("noop")
    def noop():
        return "ok"

    try:
        control.execute("noop", {})
        assert False, "Expected PolicyViolationError"
    except PolicyViolationError:
        pass


def test_policy_review():
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

    result = control.execute("payment", {"amount": 6000})
    assert result.result is None
    assert result.policy.status == PolicyStatus.REVIEW
