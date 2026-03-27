"""Tests for OpenAI SDK integration (mocked, no API calls)."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agsec.integrations.openai import protect, _check_tool_call, _build_engine
from agsec.integrations.conditions import allow, deny, review, param
from agsec.types import PolicyStatus


def _make_tool_call(name, arguments, tc_id="tc_1"):
    """Create a mock OpenAI tool_call object."""
    tc = SimpleNamespace()
    tc.id = tc_id
    tc.type = "function"
    tc.function = SimpleNamespace()
    tc.function.name = name
    tc.function.arguments = json.dumps(arguments) if isinstance(arguments, dict) else arguments
    return tc


def _make_response(*tool_calls):
    """Create a mock OpenAI ChatCompletion response."""
    message = SimpleNamespace()
    message.tool_calls = list(tool_calls) if tool_calls else None
    message.content = None
    message.role = "assistant"

    choice = SimpleNamespace()
    choice.message = message
    choice.finish_reason = "tool_calls" if tool_calls else "stop"
    choice.index = 0

    response = SimpleNamespace()
    response.choices = [choice]
    response.id = "chatcmpl-test"
    response.model = "gpt-4"
    return response


def _make_client(response):
    """Create a mock OpenAI client that returns the given response."""
    client = MagicMock()
    client.chat.completions.create = MagicMock(return_value=response)
    return client


class TestCheckToolCall:
    def test_allowed(self):
        engine = _build_engine([allow("search")])
        status, reason, meta = _check_tool_call(engine, "search", '{"query": "test"}')
        assert status == PolicyStatus.ALLOW

    def test_blocked(self):
        engine = _build_engine([deny("delete_user")])
        status, reason, meta = _check_tool_call(engine, "delete_user", '{}')
        assert status == PolicyStatus.BLOCK

    def test_default_deny(self):
        engine = _build_engine([allow("search")])
        status, _, _ = _check_tool_call(engine, "unknown_tool", '{}')
        assert status == PolicyStatus.BLOCK

    def test_conditional_deny(self):
        engine = _build_engine([
            deny("payment").when(param("amount") > 10000),
            allow("payment"),
        ])
        # Small amount — allowed
        status, _, _ = _check_tool_call(engine, "payment", '{"amount": 500}')
        assert status == PolicyStatus.ALLOW

        # Large amount — blocked
        status, _, _ = _check_tool_call(engine, "payment", '{"amount": 50000}')
        assert status == PolicyStatus.BLOCK


class TestProtect:
    def test_no_tools_passthrough(self):
        response = _make_response()  # no tool calls
        client = _make_client(response)
        protected = protect(client, allow("search"))

        result = protected.chat.completions.create(model="gpt-4", messages=[])
        assert result.choices[0].message.tool_calls is None

    def test_allowed_tool_passes(self):
        tc = _make_tool_call("search", {"query": "python docs"})
        response = _make_response(tc)
        client = _make_client(response)
        protected = protect(client, allow("search"))

        result = protected.chat.completions.create(model="gpt-4", messages=[])
        assert len(result.choices[0].message.tool_calls) == 1
        assert result.choices[0].message.tool_calls[0].function.name == "search"

    def test_blocked_tool_filtered(self):
        tc = _make_tool_call("delete_user", {"user_id": 123})
        response = _make_response(tc)
        client = _make_client(response)
        protected = protect(client, deny("delete_user"))

        result = protected.chat.completions.create(model="gpt-4", messages=[])
        assert result.choices[0].message.tool_calls is None
        assert result.choices[0].finish_reason == "stop"
        assert len(result._agsec_blocked) == 1
        assert result._agsec_blocked[0]["name"] == "delete_user"

    def test_mixed_tools(self):
        tc1 = _make_tool_call("search", {"query": "docs"}, "tc_1")
        tc2 = _make_tool_call("delete_user", {"id": 1}, "tc_2")
        response = _make_response(tc1, tc2)
        client = _make_client(response)
        protected = protect(client,
            allow("search"),
            deny("delete_user"),
        )

        result = protected.chat.completions.create(model="gpt-4", messages=[])
        assert len(result.choices[0].message.tool_calls) == 1
        assert result.choices[0].message.tool_calls[0].function.name == "search"
        assert len(result._agsec_blocked) == 1

    def test_conditional_block(self):
        tc = _make_tool_call("payment", {"amount": 50000})
        response = _make_response(tc)
        client = _make_client(response)
        protected = protect(client,
            deny("payment").when(param("amount") > 10000),
            allow("payment"),
        )

        result = protected.chat.completions.create(model="gpt-4", messages=[])
        assert result.choices[0].message.tool_calls is None
        assert result._agsec_blocked[0]["name"] == "payment"

    def test_conditional_allow(self):
        tc = _make_tool_call("payment", {"amount": 500})
        response = _make_response(tc)
        client = _make_client(response)
        protected = protect(client,
            deny("payment").when(param("amount") > 10000),
            allow("payment"),
        )

        result = protected.chat.completions.create(model="gpt-4", messages=[])
        assert len(result.choices[0].message.tool_calls) == 1

    def test_with_policy_dir(self, tmp_path):
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        (policy_dir / "policy.yaml").write_text("""
version: "1.0"
default: deny
statements:
  - sid: "DenyAll"
    effect: deny
    actions: ["tool.*"]
""")
        tc = _make_tool_call("search", {"query": "test"})
        response = _make_response(tc)
        client = _make_client(response)
        protected = protect(client, policy_dir=str(policy_dir))

        result = protected.chat.completions.create(model="gpt-4", messages=[])
        assert result.choices[0].message.tool_calls is None

    def test_review_treated_as_block(self):
        tc = _make_tool_call("send_email", {"to": "x@y.com"})
        response = _make_response(tc)
        client = _make_client(response)
        protected = protect(client, review("send_email"))

        result = protected.chat.completions.create(model="gpt-4", messages=[])
        assert result.choices[0].message.tool_calls is None
        assert result._agsec_blocked[0]["status"] == "review"
