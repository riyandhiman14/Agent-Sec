"""Tests for OpenAI SDK integration (mocked, no API calls)."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agsec.integrations.openai import protect
from agsec.integrations._base import build_engine, check_tool
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
        engine = build_engine([allow("search")])
        status, reason, meta = check_tool(engine, "search", '{"query": "test"}')
        assert status == PolicyStatus.ALLOW

    def test_blocked(self):
        engine = build_engine([deny("delete_user")])
        status, reason, meta = check_tool(engine, "delete_user", '{}')
        assert status == PolicyStatus.BLOCK

    def test_default_deny(self):
        engine = build_engine([allow("search")])
        status, _, _ = check_tool(engine, "unknown_tool", '{}')
        assert status == PolicyStatus.BLOCK

    def test_conditional_deny(self):
        engine = build_engine([
            deny("payment").when(param("amount") > 10000),
            allow("payment"),
        ])
        # Small amount — allowed
        status, _, _ = check_tool(engine, "payment", '{"amount": 500}')
        assert status == PolicyStatus.ALLOW

        # Large amount — blocked
        status, _, _ = check_tool(engine, "payment", '{"amount": 50000}')
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


# ---------------------------------------------------------------------------
# Streaming tests
# ---------------------------------------------------------------------------


def _make_stream_chunk(tool_calls=None, finish_reason=None, content=None):
    """Create a mock OpenAI streaming chunk."""
    delta = SimpleNamespace()
    delta.tool_calls = tool_calls
    delta.content = content
    delta.role = None

    choice = SimpleNamespace()
    choice.delta = delta
    choice.finish_reason = finish_reason
    choice.index = 0

    chunk = SimpleNamespace()
    chunk.choices = [choice]
    chunk.id = "chatcmpl-stream"
    return chunk


def _make_tool_call_delta(index, tc_id=None, name=None, arguments=None):
    """Create a mock tool call delta for streaming."""
    tc = SimpleNamespace()
    tc.index = index
    tc.id = tc_id
    tc.function = SimpleNamespace()
    tc.function.name = name
    tc.function.arguments = arguments
    return tc


def _make_stream_client(chunks):
    """Create a mock client that returns an iterable stream."""
    client = MagicMock()
    client.chat.completions.create = MagicMock(return_value=iter(chunks))
    return client


class TestStreaming:
    def test_streaming_returns_guarded_stream(self):
        chunks = [_make_stream_chunk(content="hello")]
        client = _make_stream_client(chunks)
        protected = protect(client, allow("search"))

        result = protected.chat.completions.create(model="gpt-4", messages=[], stream=True)
        # Should not raise NotImplementedError
        assert hasattr(result, "_agsec_blocked")

    def test_streaming_chunks_yielded_unchanged(self):
        chunks = [
            _make_stream_chunk(content="hello"),
            _make_stream_chunk(content=" world"),
        ]
        client = _make_stream_client(chunks)
        protected = protect(client, allow("search"))

        stream = protected.chat.completions.create(model="gpt-4", messages=[], stream=True)
        received = list(stream)
        assert len(received) == 2
        assert received[0].choices[0].delta.content == "hello"
        assert received[1].choices[0].delta.content == " world"

    def test_streaming_allowed_tool_not_blocked(self):
        chunks = [
            _make_stream_chunk(tool_calls=[_make_tool_call_delta(0, tc_id="tc_1", name="search", arguments='{"qu')]),
            _make_stream_chunk(tool_calls=[_make_tool_call_delta(0, arguments='ery": "test"}')]),
            _make_stream_chunk(finish_reason="tool_calls"),
        ]
        client = _make_stream_client(chunks)
        protected = protect(client, allow("search"))

        stream = protected.chat.completions.create(model="gpt-4", messages=[], stream=True)
        received = list(stream)
        assert len(received) == 3
        assert stream._agsec_blocked == []

    def test_streaming_blocked_tool_detected(self):
        chunks = [
            _make_stream_chunk(tool_calls=[_make_tool_call_delta(0, tc_id="tc_1", name="delete_user", arguments='{"id')]),
            _make_stream_chunk(tool_calls=[_make_tool_call_delta(0, arguments='": 123}')]),
            _make_stream_chunk(finish_reason="tool_calls"),
        ]
        client = _make_stream_client(chunks)
        protected = protect(client, deny("delete_user"))

        stream = protected.chat.completions.create(model="gpt-4", messages=[], stream=True)
        list(stream)  # consume
        assert len(stream._agsec_blocked) == 1
        assert stream._agsec_blocked[0]["name"] == "delete_user"
        assert stream._agsec_blocked[0]["tool_call_id"] == "tc_1"

    def test_streaming_mixed_tools(self):
        chunks = [
            _make_stream_chunk(tool_calls=[_make_tool_call_delta(0, tc_id="tc_1", name="search", arguments='{"query": "test"}')]),
            _make_stream_chunk(tool_calls=[_make_tool_call_delta(1, tc_id="tc_2", name="delete_user", arguments='{"id": 1}')]),
            _make_stream_chunk(finish_reason="tool_calls"),
        ]
        client = _make_stream_client(chunks)
        protected = protect(client, allow("search"), deny("delete_user"))

        stream = protected.chat.completions.create(model="gpt-4", messages=[], stream=True)
        list(stream)
        assert len(stream._agsec_blocked) == 1
        assert stream._agsec_blocked[0]["name"] == "delete_user"
