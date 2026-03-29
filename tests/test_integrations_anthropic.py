"""Tests for Anthropic SDK integration (mocked, no API calls)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agsec.integrations.anthropic import protect
from agsec.integrations._base import build_engine, check_tool
from agsec.integrations.conditions import allow, deny, review, param
from agsec.types import PolicyStatus


def _make_tool_use(name, input_params, block_id="tu_1"):
    """Create a mock Anthropic ToolUseBlock."""
    block = SimpleNamespace()
    block.type = "tool_use"
    block.id = block_id
    block.name = name
    block.input = input_params
    return block


def _make_text_block(text):
    """Create a mock Anthropic TextBlock."""
    block = SimpleNamespace()
    block.type = "text"
    block.text = text
    return block


def _make_response(*content_blocks):
    """Create a mock Anthropic Message response."""
    response = SimpleNamespace()
    response.id = "msg_test"
    response.model = "claude-sonnet-4-20250514"
    response.content = list(content_blocks)
    response.stop_reason = "tool_use" if any(
        getattr(b, "type", None) == "tool_use" for b in content_blocks
    ) else "end_turn"
    response.role = "assistant"
    return response


def _make_client(response):
    """Create a mock Anthropic client."""
    client = MagicMock()
    client.messages.create = MagicMock(return_value=response)
    return client


class TestCheckToolUse:
    def test_allowed(self):
        engine = build_engine([allow("search")])
        status, _, _ = check_tool(engine, "search", {"query": "test"})
        assert status == PolicyStatus.ALLOW

    def test_blocked(self):
        engine = build_engine([deny("delete_user")])
        status, _, _ = check_tool(engine, "delete_user", {})
        assert status == PolicyStatus.BLOCK

    def test_conditional(self):
        engine = build_engine([
            deny("payment").when(param("amount") > 10000),
            allow("payment"),
        ])
        status, _, _ = check_tool(engine, "payment", {"amount": 500})
        assert status == PolicyStatus.ALLOW

        status, _, _ = check_tool(engine, "payment", {"amount": 50000})
        assert status == PolicyStatus.BLOCK


class TestProtect:
    def test_no_tools_passthrough(self):
        text = _make_text_block("Hello!")
        response = _make_response(text)
        client = _make_client(response)
        protected = protect(client, allow("search"))

        result = protected.messages.create(model="claude-sonnet-4-20250514", messages=[])
        assert len(result.content) == 1
        assert result.content[0].type == "text"

    def test_allowed_tool_passes(self):
        tu = _make_tool_use("search", {"query": "docs"})
        response = _make_response(tu)
        client = _make_client(response)
        protected = protect(client, allow("search"))

        result = protected.messages.create(model="claude-sonnet-4-20250514", messages=[])
        assert len(result.content) == 1
        assert result.content[0].name == "search"

    def test_blocked_tool_filtered(self):
        tu = _make_tool_use("delete_user", {"id": 123})
        response = _make_response(tu)
        client = _make_client(response)
        protected = protect(client, deny("delete_user"))

        result = protected.messages.create(model="claude-sonnet-4-20250514", messages=[])
        assert len(result.content) == 0
        assert result.stop_reason == "end_turn"
        assert len(result._agsec_blocked) == 1

    def test_text_preserved_when_tool_blocked(self):
        text = _make_text_block("Let me delete that for you.")
        tu = _make_tool_use("delete_user", {"id": 1})
        response = _make_response(text, tu)
        client = _make_client(response)
        protected = protect(client, deny("delete_user"))

        result = protected.messages.create(model="claude-sonnet-4-20250514", messages=[])
        assert len(result.content) == 1
        assert result.content[0].type == "text"
        assert len(result._agsec_blocked) == 1

    def test_mixed_tools(self):
        tu1 = _make_tool_use("search", {"query": "docs"}, "tu_1")
        tu2 = _make_tool_use("delete_user", {"id": 1}, "tu_2")
        response = _make_response(tu1, tu2)
        client = _make_client(response)
        protected = protect(client,
            allow("search"),
            deny("delete_user"),
        )

        result = protected.messages.create(model="claude-sonnet-4-20250514", messages=[])
        tool_uses = [b for b in result.content if b.type == "tool_use"]
        assert len(tool_uses) == 1
        assert tool_uses[0].name == "search"
        assert len(result._agsec_blocked) == 1

    def test_conditional_block(self):
        tu = _make_tool_use("payment", {"amount": 50000})
        response = _make_response(tu)
        client = _make_client(response)
        protected = protect(client,
            deny("payment").when(param("amount") > 10000),
            allow("payment"),
        )

        result = protected.messages.create(model="claude-sonnet-4-20250514", messages=[])
        assert len(result.content) == 0
        assert result._agsec_blocked[0]["name"] == "payment"

    def test_conditional_allow(self):
        tu = _make_tool_use("payment", {"amount": 500})
        response = _make_response(tu)
        client = _make_client(response)
        protected = protect(client,
            deny("payment").when(param("amount") > 10000),
            allow("payment"),
        )

        result = protected.messages.create(model="claude-sonnet-4-20250514", messages=[])
        assert len(result.content) == 1
        assert result.content[0].name == "payment"

    def test_review_treated_as_block(self):
        tu = _make_tool_use("send_email", {"to": "x@y.com"})
        response = _make_response(tu)
        client = _make_client(response)
        protected = protect(client, review("send_email"))

        result = protected.messages.create(model="claude-sonnet-4-20250514", messages=[])
        assert len(result.content) == 0
        assert result._agsec_blocked[0]["status"] == "review"


# ---------------------------------------------------------------------------
# Streaming tests
# ---------------------------------------------------------------------------


def _make_stream_event(event_type, **kwargs):
    """Create a mock Anthropic stream event."""
    event = SimpleNamespace()
    event.type = event_type
    for k, v in kwargs.items():
        setattr(event, k, v)
    return event


def _make_content_block_start(index, name, block_id="tu_1"):
    cb = SimpleNamespace()
    cb.type = "tool_use"
    cb.id = block_id
    cb.name = name
    cb.input = {}
    return _make_stream_event("content_block_start", index=index, content_block=cb)


def _make_input_json_delta(index, partial_json):
    delta = SimpleNamespace()
    delta.type = "input_json_delta"
    delta.partial_json = partial_json
    return _make_stream_event("content_block_delta", index=index, delta=delta)


def _make_content_block_stop(index):
    return _make_stream_event("content_block_stop", index=index)


def _make_stream_client_anthropic(events):
    client = MagicMock()
    client.messages.create = MagicMock(return_value=iter(events))
    return client


class TestStreaming:
    def test_streaming_returns_guarded_stream(self):
        events = [_make_stream_event("message_start")]
        client = _make_stream_client_anthropic(events)
        protected = protect(client, allow("search"))

        result = protected.messages.create(model="claude-sonnet-4-20250514", messages=[], stream=True)
        assert hasattr(result, "_agsec_blocked")

    def test_streaming_events_yielded_unchanged(self):
        events = [
            _make_stream_event("message_start"),
            _make_stream_event("message_stop"),
        ]
        client = _make_stream_client_anthropic(events)
        protected = protect(client, allow("search"))

        stream = protected.messages.create(model="claude-sonnet-4-20250514", messages=[], stream=True)
        received = list(stream)
        assert len(received) == 2
        assert received[0].type == "message_start"
        assert received[1].type == "message_stop"

    def test_streaming_allowed_tool_not_blocked(self):
        events = [
            _make_content_block_start(0, "search", "tu_1"),
            _make_input_json_delta(0, '{"query": "test"}'),
            _make_content_block_stop(0),
        ]
        client = _make_stream_client_anthropic(events)
        protected = protect(client, allow("search"))

        stream = protected.messages.create(model="claude-sonnet-4-20250514", messages=[], stream=True)
        list(stream)
        assert stream._agsec_blocked == []

    def test_streaming_blocked_tool_detected(self):
        events = [
            _make_content_block_start(0, "delete_user", "tu_1"),
            _make_input_json_delta(0, '{"id": '),
            _make_input_json_delta(0, '123}'),
            _make_content_block_stop(0),
        ]
        client = _make_stream_client_anthropic(events)
        protected = protect(client, deny("delete_user"))

        stream = protected.messages.create(model="claude-sonnet-4-20250514", messages=[], stream=True)
        list(stream)
        assert len(stream._agsec_blocked) == 1
        assert stream._agsec_blocked[0]["name"] == "delete_user"
        assert stream._agsec_blocked[0]["tool_use_id"] == "tu_1"

    def test_streaming_mixed_tools(self):
        events = [
            _make_content_block_start(0, "search", "tu_1"),
            _make_input_json_delta(0, '{"query": "test"}'),
            _make_content_block_stop(0),
            _make_content_block_start(1, "delete_user", "tu_2"),
            _make_input_json_delta(1, '{"id": 1}'),
            _make_content_block_stop(1),
        ]
        client = _make_stream_client_anthropic(events)
        protected = protect(client, allow("search"), deny("delete_user"))

        stream = protected.messages.create(model="claude-sonnet-4-20250514", messages=[], stream=True)
        list(stream)
        assert len(stream._agsec_blocked) == 1
        assert stream._agsec_blocked[0]["name"] == "delete_user"
