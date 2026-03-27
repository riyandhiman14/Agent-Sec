"""Tests for Anthropic SDK integration (mocked, no API calls)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agsec.integrations.anthropic import protect, _check_tool_use, _build_engine
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
        engine = _build_engine([allow("search")])
        status, _, _ = _check_tool_use(engine, "search", {"query": "test"})
        assert status == PolicyStatus.ALLOW

    def test_blocked(self):
        engine = _build_engine([deny("delete_user")])
        status, _, _ = _check_tool_use(engine, "delete_user", {})
        assert status == PolicyStatus.BLOCK

    def test_conditional(self):
        engine = _build_engine([
            deny("payment").when(param("amount") > 10000),
            allow("payment"),
        ])
        status, _, _ = _check_tool_use(engine, "payment", {"amount": 500})
        assert status == PolicyStatus.ALLOW

        status, _, _ = _check_tool_use(engine, "payment", {"amount": 50000})
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
