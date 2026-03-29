"""agsec Anthropic SDK integration — one-line client protection.

Usage:
    from anthropic import Anthropic
    from agsec.integrations.anthropic import protect, deny, param

    client = protect(Anthropic(),
        deny("delete_user"),
        deny("payment").when(param("amount") > 10000),
    )

Install: pip install agsec[anthropic]
"""

from __future__ import annotations

import json
from typing import Any, Optional

from ..types import PolicyStatus
from .conditions import (  # noqa: F401 — re-export
    ToolRule,
    allow,
    deny,
    param,
    review,
)
from ._base import build_engine, check_tool


class _GuardedAnthropicStream:
    """Wraps Anthropic stream, checks tool calls after completion.

    Yields all events transparently. After iteration completes,
    check ._agsec_blocked for any tool calls that violate policy.
    """

    def __init__(self, stream, engine):
        self._stream = stream
        self._engine = engine
        self._tool_blocks = {}
        self._current_index = -1
        self._agsec_blocked = []

    def __iter__(self):
        for event in self._stream:
            self._accumulate(event)
            yield event
        self._check_policy()

    def __enter__(self):
        if hasattr(self._stream, "__enter__"):
            self._stream.__enter__()
        return self

    def __exit__(self, *args):
        if hasattr(self._stream, "__exit__"):
            return self._stream.__exit__(*args)

    def _accumulate(self, event):
        event_type = getattr(event, "type", "")
        if event_type == "content_block_start":
            cb = getattr(event, "content_block", None)
            if cb and getattr(cb, "type", "") == "tool_use":
                self._current_index = getattr(event, "index", -1)
                self._tool_blocks[self._current_index] = {
                    "id": cb.id,
                    "name": cb.name,
                    "input_json": "",
                }
        elif event_type == "content_block_delta":
            delta = getattr(event, "delta", None)
            if delta and getattr(delta, "type", "") == "input_json_delta":
                idx = getattr(event, "index", self._current_index)
                if idx in self._tool_blocks:
                    self._tool_blocks[idx]["input_json"] += delta.partial_json

    def _check_policy(self):
        for idx, tb in self._tool_blocks.items():
            try:
                input_params = json.loads(tb["input_json"]) if tb["input_json"] else {}
            except (json.JSONDecodeError, TypeError):
                input_params = {}
            status, reason, metadata = check_tool(self._engine, tb["name"], input_params)
            if status != PolicyStatus.ALLOW:
                self._agsec_blocked.append({
                    "tool_use_id": tb["id"],
                    "name": tb["name"],
                    "status": status.value,
                    "reason": reason,
                    "sid": metadata.get("sid", ""),
                })


def protect(
    client: Any,
    *rules: ToolRule,
    policy_dir: Optional[str] = None,
    agent: Optional[str] = None,
) -> Any:
    """Wrap an Anthropic client with policy enforcement.

    Args:
        client: An Anthropic() client instance
        *rules: Inline rules (allow/deny/review)
        policy_dir: YAML policy directory
        agent: Agent name for policy overlay

    Returns:
        Wrapped client — use exactly like the original

    Example:
        client = protect(Anthropic(),
            deny("delete_user"),
            deny("payment").when(param("amount") > 10000),
        )
    """
    engine = build_engine(list(rules), policy_dir, agent)
    original_create = client.messages.create

    def wrapped_create(*args, **kwargs):
        if kwargs.get("stream", False):
            stream = original_create(*args, **kwargs)
            return _GuardedAnthropicStream(stream, engine)

        response = original_create(*args, **kwargs)

        # No content — pass through
        if not hasattr(response, "content") or not response.content:
            return response

        # Check each tool_use block
        allowed_content = []
        blocked = []

        for block in response.content:
            # Anthropic tool_use blocks have type="tool_use"
            if getattr(block, "type", None) == "tool_use":
                name = getattr(block, "name", "unknown")
                input_params = getattr(block, "input", {})
                status, reason, metadata = check_tool(engine, name, input_params)

                if status == PolicyStatus.ALLOW:
                    allowed_content.append(block)
                else:
                    blocked.append({
                        "tool_use_id": block.id,
                        "name": name,
                        "status": status.value,
                        "reason": reason,
                        "sid": metadata.get("sid", ""),
                    })
            else:
                # Text blocks and other content pass through
                allowed_content.append(block)

        if blocked:
            response._agsec_blocked = blocked
            response.content = allowed_content

            # If no tool_use blocks remain, update stop_reason
            has_tool_use = any(
                getattr(b, "type", None) == "tool_use" for b in allowed_content
            )
            if not has_tool_use:
                response.stop_reason = "end_turn"

        return response

    client.messages.create = wrapped_create
    return client
