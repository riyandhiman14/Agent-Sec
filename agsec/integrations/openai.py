"""agsec OpenAI SDK integration — one-line client protection.

Works with OpenAI, OpenRouter, Groq, Together, Fireworks —
anything using the OpenAI-compatible API format.

Usage:
    from openai import OpenAI
    from agsec.integrations.openai import protect, deny, param

    client = protect(OpenAI(),
        deny("delete_user"),
        deny("payment").when(param("amount") > 10000),
    )

Install: pip install agsec[openai]
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


class _GuardedStream:
    """Wraps OpenAI Stream, checks tool calls after completion.

    Yields all chunks transparently. After iteration completes,
    check ._agsec_blocked for any tool calls that violate policy.
    """

    def __init__(self, stream, engine):
        self._stream = stream
        self._engine = engine
        self._accumulated = {}
        self._agsec_blocked = []

    def __iter__(self):
        for chunk in self._stream:
            self._accumulate(chunk)
            yield chunk
        self._check_policy()

    def __enter__(self):
        if hasattr(self._stream, "__enter__"):
            self._stream.__enter__()
        return self

    def __exit__(self, *args):
        if hasattr(self._stream, "__exit__"):
            return self._stream.__exit__(*args)

    @property
    def response(self):
        return getattr(self._stream, "response", None)

    def _accumulate(self, chunk):
        if not hasattr(chunk, "choices") or not chunk.choices:
            return
        delta = chunk.choices[0].delta if hasattr(chunk.choices[0], "delta") else None
        if not delta:
            return
        tool_calls = getattr(delta, "tool_calls", None)
        if not tool_calls:
            return
        for tc in tool_calls:
            idx = tc.index
            if idx not in self._accumulated:
                self._accumulated[idx] = {"id": "", "name": "", "arguments": ""}
            if tc.id:
                self._accumulated[idx]["id"] = tc.id
            if tc.function:
                if tc.function.name:
                    self._accumulated[idx]["name"] = tc.function.name
                if tc.function.arguments:
                    self._accumulated[idx]["arguments"] += tc.function.arguments

    def _check_policy(self):
        for idx, tc in self._accumulated.items():
            status, reason, metadata = check_tool(self._engine, tc["name"], tc["arguments"])
            if status != PolicyStatus.ALLOW:
                self._agsec_blocked.append({
                    "tool_call_id": tc["id"],
                    "name": tc["name"],
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
    """Wrap an OpenAI-compatible client with policy enforcement.

    Works with OpenAI, OpenRouter, Groq, Together, Fireworks —
    anything that uses client.chat.completions.create().

    Args:
        client: An OpenAI() client instance
        *rules: Inline rules (allow/deny/review)
        policy_dir: YAML policy directory
        agent: Agent name for policy overlay

    Returns:
        Wrapped client — use exactly like the original

    Example:
        client = protect(OpenAI(),
            deny("delete_user"),
            deny("payment").when(param("amount") > 10000),
        )
    """
    engine = build_engine(list(rules), policy_dir, agent)
    original_create = client.chat.completions.create

    def wrapped_create(*args, **kwargs):
        if kwargs.get("stream", False):
            stream = original_create(*args, **kwargs)
            return _GuardedStream(stream, engine)

        response = original_create(*args, **kwargs)

        # No tool calls — pass through
        if not hasattr(response, "choices") or not response.choices:
            return response

        choice = response.choices[0]
        if not hasattr(choice, "message") or not choice.message:
            return response
        if not hasattr(choice.message, "tool_calls") or not choice.message.tool_calls:
            return response

        # Check each tool call
        allowed_calls = []
        blocked = []

        for tc in choice.message.tool_calls:
            try:
                func_name = tc.function.name
                func_args = tc.function.arguments
            except AttributeError:
                # Malformed tool call — block safely
                blocked.append({
                    "tool_call_id": getattr(tc, "id", "unknown"),
                    "name": "unknown",
                    "status": "block",
                    "reason": "Malformed tool call",
                    "sid": "",
                })
                continue
            status, reason, metadata = check_tool(engine, func_name, func_args)

            if status == PolicyStatus.ALLOW:
                allowed_calls.append(tc)
            else:
                blocked.append({
                    "tool_call_id": tc.id,
                    "name": func_name,
                    "status": status.value,
                    "reason": reason,
                    "sid": metadata.get("sid", ""),
                })

        if blocked:
            # Store blocked info on the response for the caller
            response._agsec_blocked = blocked

            # Filter to only allowed calls
            choice.message.tool_calls = allowed_calls if allowed_calls else None

            # If all tools were blocked, change finish_reason
            if not allowed_calls:
                choice.finish_reason = "stop"

        return response

    client.chat.completions.create = wrapped_create
    return client
