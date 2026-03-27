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

from ..policy import PolicyEngine
from ..types import PolicyStatus
from .conditions import (  # noqa: F401 — re-export
    ToolRule,
    allow,
    compile_rules,
    deny,
    param,
    review,
)
from ._base import PolicyChecker, _get_agent_policy_dir


def _build_engine(rules, policy_dir=None, agent=None):
    """Build a PolicyEngine from inline rules + optional YAML."""
    engine = PolicyEngine(default="deny")
    engine._iam_loaded = True

    if rules:
        for stmt in compile_rules(rules):
            engine.add_statement(stmt)

    if policy_dir:
        try:
            engine.load_from_directory(policy_dir)
        except (ValueError, FileNotFoundError):
            pass

    if agent:
        agent_dir = _get_agent_policy_dir(agent)
        if agent_dir:
            try:
                engine.load_from_directory(agent_dir)
            except (ValueError, FileNotFoundError):
                pass

    return engine


def _check_tool_call(engine, name, arguments):
    """Check a single tool call against policies. Returns (status, reason)."""
    action = f"tool.{name}"
    params = {}
    if isinstance(arguments, str):
        try:
            params = json.loads(arguments)
        except (json.JSONDecodeError, TypeError):
            params = {}
    elif isinstance(arguments, dict):
        params = arguments

    result = engine.evaluate(action, params)
    return result.status, result.reason, result.metadata


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
    engine = _build_engine(list(rules), policy_dir, agent)
    original_create = client.chat.completions.create

    def wrapped_create(*args, **kwargs):
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
            func_name = tc.function.name
            func_args = tc.function.arguments
            status, reason, metadata = _check_tool_call(engine, func_name, func_args)

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
