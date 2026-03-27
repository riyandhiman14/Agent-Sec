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
from ._base import _get_agent_policy_dir


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


def _check_tool_use(engine, name, input_params):
    """Check a single tool_use block against policies."""
    action = f"tool.{name}"
    params = input_params if isinstance(input_params, dict) else {}
    result = engine.evaluate(action, params)
    return result.status, result.reason, result.metadata


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
    engine = _build_engine(list(rules), policy_dir, agent)
    original_create = client.messages.create

    def wrapped_create(*args, **kwargs):
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
                name = block.name
                input_params = getattr(block, "input", {})
                status, reason, metadata = _check_tool_use(engine, name, input_params)

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
