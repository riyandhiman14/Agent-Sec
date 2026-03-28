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

from ..types import PolicyStatus
from .conditions import (  # noqa: F401 — re-export
    ToolRule,
    allow,
    deny,
    param,
    review,
)
from ._base import build_engine, check_tool


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
            raise NotImplementedError(
                "agsec does not yet support streaming responses. "
                "Use stream=False or call the original client directly."
            )

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
