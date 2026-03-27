"""Map agent tool calls to agsec policy actions."""

from __future__ import annotations

from typing import Any, Dict, Tuple

TOOL_ACTION_MAP = {
    "Bash": "bash.execute",
    "Edit": "file.edit",
    "Write": "file.write",
    "Read": "file.read",
    "WebFetch": "web.fetch",
    "WebSearch": "web.search",
    "Glob": "file.glob",
    "Grep": "file.grep",
    "Agent": "agent.spawn",
    "NotebookEdit": "notebook.edit",
}


def map_tool_to_action(tool_name: str, tool_input: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Map an agent tool call to an agsec (action, params) pair.

    Args:
        tool_name: The tool name from the hook (e.g., "Bash", "Edit", "mcp__github__create_issue")
        tool_input: The tool arguments dict

    Returns:
        Tuple of (action_name, params_dict) for policy evaluation
    """
    # MCP tools: mcp__server__tool -> mcp.server.tool
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__")
        action = "mcp." + ".".join(parts[1:])
        return action, dict(tool_input)

    action = TOOL_ACTION_MAP.get(tool_name, f"unknown.{tool_name}")
    return action, dict(tool_input)
