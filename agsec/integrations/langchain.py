"""agsec LangChain integration — fluent policy API.

Usage:
    from agsec.integrations.langchain import guard, allow, deny, review, param

    agent = create_react_agent(llm, guard(
        allow(search, calculator),
        review(send_email),
        deny(delete_record),
        deny(payment).when(param("amount") > 10000),
    ))

Install: pip install agsec[langchain]
"""

from __future__ import annotations

from typing import Any, List, Optional, Type

try:
    from langchain_core.callbacks import (
        AsyncCallbackManagerForToolRun,
        CallbackManagerForToolRun,
    )
    from langchain_core.tools import BaseTool
except ImportError:
    raise ImportError(
        "LangChain integration requires langchain-core. "
        "Install it with: pip install agsec[langchain]"
    )

from pydantic import BaseModel

from ..exceptions import PolicyViolationError
from ..policy import PolicyEngine
from ..policy.statement import Statement
from ..types import PolicyResult, PolicyStatus
from ._base import PolicyChecker
from .conditions import Condition, param  # noqa: F401 — re-export for users


# ---------------------------------------------------------------------------
# Effect helpers
# ---------------------------------------------------------------------------


class ToolRule:
    """One or more tools with an effect and optional conditions."""

    def __init__(self, *tools: BaseTool, effect: str):
        self.tools: tuple[BaseTool, ...] = tools
        self.effect: str = effect
        self.conditions: list[Condition] = []

    def when(self, *conditions: Condition) -> ToolRule:
        """Add conditions to this rule. Returns self for chaining."""
        self.conditions.extend(conditions)
        return self


def allow(*tools: BaseTool) -> ToolRule:
    """Mark tools as allowed."""
    return ToolRule(*tools, effect="allow")


def deny(*tools: BaseTool) -> ToolRule:
    """Mark tools as denied (blocked)."""
    return ToolRule(*tools, effect="deny")


def review(*tools: BaseTool) -> ToolRule:
    """Mark tools as requiring human review."""
    return ToolRule(*tools, effect="review")


# ---------------------------------------------------------------------------
# Compile rules → PolicyEngine statements
# ---------------------------------------------------------------------------

_EFFECT_TO_STATUS = {
    "allow": PolicyStatus.ALLOW,
    "deny": PolicyStatus.BLOCK,
    "review": PolicyStatus.REVIEW,
}


def _compile_rules(rules: list[ToolRule]) -> list[Statement]:
    """Convert ToolRules into PolicyEngine Statement objects."""
    statements = []
    for rule in rules:
        effect = _EFFECT_TO_STATUS[rule.effect]
        tool_names = [f"tool.{t.name}" for t in rule.tools]

        # Merge conditions
        conditions = {}
        for cond in rule.conditions:
            conditions.update(cond.to_dict())

        sid_parts = [rule.effect.title()]
        if len(rule.tools) == 1:
            sid_parts.append(rule.tools[0].name.title())
        else:
            sid_parts.append(f"{len(rule.tools)}Tools")

        statements.append(Statement(
            sid="_".join(sid_parts),
            effect=effect,
            actions=tool_names,
            conditions=conditions,
            reason=f"{rule.effect} by inline policy",
        ))

    return statements


# ---------------------------------------------------------------------------
# GuardedTool
# ---------------------------------------------------------------------------


class GuardedTool(BaseTool):
    """A LangChain tool wrapped with agsec policy enforcement."""

    name: str = ""
    description: str = ""
    args_schema: Optional[Type[BaseModel]] = None
    return_direct: bool = False

    model_config = {"arbitrary_types_allowed": True}

    wrapped_tool: BaseTool
    engine: PolicyEngine
    action_name: str = ""

    def __init__(self, wrapped_tool: BaseTool, engine: PolicyEngine, **kwargs: Any):
        super().__init__(
            wrapped_tool=wrapped_tool,
            engine=engine,
            name=wrapped_tool.name,
            description=wrapped_tool.description,
            args_schema=wrapped_tool.args_schema,
            return_direct=getattr(wrapped_tool, "return_direct", False),
            action_name=f"tool.{wrapped_tool.name}",
            **kwargs,
        )

    def _check(self, kwargs: dict) -> None:
        result = self.engine.evaluate(self.action_name, kwargs)
        if result.status == PolicyStatus.BLOCK:
            raise PolicyViolationError(
                result.reason, self.action_name, result.status.value,
                policy_id=result.metadata.get("sid"),
            )
        if result.status == PolicyStatus.REVIEW:
            raise PolicyViolationError(
                f"[REVIEW REQUIRED] {result.reason}",
                self.action_name, result.status.value,
                policy_id=result.metadata.get("sid"),
            )

    def _run(
        self,
        *args: Any,
        run_manager: Optional[CallbackManagerForToolRun] = None,
        **kwargs: Any,
    ) -> Any:
        self._check(kwargs)
        return self.wrapped_tool._run(*args, run_manager=run_manager, **kwargs)

    async def _arun(
        self,
        *args: Any,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
        **kwargs: Any,
    ) -> Any:
        self._check(kwargs)
        return await self.wrapped_tool._arun(*args, run_manager=run_manager, **kwargs)


# ---------------------------------------------------------------------------
# guard() — main entry point
# ---------------------------------------------------------------------------


def guard(
    *args: Any,
    agent: Optional[str] = None,
    policy_dir: Optional[str] = None,
    audit: bool = True,
) -> List[BaseTool]:
    """Wrap LangChain tools with policy enforcement.

    Accepts a mix of bare tools (default: allow) and rules:

        guard(
            allow(search, calculator),
            review(send_email),
            deny(delete_record),
            deny(payment).when(param("amount") > 10000),
        )

    Args:
        *args: BaseTool instances or ToolRule objects
        agent: Agent name for agent-specific policy overlay
        policy_dir: YAML policy directory (overrides inline rules for deny)
        audit: Enable audit logging

    Returns:
        List of wrapped BaseTool instances
    """
    # 1. Collect all tools and rules
    rules: list[ToolRule] = []
    all_tools: dict[str, BaseTool] = {}  # name → tool (dedup)

    for arg in args:
        if isinstance(arg, ToolRule):
            rules.append(arg)
            for tool in arg.tools:
                all_tools[tool.name] = tool
        elif isinstance(arg, BaseTool):
            # Bare tool = allow
            rules.append(ToolRule(arg, effect="allow"))
            all_tools[arg.name] = arg
        else:
            raise TypeError(
                f"guard() accepts BaseTool or ToolRule (from allow/deny/review), "
                f"got {type(arg).__name__}"
            )

    # 2. Build PolicyEngine with inline statements
    engine = PolicyEngine(default="deny")
    engine._iam_loaded = True  # enable IAM evaluation mode

    statements = _compile_rules(rules)
    for stmt in statements:
        engine.add_statement(stmt)

    # 3. Load YAML policies if provided (deny from YAML overrides inline allow)
    if policy_dir:
        try:
            engine.load_from_directory(policy_dir)
        except (ValueError, FileNotFoundError):
            pass

    # 4. Load agent overlay if specified
    if agent:
        from ._base import _get_agent_policy_dir
        agent_dir = _get_agent_policy_dir(agent)
        if agent_dir:
            try:
                engine.load_from_directory(agent_dir)
            except (ValueError, FileNotFoundError):
                pass

    # 5. Wrap each tool
    return [
        GuardedTool(wrapped_tool=tool, engine=engine)
        for tool in all_tools.values()
    ]
