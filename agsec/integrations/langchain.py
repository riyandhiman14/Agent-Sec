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
from ..types import PolicyStatus
from .conditions import (  # noqa: F401 — re-export for users
    ToolRule,
    allow,
    compile_rules,
    deny,
    param,
    review,
)


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
    """
    rules: list[ToolRule] = []
    all_tools: dict[str, BaseTool] = {}

    for arg in args:
        if isinstance(arg, ToolRule):
            rules.append(arg)
            for item in arg.names:
                if isinstance(item, BaseTool):
                    all_tools[item.name] = item
        elif isinstance(arg, BaseTool):
            rules.append(ToolRule(arg, effect="allow"))
            all_tools[arg.name] = arg
        else:
            raise TypeError(
                f"guard() accepts BaseTool or ToolRule (from allow/deny/review), "
                f"got {type(arg).__name__}"
            )

    # Build engine
    engine = PolicyEngine(default="deny")
    engine._iam_loaded = True

    for stmt in compile_rules(rules):
        engine.add_statement(stmt)

    if policy_dir:
        try:
            engine.load_from_directory(policy_dir)
        except (ValueError, FileNotFoundError):
            pass

    if agent:
        from ._base import _get_agent_policy_dir
        agent_dir = _get_agent_policy_dir(agent)
        if agent_dir:
            try:
                engine.load_from_directory(agent_dir)
            except (ValueError, FileNotFoundError):
                pass

    return [
        GuardedTool(wrapped_tool=tool, engine=engine)
        for tool in all_tools.values()
    ]
