from __future__ import annotations

import asyncio
import logging
from functools import partial
from typing import Any, Callable, Dict, List, Optional

from .audit import AuditStore
from .exceptions import ActionExecutionError, ActionNotFoundError, PolicyViolationError
from .policy import PolicyEngine
from .registry import ActionRegistry
from .types import ActionExecutionResult, PolicyResult, PolicyStatus


class ControlLayer:
    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        action_registry: Optional[ActionRegistry] = None,
        logger: Optional[logging.Logger] = None,
        policy_dir: Optional[str] = None,
        policy_path: Optional[str] = None,
        audit_store: Optional[AuditStore] = None,
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        if policy_dir is not None:
            self.policy_engine.load_from_directory(policy_dir)
        elif policy_path is not None:
            self.policy_engine.load_from_file(policy_path)

        self.action_registry = action_registry or ActionRegistry()
        if audit_store is None:
            audit_store = AuditStore()
        self.audit_store = audit_store
        self.logger = logger or logging.getLogger("agsec")
        self.logger.setLevel(logging.DEBUG)

        # Hooks
        self._before_hooks: List[Callable] = []
        self._after_hooks: List[Callable] = []

    # -- Action registration --

    def register_action(self, name: str):
        def decorator(func):
            self.action_registry.register(name, func)
            return func
        return decorator

    # -- Hooks --

    def add_hook(self, event: str, fn: Callable) -> None:
        """Register a hook. Events: 'before_execute', 'after_execute'."""
        if event == "before_execute":
            self._before_hooks.append(fn)
        elif event == "after_execute":
            self._after_hooks.append(fn)
        else:
            raise ValueError(f"Unknown hook event: '{event}'. Use 'before_execute' or 'after_execute'.")

    def before_hook(self, fn: Callable) -> Callable:
        """Decorator to register a before_execute hook."""
        self._before_hooks.append(fn)
        return fn

    def after_hook(self, fn: Callable) -> Callable:
        """Decorator to register an after_execute hook."""
        self._after_hooks.append(fn)
        return fn

    async def _run_hooks(self, hooks: List[Callable], *args: Any) -> None:
        for hook in hooks:
            if asyncio.iscoroutinefunction(hook):
                await hook(*args)
            else:
                hook(*args)

    # -- Audit helper --

    def _safe_audit_log(
        self,
        exec_result: ActionExecutionResult,
        context: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Log to audit store, swallowing audit failures."""
        try:
            self.audit_store.log_execution(exec_result, context, error)
        except Exception as e:
            self.logger.error("Audit logging failed: %s", e)

    # -- Dry-run --

    async def dry_run(
        self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> PolicyResult:
        """Evaluate policy without executing the action. No audit logging."""
        return self.policy_engine.evaluate(action, params, context)

    def dry_run_sync(
        self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> PolicyResult:
        """Sync wrapper for dry_run."""
        return self.policy_engine.evaluate(action, params, context)

    # -- Execute --

    async def execute(
        self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> ActionExecutionResult:
        context = context or {}

        # Before hooks
        await self._run_hooks(self._before_hooks, action, params, context)

        # Policy evaluation
        try:
            policy: PolicyResult = self.policy_engine.evaluate(action, params, context)
        except Exception as e:
            self.logger.error("Policy evaluation failed for action=%s: %s", action, e)
            exec_result = ActionExecutionResult(
                action=action, params=params, result=None,
                policy=PolicyResult(status=PolicyStatus.BLOCK, reason="Policy evaluation error"),
            )
            self._safe_audit_log(exec_result, context, str(e))
            raise PolicyViolationError("Policy evaluation failed", action, "error") from e

        self.logger.info("Policy evaluation for action=%s -> %s", action, policy)

        # BLOCK
        if policy.status == PolicyStatus.BLOCK:
            self.logger.warning("Blocked action: %s, reason=%s", action, policy.reason)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            self._safe_audit_log(exec_result, context)
            raise PolicyViolationError(policy.reason, action, policy.status.value)

        # REVIEW
        if policy.status == PolicyStatus.REVIEW:
            self.logger.info("Action requires manual review: %s, reason=%s", action, policy.reason)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            self._safe_audit_log(exec_result, context)
            return exec_result

        # Unexpected status
        if policy.status != PolicyStatus.ALLOW:
            error_msg = f"Unexpected policy status: {policy.status}"
            self.logger.error(error_msg)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            self._safe_audit_log(exec_result, context, error_msg)
            raise PolicyViolationError(error_msg, action, policy.status.value)

        # Resolve action
        try:
            act = self.action_registry.get(action)
        except ActionNotFoundError as e:
            self.logger.error("Action not found: %s", action)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            self._safe_audit_log(exec_result, context, str(e))
            raise

        # Execute action
        try:
            if asyncio.iscoroutinefunction(act):
                result = await act(**params)
            else:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, partial(act, **params)
                )

            exec_result = ActionExecutionResult(action=action, params=params, result=result, policy=policy)
            self._safe_audit_log(exec_result, context)
            self.logger.info("Executed action: %s, result=%s", action, result)

            # After hooks
            await self._run_hooks(self._after_hooks, exec_result)

            return exec_result
        except Exception as e:
            self.logger.error("Action execution failed: %s, error=%s", action, e)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            self._safe_audit_log(exec_result, context, str(e))
            raise ActionExecutionError(action, e) from e

    def execute_sync(
        self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> ActionExecutionResult:
        """Sync wrapper around async execute for compatibility with non-async code."""
        try:
            return asyncio.run(self.execute(action, params, context))
        except RuntimeError as e:
            try:
                import nest_asyncio
                nest_asyncio.apply()
                return asyncio.run(self.execute(action, params, context))
            except Exception:
                raise RuntimeError(
                    "execute_sync cannot run because an event loop is already active"
                ) from e
