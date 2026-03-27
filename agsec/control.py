from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .audit import AuditStore
from .exceptions import ActionNotFoundError, PolicyViolationError
from .policy import PolicyEngine
from .registry import ActionRegistry
from .types import ActionExecutionResult, PolicyResult, PolicyStatus


class ControlLayer:
    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        action_registry: Optional[ActionRegistry] = None,
        logger: Optional[logging.Logger] = None,
        policy_yaml: Optional[str] = None,
        policy_yaml_path: Optional[str] = None,
        audit_store: Optional[AuditStore] = None,
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        if policy_yaml is not None:
            self.policy_engine.load_rules_from_yaml(policy_yaml)
        elif policy_yaml_path is not None:
            self.policy_engine.load_rules_from_yaml_file(policy_yaml_path)

        self.action_registry = action_registry or ActionRegistry()
        if audit_store is None:
            audit_store = AuditStore()
        self.audit_store = audit_store
        self.logger = logger or logging.getLogger("agsec")
        self.logger.setLevel(logging.DEBUG)

    def register_action(self, name: str):
        def decorator(func):
            self.action_registry.register(name, func)
            return func

        return decorator

    def execute(self, action: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> ActionExecutionResult:
        context = context or {}

        policy: PolicyResult = self.policy_engine.evaluate(action, params, context)
        self.logger.info(f"policy evaluation for action=%s -> %s", action, policy)

        if policy.status == PolicyStatus.BLOCK:
            self.logger.warning("Blocked action: %s, reason=%s", action, policy.reason)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            self.audit_store.log_execution(exec_result, context)
            raise PolicyViolationError(policy.reason)

        if policy.status == PolicyStatus.REVIEW:
            self.logger.info("Action requires manual review: %s, reason=%s", action, policy.reason)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            self.audit_store.log_execution(exec_result, context)
            return exec_result

        if policy.status != PolicyStatus.ALLOW:
            raise PolicyViolationError(f"Unexpected policy status: {policy.status}")

        try:
            act = self.action_registry.get(action)
        except ActionNotFoundError as exc:
            self.logger.error("Action not found: %s", action)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            self.audit_store.log_execution(exec_result, context, str(exc))
            raise

        try:
            result = act(**params)
            exec_result = ActionExecutionResult(action=action, params=params, result=result, policy=policy)
            self.audit_store.log_execution(exec_result, context)
            self.logger.info("Executed action: %s, result=%s", action, result)
            return exec_result
        except Exception as e:
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            self.audit_store.log_execution(exec_result, context, str(e))
            self.logger.error("Action execution failed: %s, error=%s", action, e)
            raise
