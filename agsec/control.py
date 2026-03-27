from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .audit import AuditStore
from .audit import AuditStore
from .exceptions import ActionExecutionError, ActionNotFoundError, AuditError, PolicyViolationError
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

        try:
            policy: PolicyResult = self.policy_engine.evaluate(action, params, context)
        except Exception as e:
            self.logger.error("Policy evaluation failed for action=%s: %s", action, e)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=PolicyResult(status=PolicyStatus.BLOCK, reason="Policy evaluation error"))
            try:
                self.audit_store.log_execution(exec_result, context, str(e))
            except Exception as audit_e:
                self.logger.error("Audit logging failed: %s", audit_e)
            raise PolicyViolationError("Policy evaluation failed", action, "error") from e

        self.logger.info("Policy evaluation for action=%s -> %s", action, policy)

        if policy.status == PolicyStatus.BLOCK:
            self.logger.warning("Blocked action: %s, reason=%s", action, policy.reason)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            try:
                self.audit_store.log_execution(exec_result, context)
            except Exception as e:
                self.logger.error("Audit logging failed: %s", e)
            raise PolicyViolationError(policy.reason, action, policy.status.value)

        if policy.status == PolicyStatus.REVIEW:
            self.logger.info("Action requires manual review: %s, reason=%s", action, policy.reason)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            try:
                self.audit_store.log_execution(exec_result, context)
            except Exception as e:
                self.logger.error("Audit logging failed: %s", e)
            return exec_result

        if policy.status != PolicyStatus.ALLOW:
            error_msg = f"Unexpected policy status: {policy.status}"
            self.logger.error(error_msg)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            try:
                self.audit_store.log_execution(exec_result, context, error_msg)
            except Exception as e:
                self.logger.error("Audit logging failed: %s", e)
            raise PolicyViolationError(error_msg, action, policy.status.value)

        try:
            act = self.action_registry.get(action)
        except ActionNotFoundError as e:
            self.logger.error("Action not found: %s", action)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            try:
                self.audit_store.log_execution(exec_result, context, str(e))
            except Exception as audit_e:
                self.logger.error("Audit logging failed: %s", audit_e)
            raise

        try:
            result = act(**params)
            exec_result = ActionExecutionResult(action=action, params=params, result=result, policy=policy)
            try:
                self.audit_store.log_execution(exec_result, context)
            except Exception as e:
                self.logger.error("Audit logging failed: %s", e)
            self.logger.info("Executed action: %s, result=%s", action, result)
            return exec_result
        except Exception as e:
            self.logger.error("Action execution failed: %s, error=%s", action, e)
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=policy)
            try:
                self.audit_store.log_execution(exec_result, context, str(e))
            except Exception as audit_e:
                self.logger.error("Audit logging failed: %s", audit_e)
            raise ActionExecutionError(action, e) from e
