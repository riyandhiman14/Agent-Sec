from __future__ import annotations

from typing import Any, Dict, Optional


class AgsecError(Exception):
    """Base exception for agsec errors."""
    def __init__(self, message: str, code: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


# Configuration Errors
class ConfigurationError(AgsecError):
    """Base class for configuration-related errors."""
    pass


class InvalidConfigError(ConfigurationError):
    """Raised when configuration is invalid."""
    def __init__(self, config_path: str, reason: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Invalid configuration in {config_path}: {reason}",
            code="INVALID_CONFIG",
            details={"config_path": config_path, "reason": reason, **(details or {})}
        )


class MissingConfigError(ConfigurationError):
    """Raised when required configuration is missing."""
    def __init__(self, missing_key: str, config_path: Optional[str] = None):
        message = f"Missing required configuration: {missing_key}"
        if config_path:
            message = f"Missing required configuration in {config_path}: {missing_key}"
        super().__init__(
            message,
            code="MISSING_CONFIG",
            details={"missing_key": missing_key, "config_path": config_path}
        )


class ConfigValidationError(ConfigurationError):
    """Raised when configuration validation fails."""
    def __init__(self, field: str, value: Any, expected: str, config_path: Optional[str] = None):
        super().__init__(
            f"Configuration validation failed for '{field}': expected {expected}, got {type(value).__name__}",
            code="CONFIG_VALIDATION_ERROR",
            details={"field": field, "value": value, "expected": expected, "config_path": config_path}
        )


# Registry Errors
class RegistryError(AgsecError):
    """Base class for action registry errors."""
    pass


class ActionNotFoundError(RegistryError):
    """Raised when an action is not registered."""
    def __init__(self, action: str, available_actions: Optional[list[str]] = None):
        super().__init__(
            f"Action '{action}' not registered",
            code="ACTION_NOT_FOUND",
            details={"action": action, "available_actions": available_actions}
        )


class DuplicateActionError(RegistryError):
    """Raised when attempting to register a duplicate action."""
    def __init__(self, action: str):
        super().__init__(
            f"Action '{action}' is already registered",
            code="DUPLICATE_ACTION",
            details={"action": action}
        )


class InvalidActionError(RegistryError):
    """Raised when an action definition is invalid."""
    def __init__(self, action: str, reason: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Invalid action '{action}': {reason}",
            code="INVALID_ACTION",
            details={"action": action, "reason": reason, **(details or {})}
        )


class RegistryFullError(RegistryError):
    """Raised when registry capacity is exceeded."""
    def __init__(self, max_actions: int, current_count: int):
        super().__init__(
            f"Registry capacity exceeded: {current_count}/{max_actions} actions",
            code="REGISTRY_FULL",
            details={"max_actions": max_actions, "current_count": current_count}
        )


# Policy Errors
class PolicyError(AgsecError):
    """Base class for policy-related errors."""
    pass


class PolicyParseError(PolicyError):
    """Raised when policy parsing fails."""
    def __init__(self, policy_path: str, parse_error: str, line: Optional[int] = None, column: Optional[int] = None):
        super().__init__(
            f"Failed to parse policy {policy_path}: {parse_error}",
            code="POLICY_PARSE_ERROR",
            details={"policy_path": policy_path, "parse_error": parse_error, "line": line, "column": column}
        )


class InvalidPolicyError(PolicyError):
    """Raised when policy structure is invalid."""
    def __init__(self, policy_id: str, reason: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Invalid policy '{policy_id}': {reason}",
            code="INVALID_POLICY",
            details={"policy_id": policy_id, "reason": reason, **(details or {})}
        )


class PolicyConflictError(PolicyError):
    """Raised when policies conflict."""
    def __init__(self, action: str, conflicting_policies: list[str], reason: str):
        super().__init__(
            f"Policy conflict for action '{action}': {reason}",
            code="POLICY_CONFLICT",
            details={"action": action, "conflicting_policies": conflicting_policies, "reason": reason}
        )


class PolicyTimeoutError(PolicyError):
    """Raised when policy evaluation times out."""
    def __init__(self, action: str, timeout_seconds: float):
        super().__init__(
            f"Policy evaluation timed out for action '{action}' after {timeout_seconds}s",
            code="POLICY_TIMEOUT",
            details={"action": action, "timeout_seconds": timeout_seconds}
        )


class PolicyViolationError(PolicyError):
    """Raised when a policy blocks an action."""
    def __init__(self, reason: str, action: str, policy_status: str, policy_id: Optional[str] = None, rule_id: Optional[str] = None):
        super().__init__(
            f"Policy violation: {reason}",
            code="POLICY_VIOLATION",
            details={"action": action, "policy_status": policy_status, "reason": reason, "policy_id": policy_id, "rule_id": rule_id}
        )


# Action Execution Errors
class ActionExecutionError(AgsecError):
    """Raised when action execution fails."""
    def __init__(self, action: str, original_error: Exception, params: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Action '{action}' execution failed: {str(original_error)}",
            code="ACTION_EXECUTION_ERROR",
            details={"action": action, "original_error": str(original_error), "error_type": type(original_error).__name__, "params": params}
        )
        self.original_error = original_error


# Audit Errors
class AuditError(AgsecError):
    """Base class for audit-related errors."""
    pass


class AuditConnectionError(AuditError):
    """Raised when audit store connection fails."""
    def __init__(self, store_type: str, connection_details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Failed to connect to {store_type} audit store",
            code="AUDIT_CONNECTION_ERROR",
            details={"store_type": store_type, "connection_details": connection_details}
        )


class AuditIntegrityError(AuditError):
    """Raised when audit log integrity is compromised."""
    def __init__(self, reason: str, record_id: Optional[str] = None):
        super().__init__(
            f"Audit log integrity violation: {reason}",
            code="AUDIT_INTEGRITY_ERROR",
            details={"reason": reason, "record_id": record_id}
        )


class AuditStorageError(AuditError):
    """Raised when audit storage fails."""
    def __init__(self, operation: str, reason: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Audit storage {operation} failed: {reason}",
            code="AUDIT_STORAGE_ERROR",
            details={"operation": operation, "reason": reason, **(details or {})}
        )


# Validation Errors
class ValidationError(AgsecError):
    """Base class for validation errors."""
    pass


class ParameterValidationError(ValidationError):
    """Raised when action parameters are invalid."""
    def __init__(self, action: str, param: str, value: Any, expected: str, reason: Optional[str] = None):
        super().__init__(
            f"Invalid parameter '{param}' for action '{action}': expected {expected}, got {type(value).__name__}",
            code="PARAMETER_VALIDATION_ERROR",
            details={"action": action, "param": param, "value": value, "expected": expected, "reason": reason}
        )


class TypeValidationError(ValidationError):
    """Raised when type validation fails."""
    def __init__(self, field: str, value: Any, expected_type: str, actual_type: str):
        super().__init__(
            f"Type validation failed for '{field}': expected {expected_type}, got {actual_type}",
            code="TYPE_VALIDATION_ERROR",
            details={"field": field, "value": value, "expected_type": expected_type, "actual_type": actual_type}
        )


class SchemaValidationError(ValidationError):
    """Raised when schema validation fails."""
    def __init__(self, schema_name: str, errors: list[str], data: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Schema validation failed for '{schema_name}': {', '.join(errors)}",
            code="SCHEMA_VALIDATION_ERROR",
            details={"schema_name": schema_name, "errors": errors, "data": data}
        )


# Security Errors
class SecurityError(AgsecError):
    """Base class for security-related errors."""
    pass


class SecurityViolationError(SecurityError):
    """Raised when a security policy is violated."""
    def __init__(self, violation_type: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Security violation: {violation_type}",
            code="SECURITY_VIOLATION",
            details={"violation_type": violation_type, **(details or {})}
        )


class TamperingError(SecurityError):
    """Raised when tampering is detected."""
    def __init__(self, component: str, evidence: str):
        super().__init__(
            f"Tampering detected in {component}: {evidence}",
            code="TAMPERING_DETECTED",
            details={"component": component, "evidence": evidence}
        )


class IntegrityError(SecurityError):
    """Raised when integrity checks fail."""
    def __init__(self, resource: str, expected_hash: str, actual_hash: str):
        super().__init__(
            f"Integrity check failed for {resource}",
            code="INTEGRITY_ERROR",
            details={"resource": resource, "expected_hash": expected_hash, "actual_hash": actual_hash}
        )


# Initialization Errors
class InitializationError(AgsecError):
    """Base class for initialization errors."""
    pass


class DependencyError(InitializationError):
    """Raised when required dependencies are missing."""
    def __init__(self, dependency: str, version_required: Optional[str] = None, version_found: Optional[str] = None):
        message = f"Missing dependency: {dependency}"
        if version_required:
            message += f" (required: {version_required})"
        if version_found:
            message += f" (found: {version_found})"
        super().__init__(
            message,
            code="DEPENDENCY_ERROR",
            details={"dependency": dependency, "version_required": version_required, "version_found": version_found}
        )


class EnvironmentError(InitializationError):
    """Raised when environment configuration is invalid."""
    def __init__(self, variable: str, reason: str):
        super().__init__(
            f"Environment configuration error for {variable}: {reason}",
            code="ENVIRONMENT_ERROR",
            details={"variable": variable, "reason": reason}
        )


# Runtime Errors
class RuntimeError(AgsecError):
    """Base class for runtime errors."""
    pass


class TimeoutError(RuntimeError):
    """Raised when operations timeout."""
    def __init__(self, operation: str, timeout_seconds: float):
        super().__init__(
            f"Operation '{operation}' timed out after {timeout_seconds}s",
            code="TIMEOUT_ERROR",
            details={"operation": operation, "timeout_seconds": timeout_seconds}
        )


class ResourceError(RuntimeError):
    """Raised when resources are exhausted."""
    def __init__(self, resource: str, limit: Any, current: Any):
        super().__init__(
            f"Resource '{resource}' exhausted: limit={limit}, current={current}",
            code="RESOURCE_ERROR",
            details={"resource": resource, "limit": limit, "current": current}
        )


class ConcurrencyError(RuntimeError):
    """Raised when concurrent access conflicts occur."""
    def __init__(self, operation: str, reason: str, conflicting_operations: Optional[list[str]] = None):
        super().__init__(
            f"Concurrency conflict in '{operation}': {reason}",
            code="CONCURRENCY_ERROR",
            details={"operation": operation, "reason": reason, "conflicting_operations": conflicting_operations}
        )
