from __future__ import annotations

from typing import Any, Dict, Optional

from .base import AgsecError


# Configuration Errors

class ConfigurationError(AgsecError):
    """Base class for configuration-related errors."""
    pass


class InvalidConfigError(ConfigurationError):
    def __init__(self, config_path: str, reason: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Invalid configuration in {config_path}: {reason}",
            code="INVALID_CONFIG",
            details={"config_path": config_path, "reason": reason, **(details or {})}
        )


class MissingConfigError(ConfigurationError):
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
    def __init__(self, field: str, value: Any, expected: str, config_path: Optional[str] = None):
        super().__init__(
            f"Configuration validation failed for '{field}': expected {expected}, got {type(value).__name__}",
            code="CONFIG_VALIDATION_ERROR",
            details={"field": field, "value": value, "expected": expected, "config_path": config_path}
        )


# Validation Errors

class ValidationError(AgsecError):
    """Base class for validation errors."""
    pass


class ParameterValidationError(ValidationError):
    def __init__(self, action: str, param: str, value: Any, expected: str, reason: Optional[str] = None):
        super().__init__(
            f"Invalid parameter '{param}' for action '{action}': expected {expected}, got {type(value).__name__}",
            code="PARAMETER_VALIDATION_ERROR",
            details={"action": action, "param": param, "value": value, "expected": expected, "reason": reason}
        )


class TypeValidationError(ValidationError):
    def __init__(self, field: str, value: Any, expected_type: str, actual_type: str):
        super().__init__(
            f"Type validation failed for '{field}': expected {expected_type}, got {actual_type}",
            code="TYPE_VALIDATION_ERROR",
            details={"field": field, "value": value, "expected_type": expected_type, "actual_type": actual_type}
        )


class SchemaValidationError(ValidationError):
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
    def __init__(self, violation_type: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Security violation: {violation_type}",
            code="SECURITY_VIOLATION",
            details={"violation_type": violation_type, **(details or {})}
        )


class TamperingError(SecurityError):
    def __init__(self, component: str, evidence: str):
        super().__init__(
            f"Tampering detected in {component}: {evidence}",
            code="TAMPERING_DETECTED",
            details={"component": component, "evidence": evidence}
        )


class IntegrityError(SecurityError):
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
    def __init__(self, operation: str, timeout_seconds: float):
        super().__init__(
            f"Operation '{operation}' timed out after {timeout_seconds}s",
            code="TIMEOUT_ERROR",
            details={"operation": operation, "timeout_seconds": timeout_seconds}
        )


class ResourceError(RuntimeError):
    def __init__(self, resource: str, limit: Any, current: Any):
        super().__init__(
            f"Resource '{resource}' exhausted: limit={limit}, current={current}",
            code="RESOURCE_ERROR",
            details={"resource": resource, "limit": limit, "current": current}
        )


class ConcurrencyError(RuntimeError):
    def __init__(self, operation: str, reason: str, conflicting_operations: Optional[list[str]] = None):
        super().__init__(
            f"Concurrency conflict in '{operation}': {reason}",
            code="CONCURRENCY_ERROR",
            details={"operation": operation, "reason": reason, "conflicting_operations": conflicting_operations}
        )
