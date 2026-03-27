from __future__ import annotations

from typing import Any, Dict, Optional

from .base import AgsecError


class AuditError(AgsecError):
    """Base class for audit-related errors."""
    pass


class AuditConnectionError(AuditError):
    def __init__(self, store_type: str, connection_details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Failed to connect to {store_type} audit store",
            code="AUDIT_CONNECTION_ERROR",
            details={"store_type": store_type, "connection_details": connection_details}
        )


class AuditIntegrityError(AuditError):
    def __init__(self, reason: str, record_id: Optional[str] = None):
        super().__init__(
            f"Audit log integrity violation: {reason}",
            code="AUDIT_INTEGRITY_ERROR",
            details={"reason": reason, "record_id": record_id}
        )


class AuditStorageError(AuditError):
    def __init__(self, operation: str, reason: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            f"Audit storage {operation} failed: {reason}",
            code="AUDIT_STORAGE_ERROR",
            details={"operation": operation, "reason": reason, **(details or {})}
        )
