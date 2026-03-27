from __future__ import annotations

from typing import Any, Dict, Optional


class AgsecError(Exception):
    """Base exception for agsec errors."""
    def __init__(self, message: str, code: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}
