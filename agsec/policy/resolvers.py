from __future__ import annotations

from typing import Any, Dict, List, Optional


def _deep_get(obj: Any, keys: List[str]) -> Any:
    """Walk a nested dict by key path. Returns None if any segment is missing."""
    for key in keys:
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return None
    return obj


def _resolve_value(key: str, params: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Any:
    """Resolve a dotted key like 'params.user.address.country' from params or context."""
    parts = key.split(".")

    if parts[0] == "params":
        return _deep_get(params, parts[1:])
    if parts[0] == "context":
        return _deep_get(context or {}, parts[1:])

    # Legacy: bare key — try params first, then context
    result = _deep_get(params, parts)
    if result is not None:
        return result
    if context:
        return _deep_get(context, parts)
    return None
