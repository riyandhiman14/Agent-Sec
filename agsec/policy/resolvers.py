from __future__ import annotations

from typing import Any, Dict, List, Optional

from .normalizers import normalize_value


def _deep_get(obj: Any, keys: List[str]) -> Any:
    """Walk a nested dict by key path. Returns None if any segment is missing."""
    for key in keys:
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return None
    return obj


def _resolve_value(key: str, params: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Any:
    """Resolve a dotted key like 'params.user.address.country' from params or context.

    String values are normalized to decode common encodings (base64, unicode, hex)
    before being returned, preventing policy bypass via obfuscation.
    """
    parts = key.split(".")

    if parts[0] == "params":
        return normalize_value(_deep_get(params, parts[1:]))
    if parts[0] == "context":
        return normalize_value(_deep_get(context or {}, parts[1:]))

    # Legacy: bare key — try params first, then context
    result = _deep_get(params, parts)
    if result is not None:
        return normalize_value(result)
    if context:
        return normalize_value(_deep_get(context, parts))
    return None
