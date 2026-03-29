"""Input normalization to prevent encoding bypasses.

Decodes common encodings (base64, unicode escapes, hex escapes)
before policy evaluation, so regex patterns catch obfuscated inputs.
"""

from __future__ import annotations

import base64
import binascii
import re


def normalize_value(value):
    """Normalize a string value by decoding common encodings.

    Returns original value if not a string or decoding fails.
    Non-destructive: only decodes if the result is valid printable text.
    """
    if not isinstance(value, str):
        return value

    normalized = value

    # Try unicode escapes (\u0052 -> R)
    if "\\u" in normalized:
        try:
            decoded = normalized.encode("utf-8").decode("unicode_escape")
            if decoded != normalized and decoded.isprintable():
                normalized = decoded
        except (UnicodeDecodeError, ValueError):
            pass

    # Try hex escapes (\x72 -> r)
    if "\\x" in normalized:
        try:
            decoded = normalized.encode("utf-8").decode("unicode_escape")
            if decoded != normalized and decoded.isprintable():
                normalized = decoded
        except (UnicodeDecodeError, ValueError):
            pass

    # Try base64 — only if the entire string looks like pure base64
    # (no spaces, only base64 chars, reasonable length)
    stripped = normalized.strip()
    if (
        len(stripped) >= 4
        and len(stripped) <= 1000
        and re.match(r"^[A-Za-z0-9+/=]+$", stripped)
    ):
        try:
            decoded = base64.b64decode(stripped, validate=True).decode("utf-8")
            if decoded.isprintable() and len(decoded) >= 2:
                normalized = decoded
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass

    return normalized
