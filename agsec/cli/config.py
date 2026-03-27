"""Config discovery for agsec CLI."""

from __future__ import annotations

import os


def find_policy_dir(start_dir: str | None = None) -> str:
    """Find the policies directory by walking up from start_dir.

    Search order:
    1. AGSEC_POLICY_DIR environment variable
    2. Walk up from start_dir looking for policies/ or .agsec/policies/
    """
    env_dir = os.environ.get("AGSEC_POLICY_DIR")
    if env_dir and os.path.isdir(env_dir):
        return os.path.abspath(env_dir)

    start = os.path.abspath(start_dir or os.getcwd())
    current = start
    for _ in range(20):
        for candidate in ("policies", os.path.join(".agsec", "policies")):
            path = os.path.join(current, candidate)
            if os.path.isdir(path):
                return path
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    raise FileNotFoundError(
        "No policies directory found. Run 'agsec init' to create one, "
        "or set AGSEC_POLICY_DIR environment variable."
    )


def get_audit_db_path() -> str:
    """Return path to the audit SQLite database."""
    env_path = os.environ.get("AGSEC_AUDIT_DB")
    if env_path:
        return env_path
    agsec_dir = os.path.join(os.path.expanduser("~"), ".agsec")
    os.makedirs(agsec_dir, exist_ok=True)
    return os.path.join(agsec_dir, "audit.db")


def get_templates_dir() -> str:
    """Return path to bundled policy templates."""
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates", "policies")
