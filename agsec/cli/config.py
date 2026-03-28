"""Config discovery for agsec CLI."""

from __future__ import annotations

import os

import yaml

CONFIG_FILENAME = ".agsec.yaml"


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


def find_config_path(start_dir: str | None = None) -> str | None:
    """Find .agsec.yaml config file by walking up from start_dir."""
    env_mode = os.environ.get("AGSEC_MODE")
    if env_mode:
        return None  # env var overrides file

    start = os.path.abspath(start_dir or os.getcwd())
    current = start
    for _ in range(20):
        path = os.path.join(current, CONFIG_FILENAME)
        if os.path.isfile(path):
            return path
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


VALID_MODES = ("observe", "enforce", "halt")


def load_mode(start_dir: str | None = None) -> str:
    """Return 'observe', 'enforce', or 'halt'. Default: 'enforce'."""
    # Env var takes priority
    env_mode = os.environ.get("AGSEC_MODE")
    if env_mode in VALID_MODES:
        return env_mode

    config_path = find_config_path(start_dir)
    if config_path:
        try:
            with open(config_path, "r") as f:
                doc = yaml.safe_load(f) or {}
            return doc.get("mode", "enforce")
        except Exception:
            pass
    return "enforce"


def set_mode(mode: str, start_dir: str | None = None, store_previous: bool = False) -> str:
    """Write mode to .agsec.yaml. Returns path of config file.

    If store_previous=True, saves the current mode as previous_mode (used by halt/resume).
    """
    config_path = find_config_path(start_dir)
    if config_path:
        try:
            with open(config_path, "r") as f:
                doc = yaml.safe_load(f) or {}
        except Exception:
            doc = {}
        if store_previous:
            doc["previous_mode"] = doc.get("mode", "enforce")
        doc["mode"] = mode
        with open(config_path, "w") as f:
            yaml.dump(doc, f, default_flow_style=False, sort_keys=False)
        return config_path

    # No config file found — create one in cwd
    config_path = os.path.join(os.getcwd(), CONFIG_FILENAME)
    doc = {"mode": mode}
    if store_previous:
        doc["previous_mode"] = "enforce"
    with open(config_path, "w") as f:
        yaml.dump(doc, f, default_flow_style=False, sort_keys=False)
    return config_path


def get_previous_mode(start_dir: str | None = None) -> str:
    """Return the mode that was active before halt. Default: 'enforce'."""
    config_path = find_config_path(start_dir)
    if config_path:
        try:
            with open(config_path, "r") as f:
                doc = yaml.safe_load(f) or {}
            return doc.get("previous_mode", "enforce")
        except Exception:
            pass
    return "enforce"
