"""agsec install — configure hooks for Claude Code or Codex."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys

from ..output import error, info, success, warn


def register(subparsers):
    p = subparsers.add_parser("install", help="Install agsec hooks for an agent platform")
    p.add_argument("platform", choices=["claude-code", "codex", "cursor", "windsurf", "cline", "copilot"], help="Target platform")
    p.add_argument("--project-dir", default=None, help="Project root (default: cwd)")
    p.set_defaults(func=run)


def register_uninstall(subparsers):
    p = subparsers.add_parser("uninstall", help="Remove agsec hooks from an agent platform")
    p.add_argument("platform", choices=["claude-code", "codex", "cursor", "windsurf", "cline", "copilot"], help="Target platform")
    p.add_argument("--project-dir", default=None, help="Project root (default: cwd)")
    p.set_defaults(func=run_uninstall)


def _find_agsec_bin() -> str:
    """Find the full path to the agsec executable."""
    # Check if running as console script
    agsec_bin = shutil.which("agsec")
    if agsec_bin:
        return agsec_bin
    # Fallback: use python -m
    return f"{sys.executable} -m agsec.cli.main"


def run(args):
    project_dir = os.path.abspath(args.project_dir or os.getcwd())
    installers = {
        "claude-code": _install_claude_code,
        "codex": _install_codex,
        "cursor": _install_cursor,
        "windsurf": _install_windsurf,
        "cline": _install_cline,
        "copilot": _install_copilot,
    }
    installers[args.platform](project_dir)


def _install_claude_code(project_dir: str):
    claude_dir = os.path.join(project_dir, ".claude")
    os.makedirs(claude_dir, mode=0o700, exist_ok=True)

    settings_path = os.path.join(claude_dir, "settings.json")
    agsec_cmd = _find_agsec_bin()

    # Find policies directory relative to project
    policy_dir = None
    for candidate in ("policies", os.path.join(".agsec", "policies")):
        if os.path.isdir(os.path.join(project_dir, candidate)):
            policy_dir = os.path.join(project_dir, candidate)
            break

    hook_command = f"{agsec_cmd} check --format=claude-code --agent claude-code"
    if policy_dir:
        hook_command += f" --policy-dir {shlex.quote(policy_dir)}"

    new_hook = {
        "matcher": "",
        "hooks": [
            {
                "type": "command",
                "command": hook_command,
                "timeout": 30,
            }
        ],
    }

    # Load existing settings or start fresh
    settings = {}
    if os.path.isfile(settings_path):
        with open(settings_path, "r") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}

    # Merge hooks — don't duplicate
    hooks = settings.setdefault("hooks", {})
    pre_tool_hooks = hooks.setdefault("PreToolUse", [])

    # Check if agsec hook already installed
    already_installed = any(
        "agsec" in str(h.get("hooks", [{}])[0].get("command", "")) if isinstance(h, dict) else False
        for h in pre_tool_hooks
    )

    if already_installed:
        warn("agsec hook already installed in Claude Code.")
        info(f"  Config: {settings_path}")
        return

    pre_tool_hooks.append(new_hook)

    fd = os.open(settings_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(settings, f, indent=2)

    success("agsec hook installed for Claude Code.")
    info(f"  Config: {settings_path}")
    info(f"  Hook: {hook_command}")
    info("The firewall is now active. Every tool call will be checked against your policies.")


def _install_codex(project_dir: str):
    # Codex uses ~/.codex/ or project-level config
    codex_dir = os.path.join(project_dir, ".codex")
    os.makedirs(codex_dir, mode=0o700, exist_ok=True)

    hooks_path = os.path.join(codex_dir, "hooks.json")
    agsec_cmd = _find_agsec_bin()
    hook_command = f"{agsec_cmd} check --format=codex --agent codex"

    hooks_config = {
        "hooks": [
            {
                "event": "PreToolUse",
                "command": hook_command,
            }
        ]
    }

    if os.path.isfile(hooks_path):
        with open(hooks_path, "r") as f:
            try:
                existing = json.load(f)
                # Check if already installed
                for h in existing.get("hooks", []):
                    if "agsec" in h.get("command", ""):
                        warn("agsec hook already installed for Codex.")
                        info(f"  Config: {hooks_path}")
                        return
                existing.setdefault("hooks", []).append(hooks_config["hooks"][0])
                hooks_config = existing
            except json.JSONDecodeError:
                pass

    fd = os.open(hooks_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(hooks_config, f, indent=2)

    success("agsec hook installed for Codex.")
    info(f"  Config: {hooks_path}")
    info(f"  Hook: {hook_command}")


# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------


def run_uninstall(args):
    project_dir = os.path.abspath(args.project_dir or os.getcwd())
    uninstallers = {
        "claude-code": _uninstall_claude_code,
        "codex": _uninstall_codex,
        "cursor": _uninstall_cursor,
        "windsurf": _uninstall_windsurf,
        "cline": _uninstall_cline,
        "copilot": _uninstall_copilot,
    }
    uninstallers[args.platform](project_dir)


def _uninstall_claude_code(project_dir: str):
    settings_path = os.path.join(project_dir, ".claude", "settings.json")

    if not os.path.isfile(settings_path):
        warn("agsec is not installed for Claude Code (no settings.json found).")
        return

    with open(settings_path, "r") as f:
        try:
            settings = json.load(f)
        except json.JSONDecodeError:
            error("Could not read settings.json.")
            return

    hooks = settings.get("hooks", {})
    pre_tool_hooks = hooks.get("PreToolUse", [])

    # Filter out agsec hooks
    filtered = [
        h for h in pre_tool_hooks
        if not (isinstance(h, dict) and "agsec" in str(h.get("hooks", [{}])[0].get("command", "")))
    ]

    if len(filtered) == len(pre_tool_hooks):
        warn("agsec is not installed for Claude Code.")
        return

    # Clean up empty structures
    if filtered:
        hooks["PreToolUse"] = filtered
    else:
        hooks.pop("PreToolUse", None)

    if hooks:
        settings["hooks"] = hooks
    else:
        settings.pop("hooks", None)

    fd = os.open(settings_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(settings, f, indent=2)

    success("agsec hook removed from Claude Code.")
    info(f"  Config: {settings_path}")
    info("  Restart Claude Code for changes to take effect.")


def _uninstall_codex(project_dir: str):
    hooks_path = os.path.join(project_dir, ".codex", "hooks.json")

    if not os.path.isfile(hooks_path):
        warn("agsec is not installed for Codex (no hooks.json found).")
        return

    with open(hooks_path, "r") as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError:
            error("Could not read hooks.json.")
            return

    hooks_list = config.get("hooks", [])
    filtered = [h for h in hooks_list if "agsec" not in h.get("command", "")]

    if len(filtered) == len(hooks_list):
        warn("agsec is not installed for Codex.")
        return

    config["hooks"] = filtered

    fd = os.open(hooks_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(config, f, indent=2)

    success("agsec hook removed from Codex.")
    info(f"  Config: {hooks_path}")


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------


def _install_cursor(project_dir: str):
    cursor_dir = os.path.join(project_dir, ".cursor")
    os.makedirs(cursor_dir, mode=0o700, exist_ok=True)

    hooks_path = os.path.join(cursor_dir, "hooks.json")
    agsec_cmd = _find_agsec_bin()
    policy_dir = _find_policy_dir(project_dir)

    hook_command = f"{agsec_cmd} check --format=cursor --agent cursor"
    if policy_dir:
        hook_command += f" --policy-dir {shlex.quote(policy_dir)}"

    hook_entry = {"command": hook_command}

    config = {"version": 1, "hooks": {}}
    if os.path.isfile(hooks_path):
        with open(hooks_path, "r") as f:
            try:
                config = json.load(f)
            except json.JSONDecodeError:
                config = {"version": 1, "hooks": {}}

    hooks = config.setdefault("hooks", {})
    shell_hooks = hooks.setdefault("beforeShellExecution", [])

    if any("agsec" in h.get("command", "") for h in shell_hooks):
        warn("agsec hook already installed for Cursor.")
        return

    shell_hooks.append(hook_entry)

    _write_json(hooks_path, config)
    success("agsec hook installed for Cursor.")
    info(f"  Config: {hooks_path}")


def _uninstall_cursor(project_dir: str):
    hooks_path = os.path.join(project_dir, ".cursor", "hooks.json")
    _uninstall_json_hooks(hooks_path, "Cursor", "beforeShellExecution")


# ---------------------------------------------------------------------------
# Windsurf
# ---------------------------------------------------------------------------


def _install_windsurf(project_dir: str):
    windsurf_dir = os.path.join(project_dir, ".windsurf")
    os.makedirs(windsurf_dir, mode=0o700, exist_ok=True)

    settings_path = os.path.join(windsurf_dir, "settings.json")
    agsec_cmd = _find_agsec_bin()
    policy_dir = _find_policy_dir(project_dir)

    hook_command = f"{agsec_cmd} check --format=windsurf --agent windsurf"
    if policy_dir:
        hook_command += f" --policy-dir {shlex.quote(policy_dir)}"

    new_hook = {
        "matcher": "",
        "hooks": [{"type": "command", "command": hook_command, "timeout": 30}],
    }

    settings = {}
    if os.path.isfile(settings_path):
        with open(settings_path, "r") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}

    hooks = settings.setdefault("hooks", {})
    pre_hooks = hooks.setdefault("PreToolUse", [])

    if any("agsec" in str(h) for h in pre_hooks):
        warn("agsec hook already installed for Windsurf.")
        return

    pre_hooks.append(new_hook)

    _write_json(settings_path, settings)
    success("agsec hook installed for Windsurf.")
    info(f"  Config: {settings_path}")


def _uninstall_windsurf(project_dir: str):
    settings_path = os.path.join(project_dir, ".windsurf", "settings.json")
    _uninstall_settings_hooks(settings_path, "Windsurf")


# ---------------------------------------------------------------------------
# Cline
# ---------------------------------------------------------------------------


def _install_cline(project_dir: str):
    hooks_dir = os.path.join(project_dir, ".clinerules", "hooks")
    os.makedirs(hooks_dir, mode=0o700, exist_ok=True)

    script_path = os.path.join(hooks_dir, "agsec-check.sh")
    agsec_cmd = _find_agsec_bin()
    policy_dir = _find_policy_dir(project_dir)

    cmd = f"{agsec_cmd} check --format=cline --agent cline"
    if policy_dir:
        cmd += f" --policy-dir {shlex.quote(policy_dir)}"

    if os.path.isfile(script_path):
        warn("agsec hook already installed for Cline.")
        return

    script = f"""#!/bin/bash
# agsec firewall hook for Cline
{cmd}
"""
    fd = os.open(script_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
    with os.fdopen(fd, "w") as f:
        f.write(script)

    success("agsec hook installed for Cline.")
    info(f"  Script: {script_path}")


def _uninstall_cline(project_dir: str):
    script_path = os.path.join(project_dir, ".clinerules", "hooks", "agsec-check.sh")

    if not os.path.isfile(script_path):
        warn("agsec is not installed for Cline.")
        return

    os.unlink(script_path)
    success("agsec hook removed from Cline.")
    info(f"  Removed: {script_path}")


# ---------------------------------------------------------------------------
# GitHub Copilot
# ---------------------------------------------------------------------------


def _install_copilot(project_dir: str):
    """Install hooks for GitHub Copilot.

    Two locations:
    - Project-level: .github/hooks/ (for cloud coding agent, must be committed)
    - User-level: ~/.copilot/hooks/ (for local VS Code Copilot)

    Note: VS Code Copilot also reads .claude/settings.json, so
    'agsec install claude-code' already covers local VS Code Copilot.
    This install is primarily for the cloud coding agent.
    """
    agsec_cmd = _find_agsec_bin()
    policy_dir = _find_policy_dir(project_dir)

    cmd = f"{agsec_cmd} check --format=copilot --agent copilot"
    if policy_dir:
        cmd += f" --policy-dir {shlex.quote(policy_dir)}"

    # Install to project .github/hooks/ (for cloud coding agent)
    project_hooks_dir = os.path.join(project_dir, ".github", "hooks")
    os.makedirs(project_hooks_dir, mode=0o700, exist_ok=True)

    hooks_path = os.path.join(project_hooks_dir, "hooks.json")

    hook_entry = {
        "type": "command",
        "bash": cmd,
        "timeoutSec": 30,
        "comment": "agsec firewall",
    }

    config = {"version": 1, "hooks": {}}
    if os.path.isfile(hooks_path):
        with open(hooks_path, "r") as f:
            try:
                config = json.load(f)
            except json.JSONDecodeError:
                config = {"version": 1, "hooks": {}}

    hooks = config.setdefault("hooks", {})
    pre_hooks = hooks.setdefault("preToolUse", [])

    if any("agsec" in str(h.get("bash", "")) for h in pre_hooks):
        warn("agsec hook already installed for GitHub Copilot.")
        return

    pre_hooks.append(hook_entry)

    _write_json(hooks_path, config)

    # Also install to ~/.copilot/hooks/ for local VS Code Copilot
    user_hooks_dir = os.path.join(os.path.expanduser("~"), ".copilot", "hooks")
    os.makedirs(user_hooks_dir, mode=0o700, exist_ok=True)
    user_hooks_path = os.path.join(user_hooks_dir, "hooks.json")
    _write_json(user_hooks_path, config)

    success("agsec hook installed for GitHub Copilot.")
    info(f"  Project: {hooks_path} (commit and push for cloud agent)")
    info(f"  User:    {user_hooks_path} (local VS Code)")
    info("  Note: 'agsec install claude-code' also covers VS Code Copilot")
    info("  since VS Code reads .claude/settings.json hooks.")


def _uninstall_copilot(project_dir: str):
    removed = False

    # Remove from project .github/hooks/
    project_path = os.path.join(project_dir, ".github", "hooks", "hooks.json")
    if os.path.isfile(project_path):
        if _remove_agsec_from_hooks_file(project_path):
            info(f"  Removed from: {project_path}")
            removed = True

    # Remove from ~/.copilot/hooks/
    user_path = os.path.join(os.path.expanduser("~"), ".copilot", "hooks", "hooks.json")
    if os.path.isfile(user_path):
        if _remove_agsec_from_hooks_file(user_path):
            info(f"  Removed from: {user_path}")
            removed = True

    if removed:
        success("agsec hook removed from GitHub Copilot.")
    else:
        warn("agsec is not installed for GitHub Copilot.")


def _remove_agsec_from_hooks_file(path: str) -> bool:
    """Remove agsec hooks from a hooks.json file. Returns True if modified."""
    with open(path, "r") as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError:
            return False

    pre_hooks = config.get("hooks", {}).get("preToolUse", [])
    filtered = [h for h in pre_hooks if "agsec" not in str(h.get("bash", ""))]

    if len(filtered) == len(pre_hooks):
        return False

    if filtered:
        config["hooks"]["preToolUse"] = filtered
    else:
        config.get("hooks", {}).pop("preToolUse", None)

    _write_json(path, config)
    return True


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _find_policy_dir(project_dir: str):
    """Find policy directory in project."""
    for candidate in ("policies", os.path.join(".agsec", "policies")):
        if os.path.isdir(os.path.join(project_dir, candidate)):
            return os.path.join(project_dir, candidate)
    return None


def _write_json(path: str, data: dict):
    """Write JSON with restricted permissions."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)


def _uninstall_json_hooks(hooks_path: str, name: str, hook_key: str):
    """Remove agsec hooks from a JSON hooks file with a list under hook_key."""
    if not os.path.isfile(hooks_path):
        warn(f"agsec is not installed for {name}.")
        return

    with open(hooks_path, "r") as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError:
            error(f"Could not read {os.path.basename(hooks_path)}.")
            return

    hooks_list = config.get("hooks", {}).get(hook_key, [])
    filtered = [h for h in hooks_list if "agsec" not in h.get("command", "")]

    if len(filtered) == len(hooks_list):
        warn(f"agsec is not installed for {name}.")
        return

    config["hooks"][hook_key] = filtered
    _write_json(hooks_path, config)
    success(f"agsec hook removed from {name}.")
    info(f"  Config: {hooks_path}")


def _uninstall_settings_hooks(settings_path: str, name: str):
    """Remove agsec hooks from a settings.json with PreToolUse structure."""
    if not os.path.isfile(settings_path):
        warn(f"agsec is not installed for {name}.")
        return

    with open(settings_path, "r") as f:
        try:
            settings = json.load(f)
        except json.JSONDecodeError:
            error(f"Could not read {os.path.basename(settings_path)}.")
            return

    hooks = settings.get("hooks", {})
    pre_hooks = hooks.get("PreToolUse", [])
    filtered = [h for h in pre_hooks if "agsec" not in str(h)]

    if len(filtered) == len(pre_hooks):
        warn(f"agsec is not installed for {name}.")
        return

    if filtered:
        hooks["PreToolUse"] = filtered
    else:
        hooks.pop("PreToolUse", None)

    if hooks:
        settings["hooks"] = hooks
    else:
        settings.pop("hooks", None)

    _write_json(settings_path, settings)
    success(f"agsec hook removed from {name}.")
    info(f"  Config: {settings_path}")
