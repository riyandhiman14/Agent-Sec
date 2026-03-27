"""agsec install — configure hooks for Claude Code or Codex."""

from __future__ import annotations

import json
import os
import shutil
import sys


def register(subparsers):
    p = subparsers.add_parser("install", help="Install agsec hooks for an agent platform")
    p.add_argument("platform", choices=["claude-code", "codex"], help="Target platform")
    p.add_argument("--project-dir", default=None, help="Project root (default: cwd)")
    p.set_defaults(func=run)


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

    if args.platform == "claude-code":
        _install_claude_code(project_dir)
    elif args.platform == "codex":
        _install_codex(project_dir)


def _install_claude_code(project_dir: str):
    claude_dir = os.path.join(project_dir, ".claude")
    os.makedirs(claude_dir, exist_ok=True)

    settings_path = os.path.join(claude_dir, "settings.json")
    agsec_cmd = _find_agsec_bin()

    # Find policies directory relative to project
    policy_dir = None
    for candidate in ("policies", os.path.join(".agsec", "policies")):
        if os.path.isdir(os.path.join(project_dir, candidate)):
            policy_dir = os.path.join(project_dir, candidate)
            break

    hook_command = f"{agsec_cmd} check --format=claude-code"
    if policy_dir:
        hook_command += f" --policy-dir {policy_dir}"

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
        print("agsec hook already installed in Claude Code.")
        print(f"  Config: {settings_path}")
        return

    pre_tool_hooks.append(new_hook)

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)

    print("agsec hook installed for Claude Code.")
    print(f"  Config: {settings_path}")
    print(f"  Hook: {hook_command}")
    print()
    print("The firewall is now active. Every tool call will be checked against your policies.")


def _install_codex(project_dir: str):
    # Codex uses ~/.codex/ or project-level config
    codex_dir = os.path.join(project_dir, ".codex")
    os.makedirs(codex_dir, exist_ok=True)

    hooks_path = os.path.join(codex_dir, "hooks.json")
    agsec_cmd = _find_agsec_bin()
    hook_command = f"{agsec_cmd} check --format=codex"

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
                        print("agsec hook already installed for Codex.")
                        print(f"  Config: {hooks_path}")
                        return
                existing.setdefault("hooks", []).append(hooks_config["hooks"][0])
                hooks_config = existing
            except json.JSONDecodeError:
                pass

    with open(hooks_path, "w") as f:
        json.dump(hooks_config, f, indent=2)

    print("agsec hook installed for Codex.")
    print(f"  Config: {hooks_path}")
    print(f"  Hook: {hook_command}")
