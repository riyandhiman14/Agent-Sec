"""agsec status — show current firewall state at a glance."""

from __future__ import annotations

import glob
import json
import os
import sys

from ... import __version__
from ...audit import AuditStore
from ..config import find_policy_dir, get_audit_db_path, load_mode
from ..output import error, heading, info, panel, plain, print_mode, success, table


def register(subparsers):
    p = subparsers.add_parser("status", help="Show current firewall status")
    p.set_defaults(func=run)


def run(args):
    lines = []

    # Version
    lines.append(f"agsec v{__version__}")
    lines.append("")

    # Mode
    mode = load_mode()
    mode_display = mode.upper()
    if mode == "halt":
        mode_display += " (all actions blocked)"
    elif mode == "observe":
        mode_display += " (logging only, not blocking)"
    elif mode == "enforce":
        mode_display += " (active)"
    lines.append(f"  Mode:       {mode_display}")

    # Installed platforms
    platforms = _detect_platforms()
    if platforms:
        lines.append(f"  Platforms:  {', '.join(platforms)}")
    else:
        lines.append("  Platforms:  none installed")

    # Policies
    try:
        policy_dir = find_policy_dir()
        files = sorted(
            glob.glob(os.path.join(policy_dir, "*.yaml"))
            + glob.glob(os.path.join(policy_dir, "*.yml"))
        )
        # Count statements
        stmt_count = 0
        for f in files:
            with open(f, "r") as fh:
                import yaml
                parsed = yaml.safe_load(fh.read())
                if isinstance(parsed, dict) and "statements" in parsed:
                    stmts = parsed.get("statements", [])
                    if isinstance(stmts, list):
                        stmt_count += len(stmts)
        lines.append(f"  Policies:   {len(files)} files, {stmt_count} statements")
    except (FileNotFoundError, Exception):
        lines.append("  Policies:   not configured (run `agsec init`)")

    # Audit stats
    try:
        audit = AuditStore(get_audit_db_path())
        stats = audit.get_execution_stats()
        total = stats.get("total_executions", 0)
        blocked = stats.get("blocked", 0)
        if total > 0:
            if mode == "observe":
                lines.append(f"  Audit:      {total} actions logged ({blocked} would block)")
            else:
                lines.append(f"  Audit:      {total} actions logged ({blocked} blocked)")

            # Last blocked action
            last_blocked = audit.get_executions(limit=100)
            for ex in last_blocked:
                if ex.get("policy_status") == "block":
                    action = ex.get("action", "unknown")
                    reason = ex.get("policy_reason", "")
                    ts = ex.get("timestamp", "")
                    ago = _time_ago(ts)
                    detail = f"{action}"
                    if reason:
                        detail += f" ({reason})"
                    if ago:
                        lines.append(f"  Last block: {ago} — {detail}")
                    else:
                        lines.append(f"  Last block: {detail}")
                    break
            else:
                if blocked == 0:
                    lines.append("  Last block: none")
        else:
            lines.append("  Audit:      no actions logged yet")
        audit.close()
    except Exception:
        lines.append("  Audit:      database not available")

    # Output
    content = "\n".join(lines)
    try:
        from ..output import RICH
        if RICH:
            panel("agsec status", content)
        else:
            print(content)
    except Exception:
        print(content)


def _detect_platforms():
    """Detect which platforms have agsec hooks installed."""
    platforms = []
    cwd = os.getcwd()

    checks = [
        ("claude-code", os.path.join(cwd, ".claude", "settings.json"), "agsec"),
        ("codex", os.path.join(cwd, ".codex", "hooks.json"), "agsec"),
        ("cursor", os.path.join(cwd, ".cursor", "hooks.json"), "agsec"),
        ("windsurf", os.path.join(cwd, ".windsurf", "settings.json"), "agsec"),
        ("cline", os.path.join(cwd, ".clinerules", "hooks", "agsec-check.sh"), None),
        ("copilot", os.path.join(cwd, ".github", "hooks", "hooks.json"), "agsec"),
    ]

    for name, path, search_str in checks:
        if not os.path.isfile(path):
            continue
        if search_str is None:
            # File existence = installed (cline)
            platforms.append(name)
        else:
            try:
                with open(path, "r") as f:
                    if search_str in f.read():
                        platforms.append(name)
            except Exception:
                pass

    return platforms


def _time_ago(iso_timestamp):
    """Convert ISO timestamp to human-readable 'X ago' string."""
    if not iso_timestamp:
        return ""
    try:
        from datetime import datetime
        ts = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00").split("+")[0])
        now = datetime.utcnow()
        diff = now - ts
        seconds = int(diff.total_seconds())
        if seconds < 60:
            return f"{seconds}s ago"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m ago"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}h ago"
        days = hours // 24
        return f"{days}d ago"
    except Exception:
        return ""
