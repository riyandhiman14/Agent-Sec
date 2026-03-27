"""agsec check — evaluate an action against policies. Called by hooks."""

from __future__ import annotations

import json
import sys

from ...audit import AuditStore
from ...policy import PolicyEngine
from ...types import ActionExecutionResult, PolicyResult, PolicyStatus
from ..config import find_policy_dir, get_audit_db_path
from ..mapping import map_tool_to_action


def register(subparsers):
    p = subparsers.add_parser("check", help="Check an action against policies (used by hooks)")
    p.add_argument("--format", choices=["generic", "claude-code", "codex"], default="generic",
                   help="Output format (default: generic)")
    p.add_argument("--policy-dir", help="Override policy directory")
    p.add_argument("--action", help="Action name (if not reading from stdin)")
    p.add_argument("--params", help="JSON params (if not reading from stdin)")
    p.add_argument("--strict", action="store_true", help="Fail closed if no policies found (block all)")
    p.set_defaults(func=run)


def run(args):
    # Read input — from stdin (hook) or from args (manual)
    if not sys.stdin.isatty():
        try:
            raw = json.load(sys.stdin)
        except json.JSONDecodeError:
            _exit_error(args.format, "Invalid JSON on stdin", 1)
            return
    elif args.action:
        try:
            raw = {"action": args.action, "params": json.loads(args.params or "{}")}
        except json.JSONDecodeError:
            _exit_error(args.format, "Invalid JSON in --params", 1)
            return
    else:
        _exit_error(args.format, "No input. Pipe JSON via stdin or use --action/--params.", 1)
        return

    # Map tool call to agsec action
    if "tool_name" in raw:
        action, params = map_tool_to_action(raw["tool_name"], raw.get("tool_input", {}))
    else:
        action, params = raw.get("action", "unknown"), raw.get("params", {})

    # Build context from hook metadata
    context = {}
    for key in ("session_id", "cwd", "permission_mode"):
        if key in raw:
            context[key] = raw[key]

    # Find and load policies
    try:
        policy_dir = args.policy_dir or find_policy_dir()
    except FileNotFoundError:
        if getattr(args, "strict", False):
            _exit_error(args.format, "No policies found. Blocking all actions (--strict mode).", 1)
            return
        # Fail-open: allow when no policies found (warn on stderr)
        print('{"warning": "No agsec policies found. Run agsec init."}', file=sys.stderr)
        sys.exit(0)

    engine = PolicyEngine()
    try:
        engine.load_from_directory(policy_dir)
    except (ValueError, FileNotFoundError):
        if getattr(args, "strict", False):
            _exit_error(args.format, "Failed to load policies. Blocking all actions.", 1)
            return
        print('{"warning": "Failed to load policies."}', file=sys.stderr)
        sys.exit(0)

    # Evaluate
    result = engine.evaluate(action, params, context)

    # Audit log (never fail the check due to audit)
    try:
        audit = AuditStore(get_audit_db_path())
        exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=result)
        audit.log_execution(exec_result, context)
    except Exception:
        pass

    # Output based on format
    if result.status == PolicyStatus.ALLOW:
        sys.exit(0)

    reason = result.reason or "Blocked by policy"
    sid = result.metadata.get("sid", "")

    if args.format == "claude-code":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"[agsec] {reason}" + (f" (sid: {sid})" if sid else ""),
            }
        }
        print(json.dumps(output))
        sys.exit(2)

    elif args.format == "codex":
        output = {
            "decision": "block",
            "reason": f"[agsec] {reason}" + (f" (sid: {sid})" if sid else ""),
        }
        print(json.dumps(output))
        sys.exit(2)

    else:  # generic
        msg = {"blocked": True, "status": result.status.value, "reason": reason, "sid": sid}
        print(json.dumps(msg), file=sys.stderr)
        sys.exit(1 if result.status == PolicyStatus.BLOCK else 2)


def _exit_error(fmt: str, message: str, code: int):
    print(json.dumps({"error": message}), file=sys.stderr)
    sys.exit(code)
