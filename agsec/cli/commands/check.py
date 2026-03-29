"""agsec check — evaluate an action against policies. Called by hooks."""

from __future__ import annotations

import json
import sys

from ...audit import AuditStore
from ...policy import PolicyEngine
from ...types import ActionExecutionResult, PolicyResult, PolicyStatus
from ..config import find_policy_dir, get_audit_db_path, load_mode
from ..mapping import map_tool_to_action


def register(subparsers):
    p = subparsers.add_parser("check", help="Check an action against policies (used by hooks)")
    p.add_argument("--format", choices=["generic", "claude-code", "codex", "cursor", "windsurf", "cline", "copilot"],
                   default="generic", help="Output format (default: generic)")
    p.add_argument("--policy-dir", help="Override policy directory")
    p.add_argument("--action", help="Action name (if not reading from stdin)")
    p.add_argument("--params", help="JSON params (if not reading from stdin)")
    p.add_argument("--strict", action="store_true", help="Fail closed if no policies found (block all)")
    p.add_argument("--agent", help="Agent identity (e.g. claude-code, copilot)")
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
        # Claude Code / Windsurf / Cline format
        action, params = map_tool_to_action(raw["tool_name"], raw.get("tool_input", {}))
    elif "toolName" in raw:
        # GitHub Copilot format (toolArgs is a JSON string)
        tool_args = raw.get("toolArgs", "{}")
        if isinstance(tool_args, str):
            try:
                tool_args = json.loads(tool_args)
            except (json.JSONDecodeError, TypeError):
                tool_args = {}
        action, params = map_tool_to_action(raw["toolName"], tool_args)
    else:
        action, params = raw.get("action", "unknown"), raw.get("params", {})

    # Validate types
    if not isinstance(action, str):
        action = str(action)
    if not isinstance(params, dict):
        params = {}

    # Build context from hook metadata
    context = {}
    for key in ("session_id", "cwd", "permission_mode"):
        if key in raw:
            context[key] = raw[key]

    # Agent identity (from --agent flag)
    agent_name = getattr(args, "agent", None)
    if agent_name:
        context["agent"] = agent_name

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

    # Build layered engine: project policies + optional agent overlay
    from ...policy.engine import LayeredPolicyEngine
    from ...integrations._base import _get_agent_policy_dir

    layered = LayeredPolicyEngine()

    # Project layer
    project_engine = PolicyEngine()
    try:
        project_engine.load_from_directory(policy_dir)
        layered.add_layer("project", project_engine)
    except (ValueError, FileNotFoundError):
        if getattr(args, "strict", False):
            _exit_error(args.format, "Failed to load policies. Blocking all actions.", 1)
            return
        print('{"warning": "Failed to load policies."}', file=sys.stderr)
        sys.exit(0)

    # Agent layer (only adds restrictions)
    if agent_name:
        agent_dir = _get_agent_policy_dir(agent_name)
        if agent_dir:
            try:
                agent_engine = PolicyEngine()
                agent_engine.load_from_directory(agent_dir)
                agent_engine._default = PolicyStatus.ALLOW
                layered.add_layer("agent", agent_engine)
            except (ValueError, FileNotFoundError):
                pass

    # Evaluate
    result = layered.evaluate(action, params, context)

    # Check mode (observe vs enforce)
    mode = load_mode()
    context["agsec_mode"] = mode

    # Determine actual outcome: what really happened to this action
    if mode == "halt":
        outcome = "blocked"
    elif mode == "observe":
        outcome = "allowed"  # observe lets everything through
    elif result.status == PolicyStatus.BLOCK:
        outcome = "blocked"
    elif result.status == PolicyStatus.REVIEW:
        outcome = "review"
    else:
        outcome = "allowed"

    # Audit log (never fail the check due to audit)
    try:
        with AuditStore(get_audit_db_path()) as audit:
            exec_result = ActionExecutionResult(action=action, params=params, result=None, policy=result)
            audit.log_execution(exec_result, context, outcome=outcome)
    except Exception:
        pass

    # Halt mode: block everything immediately
    if mode == "halt":
        reason_halt = "[agsec] HALTED: All agent actions are blocked. Run 'agsec resume' to restore."
        if args.format in ("claude-code", "windsurf"):
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason_halt}}))
        elif args.format == "cline":
            print(json.dumps({"cancel": True, "errorMessage": reason_halt}))
        elif args.format in ("codex", "cursor", "copilot"):
            print(json.dumps({"deny": True, "reason": reason_halt}))
        else:
            print(json.dumps({"blocked": True, "status": "halt", "reason": reason_halt}), file=sys.stderr)
        sys.exit(2 if args.format != "cline" else 0)

    # Observe mode: log everything but always allow
    if mode == "observe":
        sys.exit(0)

    # Enforce mode: act on policy decision
    if result.status == PolicyStatus.ALLOW:
        sys.exit(0)

    reason = result.reason or "Blocked by policy"
    sid = result.metadata.get("sid", "")

    reason_full = f"[agsec] {reason}" + (f" (sid: {sid})" if sid else "")

    if args.format in ("claude-code", "windsurf"):
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason_full,
            }
        }
        print(json.dumps(output))
        sys.exit(2)

    elif args.format == "codex":
        print(json.dumps({"decision": "block", "reason": reason_full}))
        sys.exit(2)

    elif args.format == "cursor":
        print(json.dumps({"deny": True, "reason": reason_full}))
        sys.exit(2)

    elif args.format == "cline":
        print(json.dumps({"cancel": True, "errorMessage": reason_full}))
        sys.exit(0)  # Cline uses exit 0 with cancel:true in JSON

    elif args.format == "copilot":
        print(json.dumps({"permissionDecision": "deny", "permissionDecisionReason": reason_full}))
        sys.exit(0)  # Copilot reads stdout JSON, exit 0 for parsed output

    else:  # generic
        msg = {"blocked": True, "status": result.status.value, "reason": reason, "sid": sid}
        print(json.dumps(msg), file=sys.stderr)
        sys.exit(1 if result.status == PolicyStatus.BLOCK else 2)


def _exit_error(fmt: str, message: str, code: int):
    print(json.dumps({"error": message}), file=sys.stderr)
    sys.exit(code)
