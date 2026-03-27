"""agsec policy — manage policy statements from the CLI."""

from __future__ import annotations

import os
import sys

import yaml

from ..config import find_policy_dir


def register(subparsers):
    p = subparsers.add_parser("policy", help="Manage policy statements")
    sub = p.add_subparsers(dest="policy_command")

    # agsec policy add
    add_p = sub.add_parser("add", help="Add a new policy statement")
    add_p.add_argument("--sid", required=True, help="Statement ID (e.g., BlockSlack)")
    add_p.add_argument("--effect", required=True, choices=["allow", "deny", "review"], help="Effect")
    add_p.add_argument("--actions", required=True, nargs="+", help="Action patterns (e.g., bash.execute file.write)")
    add_p.add_argument("--reason", default="", help="Human-readable reason")
    add_p.add_argument("--condition", action="append", dest="conditions", metavar="KEY:OP:VALUE",
                       help="Condition in KEY:OP:VALUE format (e.g., params.command:regex:'rm.*-rf')")
    add_p.add_argument("--match", choices=["all", "any"], default="all", help="Condition match mode")
    add_p.add_argument("--file", help="Target policy file (default: auto-pick or create custom.yaml)")
    add_p.set_defaults(func=run_add)

    # agsec policy remove
    rm_p = sub.add_parser("remove", help="Remove a policy statement by SID")
    rm_p.add_argument("sid", help="Statement ID to remove")
    rm_p.set_defaults(func=run_remove)

    # agsec policy list
    ls_p = sub.add_parser("list", help="List all policy statements")
    ls_p.set_defaults(func=run_list)

    p.set_defaults(func=lambda args: p.print_help() if not args.policy_command else None)


def _parse_condition(cond_str: str) -> tuple:
    """Parse 'KEY:OP:VALUE' into (key, op, value)."""
    parts = cond_str.split(":", 2)
    if len(parts) != 3:
        raise ValueError(f"Condition must be KEY:OP:VALUE, got: {cond_str}")
    key, op, value = parts

    # Try to parse value as number or bool
    stripped = value.strip("'\"")
    try:
        parsed_value = int(stripped)
    except ValueError:
        try:
            parsed_value = float(stripped)
        except ValueError:
            if stripped.lower() == "true":
                parsed_value = True
            elif stripped.lower() == "false":
                parsed_value = False
            else:
                parsed_value = stripped

    return key, op, parsed_value


def run_add(args):
    try:
        policy_dir = find_policy_dir()
    except FileNotFoundError:
        print("No policies directory found. Run 'agsec init' first.", file=sys.stderr)
        sys.exit(1)

    # Build statement
    statement = {
        "sid": args.sid,
        "effect": args.effect,
        "actions": args.actions,
    }
    if args.reason:
        statement["reason"] = args.reason
    if args.match != "all":
        statement["match"] = args.match

    if args.conditions:
        conditions = {}
        for cond_str in args.conditions:
            try:
                key, op, value = _parse_condition(cond_str)
                conditions[key] = {"op": op, "value": value}
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
        statement["conditions"] = conditions

    # Determine target file
    if args.file:
        target = os.path.join(policy_dir, args.file)
        if not target.endswith((".yaml", ".yml")):
            target += ".yaml"
    else:
        target = os.path.join(policy_dir, "99_custom.yaml")

    # Load or create the file
    if os.path.isfile(target):
        with open(target, "r") as f:
            doc = yaml.safe_load(f) or {}
    else:
        doc = {"version": "1.0"}

    # Check for duplicate SID
    existing = doc.get("statements", [])
    for s in existing:
        if s.get("sid") == args.sid:
            print(f"Error: Statement '{args.sid}' already exists in {os.path.basename(target)}", file=sys.stderr)
            sys.exit(1)

    existing.append(statement)
    doc["statements"] = existing

    with open(target, "w") as f:
        yaml.dump(doc, f, default_flow_style=False, sort_keys=False)

    print(f"Added statement '{args.sid}' ({args.effect}) to {os.path.basename(target)}")
    print(f"  Actions: {', '.join(args.actions)}")
    if args.reason:
        print(f"  Reason: {args.reason}")
    if args.conditions:
        print(f"  Conditions: {', '.join(args.conditions)}")


def run_remove(args):
    try:
        policy_dir = find_policy_dir()
    except FileNotFoundError:
        print("No policies directory found.", file=sys.stderr)
        sys.exit(1)

    files = sorted(
        f for f in os.listdir(policy_dir)
        if f.endswith((".yaml", ".yml"))
    )

    found = False
    for filename in files:
        path = os.path.join(policy_dir, filename)
        with open(path, "r") as f:
            doc = yaml.safe_load(f) or {}

        statements = doc.get("statements", [])
        original_len = len(statements)
        statements = [s for s in statements if s.get("sid") != args.sid]

        if len(statements) < original_len:
            doc["statements"] = statements
            with open(path, "w") as f:
                yaml.dump(doc, f, default_flow_style=False, sort_keys=False)
            print(f"Removed statement '{args.sid}' from {filename}")
            found = True
            break

    if not found:
        print(f"Statement '{args.sid}' not found in any policy file.", file=sys.stderr)
        sys.exit(1)


def run_list(args):
    try:
        policy_dir = find_policy_dir()
    except FileNotFoundError:
        print("No policies directory found. Run 'agsec init' first.", file=sys.stderr)
        sys.exit(1)

    files = sorted(
        f for f in os.listdir(policy_dir)
        if f.endswith((".yaml", ".yml"))
    )

    if not files:
        print("No policy files found.")
        return

    total = 0
    for filename in files:
        path = os.path.join(policy_dir, filename)
        with open(path, "r") as f:
            doc = yaml.safe_load(f) or {}

        default = doc.get("default", "")
        statements = doc.get("statements", [])
        rules = doc.get("rules", [])

        if not statements and not rules:
            continue

        print(f"\n{filename}" + (f"  (default: {default})" if default else ""))
        print("-" * 60)

        for s in statements:
            sid = s.get("sid", "(no sid)")
            effect = s.get("effect", "?").upper()
            actions = s.get("actions", ["*"])
            reason = s.get("reason", "")
            icon = {"ALLOW": "+", "DENY": "X", "BLOCK": "X", "REVIEW": "?"}
            marker = icon.get(effect, " ")

            print(f"  [{marker}] {sid:30s} {effect:6s}  {', '.join(actions)}")
            if reason:
                print(f"      {reason}")
            total += 1

        for r in rules:
            action = r.get("action", "*")
            status = r.get("status", "?").upper()
            reason = r.get("reason", "")
            print(f"  [ ] (legacy rule)              {status:6s}  {action}")
            if reason:
                print(f"      {reason}")
            total += 1

    print(f"\n{total} statement(s) across {len(files)} file(s)")
