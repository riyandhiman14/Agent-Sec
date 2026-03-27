"""agsec policy — manage policy statements from the CLI."""

from __future__ import annotations

import os
import sys

import yaml

from ..config import find_policy_dir

# Known actions for interactive picker
KNOWN_ACTIONS = {
    "1": ("bash.execute", "Bash/shell commands"),
    "2": ("file.write", "File creation"),
    "3": ("file.edit", "File editing"),
    "4": ("file.read", "File reading"),
    "5": ("web.fetch", "HTTP requests"),
    "6": ("web.search", "Web searches"),
    "7": ("file.glob", "File search by pattern"),
    "8": ("file.grep", "Content search"),
    "9": ("agent.spawn", "Sub-agent spawning"),
    "10": ("notebook.edit", "Notebook editing"),
}

KNOWN_OPERATORS = {
    "1": ("==", "equals"),
    "2": ("!=", "not equals"),
    "3": (">", "greater than"),
    "4": ("<", "less than"),
    "5": (">=", "greater or equal"),
    "6": ("<=", "less or equal"),
    "7": ("in", "is in list"),
    "8": ("not_in", "is not in list"),
    "9": ("contains", "contains substring"),
    "10": ("starts_with", "starts with"),
    "11": ("ends_with", "ends with"),
    "12": ("regex", "matches regex pattern"),
    "13": ("exists", "field exists"),
    "14": ("not_exists", "field does not exist"),
}


def _prompt(message, default=None):
    """Prompt user for input with optional default."""
    if default:
        raw = input(f"  {message} [{default}]: ").strip()
        return raw or default
    return input(f"  {message}: ").strip()


def _prompt_choice(message, choices):
    """Prompt user to pick from numbered choices."""
    print(f"\n  {message}")
    for key, (value, desc) in choices.items():
        print(f"    {key}) {desc} ({value})")
    while True:
        raw = input("  Choice: ").strip()
        if raw in choices:
            return choices[raw][0]
        # Allow typing the value directly
        for _, (value, _) in choices.items():
            if raw == value:
                return value
        print("  Invalid choice. Try again.")


def _prompt_yes_no(message, default=True):
    """Prompt yes/no question."""
    hint = "Y/n" if default else "y/N"
    raw = input(f"  {message} [{hint}]: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def register(subparsers):
    p = subparsers.add_parser("policy", help="Manage policy statements")
    sub = p.add_subparsers(dest="policy_command")

    # agsec policy add
    add_p = sub.add_parser("add", help="Add a new policy statement (interactive)")
    add_p.add_argument("--sid", help="Statement ID")
    add_p.add_argument("--effect", choices=["allow", "deny", "review"], help="Effect")
    add_p.add_argument("--actions", nargs="+", help="Action patterns")
    add_p.add_argument("--reason", default="", help="Reason")
    add_p.add_argument("--condition", action="append", dest="conditions", metavar="KEY:OP:VALUE")
    add_p.add_argument("--match", choices=["all", "any"], default="all")
    add_p.add_argument("--file", help="Target policy file")
    add_p.add_argument("--no-interactive", action="store_true", help="Skip interactive prompts")
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


def _parse_value(raw: str):
    """Parse a string value into the appropriate Python type."""
    stripped = raw.strip("'\"")
    try:
        return int(stripped)
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        pass
    if stripped.lower() == "true":
        return True
    if stripped.lower() == "false":
        return False
    return stripped


def _interactive_add():
    """Walk the user through creating a policy step by step."""
    print("\n  Create a new policy statement\n")

    # 1. Effect
    print("  What should this policy do?")
    print("    1) deny   — Block the action")
    print("    2) allow  — Allow the action")
    print("    3) review — Flag for human review")
    while True:
        choice = input("  Choice [1]: ").strip() or "1"
        effect_map = {"1": "deny", "2": "allow", "3": "review", "deny": "deny", "allow": "allow", "review": "review"}
        if choice in effect_map:
            effect = effect_map[choice]
            break
        print("  Invalid choice.")

    # 2. Actions
    print(f"\n  What actions should this policy {effect}?")
    print("  Pick from the list or type custom action patterns (e.g., mcp.slack.*)")
    for key, (value, desc) in KNOWN_ACTIONS.items():
        print(f"    {key:>2}) {desc:25s} ({value})")
    print(f"    *)  Type custom action pattern")
    print()

    actions = []
    while True:
        raw = input("  Action (number, pattern, or Enter to finish): ").strip()
        if not raw:
            if actions:
                break
            print("  At least one action is required.")
            continue
        if raw in KNOWN_ACTIONS:
            action = KNOWN_ACTIONS[raw][0]
            actions.append(action)
            print(f"    Added: {action}")
        elif raw == "*":
            actions.append("*")
            print("    Added: * (all actions)")
        else:
            actions.append(raw)
            print(f"    Added: {raw}")

    # 3. Conditions — smart flow based on selected actions
    conditions = {}

    # Suggest the most relevant field based on actions
    field_hints = {
        "bash.execute": ("params.command", "e.g., rm, curl, git push --force"),
        "file.write": ("params.file_path", "e.g., .env, credentials.json, /etc/"),
        "file.edit": ("params.file_path", "e.g., .env, credentials.json"),
        "file.read": ("params.file_path", "e.g., .env, secrets.yaml, id_rsa"),
        "web.fetch": ("params.url", "e.g., https://evil.com, *.internal.com"),
        "web.search": ("params.query", "e.g., sensitive search terms"),
        "agent.spawn": ("params.prompt", "e.g., keyword in agent prompt"),
    }

    # Find the best hint
    hint_field, hint_example = None, None
    for a in actions:
        if a in field_hints:
            hint_field, hint_example = field_hints[a]
            break

    print(f"\n  When should this apply? Enter a pattern to match, or press Enter to apply to ALL.")
    if hint_field:
        print(f"    Field: {hint_field}")
        print(f"    Examples: {hint_example}")

    pattern = input(f"\n  Pattern to match (or Enter for no condition): ").strip()

    if pattern:
        # User typed a pattern — auto-configure the condition
        field = hint_field or _prompt("  Field to check (e.g., params.command, params.file_path)")

        # Auto-detect the best operator
        if any(c in pattern for c in (r"\\", ".*", "^", "$", "[", "|", "+")):
            op = "regex"
        elif "*" in pattern:
            # Convert glob-like to regex
            op = "regex"
            pattern = pattern.replace(".", "\\.").replace("*", ".*")
        else:
            op = "contains"

        print(f"    Using: {field} {op} \"{pattern}\"")

        # Let user override
        if not _prompt_yes_no(f"  Looks right?", default=True):
            field = _prompt("  Field to check", default=field)
            op = _prompt_choice("  Operator:", KNOWN_OPERATORS)
            if op not in ("exists", "not_exists"):
                pattern = _prompt("  Value", default=pattern)

        if op in ("exists", "not_exists"):
            conditions[field] = {"op": op}
        else:
            conditions[field] = {"op": op, "value": pattern}

    # Ask for additional conditions
    while conditions and _prompt_yes_no("  Add another condition?", default=False):
        key = _prompt("  Field to check")
        if not key:
            break
        op = _prompt_choice("  Operator:", KNOWN_OPERATORS)
        if op in ("exists", "not_exists"):
            conditions[key] = {"op": op}
        else:
            value_raw = _prompt("  Value")
            conditions[key] = {"op": op, "value": _parse_value(value_raw)}
        print(f"    Condition: {key} {op} {conditions[key].get('value', '')}")

    match = "all"
    if len(conditions) > 1:
        if _prompt_yes_no("  Must ALL conditions match? (No = ANY condition)", default=True):
            match = "all"
        else:
            match = "any"

    # 4. Reason
    # Auto-suggest a reason
    if conditions and pattern:
        suggested_reason = f"{effect.title()}ed: matches '{pattern}'"
    else:
        suggested_reason = ""
    reason = _prompt("\n  Reason (shown when action is blocked)", default=suggested_reason)

    # 5. SID
    # Auto-generate a suggestion
    effect_prefix = {"deny": "Block", "allow": "Allow", "review": "Review"}
    action_hint = actions[0].split(".")[-1].title() if actions else "Action"
    suggested_sid = f"{effect_prefix[effect]}{action_hint}"
    sid = _prompt(f"  Statement ID", default=suggested_sid)

    # 6. Target file — auto-name from pattern
    if pattern:
        import re
        clean = re.sub(r"[^a-zA-Z0-9]+", "_", pattern).strip("_").lower()
        suggested_file = f"{clean}_restriction.yaml"
    else:
        suggested_file = "99_custom.yaml"
    file_name = _prompt("  Save to file", default=suggested_file)

    return {
        "sid": sid,
        "effect": effect,
        "actions": actions,
        "conditions": conditions,
        "match": match,
        "reason": reason,
        "file": file_name,
    }


def run_add(args):
    try:
        policy_dir = find_policy_dir()
    except FileNotFoundError:
        print("No policies directory found. Run 'agsec init' first.", file=sys.stderr)
        sys.exit(1)

    # Interactive mode if required args are missing
    is_interactive = not args.no_interactive and not (args.sid and args.effect and args.actions)

    if is_interactive:
        try:
            data = _interactive_add()
        except (KeyboardInterrupt, EOFError):
            print("\n  Cancelled.")
            sys.exit(0)
        sid = data["sid"]
        effect = data["effect"]
        actions = data["actions"]
        reason = data["reason"]
        conditions = data["conditions"]
        match_type = data["match"]
        target_file = data["file"]
    else:
        sid = args.sid
        effect = args.effect
        actions = args.actions
        reason = args.reason or ""
        match_type = args.match
        target_file = args.file or "99_custom.yaml"
        conditions = {}
        if args.conditions:
            for cond_str in args.conditions:
                try:
                    key, op, value = _parse_condition(cond_str)
                    conditions[key] = {"op": op, "value": value}
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    sys.exit(1)

    # Build statement
    statement = {"sid": sid, "effect": effect, "actions": actions}
    if reason:
        statement["reason"] = reason
    if match_type != "all":
        statement["match"] = match_type
    if conditions:
        statement["conditions"] = conditions

    # Determine target file
    target = os.path.join(policy_dir, target_file)
    if not target.endswith((".yaml", ".yml")):
        target += ".yaml"

    # Load or create the file
    if os.path.isfile(target):
        with open(target, "r") as f:
            doc = yaml.safe_load(f) or {}
    else:
        doc = {"version": "1.0"}

    # Check for duplicate SID
    existing = doc.get("statements", [])
    for s in existing:
        if s.get("sid") == sid:
            print(f"Error: Statement '{sid}' already exists in {os.path.basename(target)}", file=sys.stderr)
            sys.exit(1)

    existing.append(statement)
    doc["statements"] = existing

    with open(target, "w") as f:
        yaml.dump(doc, f, default_flow_style=False, sort_keys=False)

    # Summary
    print(f"\n  Added to {os.path.basename(target)}:")
    icon = {"deny": "X", "allow": "+", "review": "?"}
    print(f"  [{icon.get(effect, ' ')}] {sid} ({effect.upper()})")
    print(f"      Actions: {', '.join(actions)}")
    if conditions:
        for key, cond in conditions.items():
            print(f"      Condition: {key} {cond['op']} {cond.get('value', '')}")
    if reason:
        print(f"      Reason: {reason}")
    print()


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
