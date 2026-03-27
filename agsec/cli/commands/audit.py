"""agsec audit — query audit logs."""

from __future__ import annotations

import json
import sys

from ...audit import AuditStore
from ..config import get_audit_db_path, load_mode


def register(subparsers):
    p = subparsers.add_parser("audit", help="Query audit logs")
    p.add_argument("--stats", action="store_true", help="Show summary statistics")
    p.add_argument("--action", help="Filter by action name")
    p.add_argument("--limit", type=int, default=20, help="Number of records (default: 20)")
    p.add_argument("--json", dest="as_json", action="store_true", help="Output as JSON")
    p.set_defaults(func=run)


def run(args):
    try:
        audit = AuditStore(get_audit_db_path())
    except Exception as e:
        print(f"Error opening audit database: {e}", file=sys.stderr)
        sys.exit(1)

    if args.stats:
        stats = audit.get_execution_stats()
        mode = load_mode()
        if args.as_json:
            stats["mode"] = mode
            print(json.dumps(stats, indent=2))
        else:
            mode_label = "OBSERVE" if mode == "observe" else "ENFORCE"
            print(f"Audit Statistics ({mode_label} mode)")
            print(f"  Total:        {stats['total_executions']}")
            print(f"  Allowed:      {stats['allowed']}")
            if mode == "observe":
                print(f"  Would block:  {stats['blocked']}")
                print(f"  Would review: {stats['reviewed']}")
            else:
                print(f"  Blocked:      {stats['blocked']}")
                print(f"  Reviewed:     {stats['reviewed']}")
            print(f"  Errors:       {stats['errors']}")
        return

    executions = audit.get_executions(action=args.action, limit=args.limit)

    if not executions:
        print("No audit records found.")
        return

    if args.as_json:
        print(json.dumps(executions, indent=2, default=str))
    else:
        for ex in executions:
            status = ex["policy_status"].upper()
            icon = {"allow": "+", "block": "X", "review": "?"}
            marker = icon.get(ex["policy_status"], " ")
            print(f"  [{marker}] {ex['timestamp']}  {status:6s}  {ex['action']}")
            if ex.get("policy_reason"):
                print(f"       {ex['policy_reason']}")
