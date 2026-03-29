"""agsec audit — query audit logs."""

from __future__ import annotations

import json
import sys

from ...audit import AuditStore
from ..config import get_audit_db_path, load_mode
from ..output import error, heading, info, mode_label, plain, status_allow, status_block, status_review, table


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
        error(f"Cannot open audit database: {e}")
        info("Fix: Check permissions on ~/.agsec/audit.db or set AGSEC_AUDIT_DB")
        sys.exit(1)

    if args.stats:
        stats = audit.get_execution_stats()
        mode = load_mode()
        if args.as_json:
            stats["mode"] = mode
            print(json.dumps(stats, indent=2))
        else:
            heading(f"Audit Statistics ({mode_label(mode)} mode)")
            plain(f"  Total:        {stats['total_executions']}")
            plain(f"  Allowed:      {stats['allowed']}")
            if mode == "observe":
                plain(f"  Would block:  {stats['blocked']}")
                plain(f"  Would review: {stats['reviewed']}")
            else:
                plain(f"  Blocked:      {stats['blocked']}")
                plain(f"  Reviewed:     {stats['reviewed']}")
            plain(f"  Errors:       {stats['errors']}")
        return

    executions = audit.get_executions(action=args.action, limit=args.limit)

    if not executions:
        info("No audit records found.")
        return

    if args.as_json:
        print(json.dumps(executions, indent=2, default=str))
    else:
        for ex in executions:
            status = ex["policy_status"]
            ts = ex["timestamp"]
            action = ex["action"]
            reason = ex.get("policy_reason", "")

            line = f"{ts}  {status.upper():6s}  {action}"
            if status == "allow":
                status_allow(line)
            elif status == "block":
                status_block(line)
            else:
                status_review(line)

            if reason:
                info(f"       {reason}")
