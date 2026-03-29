"""agsec analyze — threat analysis with consequences."""

from __future__ import annotations

import json
import sys

from ...audit import AuditStore
from ...threat import Severity, ThreatClassifier, group_findings
from ..config import get_audit_db_path, load_mode
from ..output import (
    error, heading, info, mode_label, plain, severity_label,
    status_allow, status_block, status_review, success, subheading, warn,
)


# Human-readable labels for action types: (display_name, param_field_for_value)
ACTION_LABELS = {
    "bash.execute": ("Shell Commands", "command"),
    "file.edit": ("File Edits", "file_path"),
    "file.write": ("File Creation", "file_path"),
    "file.read": ("File Reads", "file_path"),
    "web.fetch": ("Web Requests", "url"),
    "web.search": ("Web Searches", "query"),
    "file.glob": ("File Search", "pattern"),
    "file.grep": ("Content Search", "pattern"),
    "agent.spawn": ("Sub-Agent Spawns", "prompt"),
    "notebook.edit": ("Notebook Edits", "file_path"),
}

MAX_ITEMS_PER_GROUP = 5


def register(subparsers):
    p = subparsers.add_parser("analyze", help="Threat analysis of observed agent behavior")
    p.add_argument("--hours", type=float, help="Analyze last N hours")
    p.add_argument("--days", type=float, help="Analyze last N days")
    p.add_argument("--all", dest="show_all", action="store_true",
                   help="Show all actions grouped by type (full activity report)")
    p.add_argument("--json", dest="as_json", action="store_true", help="Output as JSON")
    p.set_defaults(func=run)


def run(args):
    try:
        audit = AuditStore(get_audit_db_path())
    except Exception as e:
        error(f"Cannot open audit database: {e}")
        info("Fix: Check permissions on ~/.agsec/audit.db or set AGSEC_AUDIT_DB")
        sys.exit(1)

    executions = audit.get_executions_since(hours=args.hours, days=args.days)

    if not executions:
        info("No audit records found. Run your agent in observe mode first.")
        return

    mode = load_mode()

    if args.show_all:
        groups = _build_activity_groups(executions)
        if args.as_json:
            _render_all_json(groups, executions, mode, args)
        else:
            _render_all_human(groups, executions, mode, args)
    else:
        classifier = ThreatClassifier()
        report = classifier.classify(executions)
        if args.as_json:
            _render_json(report, mode, args)
        else:
            _render_human(report, mode, args)


def _render_human(report, mode, args):
    heading("agsec threat analysis")

    # Time window
    if args.hours:
        window = f"Last {args.hours}h"
    elif args.days:
        window = f"Last {args.days}d"
    else:
        window = "All time"
    plain(f"Time window: {window} ({report.total_executions} actions)")
    plain(f"Mode: {mode_label(mode)}")
    plain("")

    # Blast radius
    bar_filled = int(report.blast_radius)
    bar_empty = 10 - bar_filled
    bar = "\u2588" * bar_filled + "\u2591" * bar_empty
    plain(f"Blast Radius: {report.blast_radius} / 10.0 \u2014 {report.blast_radius_label}")
    plain(f"              {bar}")
    plain("")

    # Threats (allowed through)
    if report.threats:
        grouped = group_findings(report.threats)
        current_severity = None

        for group in grouped:
            sev = group["severity"]
            if sev.upper() != current_severity:
                current_severity = sev.upper()
                sev_count = report.severity_counts.get(sev, 0)
                subheading(f"{severity_label(sev)} ({sev_count} unblocked)")

            plain(f"  {group['name']} ({group['count']}x)")
            if group["examples"]:
                examples_str = ", ".join(group["examples"][:3])
                if len(examples_str) > 100:
                    examples_str = examples_str[:97] + "..."
                info(f"    \u2192 {examples_str}")
            info(f"    Impact: {group['consequence']}")
            plain("")
    else:
        success("No unblocked threats detected.")
        plain("")

    # Caught by policy
    if report.blocked:
        total_blocked = len(report.blocked)
        success(f"Caught by policy ({total_blocked} actions blocked)")
        blocked_grouped = group_findings(report.blocked)
        summaries = [f"{g['count']}x {g['name'].lower()}" for g in blocked_grouped]
        info(f"  {', '.join(summaries)}")
        plain("")

    # Recommendations
    if report.recommendations:
        subheading("Recommendations")
        for i, rec in enumerate(report.recommendations, 1):
            plain(f"  {i}. {rec}")


def _render_json(report, mode, args):
    threat_groups = group_findings(report.threats)
    blocked_groups = group_findings(report.blocked)

    output = {
        "blast_radius": report.blast_radius,
        "blast_radius_label": report.blast_radius_label,
        "mode": mode,
        "total_executions": report.total_executions,
        "severity_counts": report.severity_counts,
        "threats": threat_groups,
        "blocked_by_policy": blocked_groups,
        "recommendations": report.recommendations,
    }

    if args.hours:
        output["time_window"] = f"{args.hours}h"
    elif args.days:
        output["time_window"] = f"{args.days}d"
    else:
        output["time_window"] = "all"

    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# --all: Full activity report
# ---------------------------------------------------------------------------


def _get_time_window(args):
    if args.hours:
        return f"Last {args.hours}h"
    elif args.days:
        return f"Last {args.days}d"
    return "All time"


def _build_activity_groups(executions):
    """Group all executions by action type with human-readable labels."""
    groups = {}

    for row in executions:
        action = row.get("action", "")
        status = row.get("policy_status", "allow")

        # Skip internal tools — not interesting to users
        if action.startswith("internal."):
            continue

        raw_params = row.get("params", "{}")
        if isinstance(raw_params, str):
            try:
                params = json.loads(raw_params)
            except (json.JSONDecodeError, TypeError):
                params = {}
        elif isinstance(raw_params, dict):
            params = raw_params
        else:
            params = {}

        # Resolve label and value field
        if action in ACTION_LABELS:
            label, value_field = ACTION_LABELS[action]
        elif action.startswith("mcp."):
            label = f"MCP: {action[4:]}"
            value_field = None
        else:
            label = action
            value_field = None

        if action not in groups:
            groups[action] = {
                "label": label,
                "items": [],
                "counts": {"allow": 0, "block": 0, "review": 0},
            }

        groups[action]["counts"][status] = groups[action]["counts"].get(status, 0) + 1

        # Extract display value
        if value_field and value_field in params:
            value = str(params[value_field])
        elif params:
            value = str(list(params.values())[0])
        else:
            value = "(no params)"

        # Truncate long values
        if len(value) > 100:
            value = value[:97] + "..."

        groups[action]["items"].append({"value": value, "status": status})

    return groups


def _render_all_human(groups, executions, mode, args):
    heading("agsec activity report")

    window = _get_time_window(args)
    total = len([e for e in executions if not e.get("action", "").startswith("internal.")])
    plain(f"Time window: {window} ({total} actions)  |  Mode: {mode_label(mode)}")
    plain("")

    is_observe = mode == "observe"

    # Sort: groups with blocks/reviews first, then by total count descending
    def sort_key(item):
        g = item[1]
        has_issues = g["counts"].get("block", 0) + g["counts"].get("review", 0)
        total_count = sum(g["counts"].values())
        return (-has_issues, -total_count)

    sorted_groups = sorted(groups.items(), key=sort_key)

    for action, group in sorted_groups:
        label = group["label"]
        counts = group["counts"]
        total_count = sum(counts.values())

        # Build count summary
        parts = []
        if counts.get("allow", 0):
            parts.append(f"{counts['allow']} allow")
        if counts.get("block", 0):
            block_word = "would-block" if is_observe else "block"
            parts.append(f"{counts['block']} {block_word}")
        if counts.get("review", 0):
            parts.append(f"{counts['review']} review")

        summary = ", ".join(parts)
        subheading(f"{label} ({total_count} actions \u2014 {summary})")

        # Sort items: block first, then review, then allow
        status_order = {"block": 0, "review": 1, "allow": 2}
        sorted_items = sorted(group["items"], key=lambda x: status_order.get(x["status"], 3))

        # Deduplicate values while preserving order and worst status
        seen = {}
        for item in sorted_items:
            val = item["value"]
            if val not in seen:
                seen[val] = item
            # Keep the worst status (block > review > allow)
            elif status_order.get(item["status"], 3) < status_order.get(seen[val]["status"], 3):
                seen[val] = item

        deduped = list(seen.values())

        shown = 0
        for item in deduped:
            if shown >= MAX_ITEMS_PER_GROUP:
                break
            value = item["value"]
            status = item["status"]

            if status == "block":
                status_block(f"  {value}")
            elif status == "review":
                status_review(f"  {value}")
            else:
                status_allow(f"  {value}")
            shown += 1

        remaining = len(deduped) - shown
        if remaining > 0:
            info(f"  ... {remaining} more")

        plain("")


def _render_all_json(groups, executions, mode, args):
    total = len([e for e in executions if not e.get("action", "").startswith("internal.")])

    output = {
        "mode": mode,
        "total_actions": total,
        "groups": {},
    }

    if args.hours:
        output["time_window"] = f"{args.hours}h"
    elif args.days:
        output["time_window"] = f"{args.days}d"
    else:
        output["time_window"] = "all"

    for action, group in groups.items():
        counts = group["counts"]
        output["groups"][action] = {
            "label": group["label"],
            "total": sum(counts.values()),
            "allow": counts.get("allow", 0),
            "block": counts.get("block", 0),
            "review": counts.get("review", 0),
            "items": group["items"],
        }

    print(json.dumps(output, indent=2))
