"""agsec analyze — threat analysis with consequences."""

from __future__ import annotations

import json
import sys

from ...audit import AuditStore
from ...threat import Severity, ThreatClassifier, group_findings
from ..config import get_audit_db_path, load_mode


def register(subparsers):
    p = subparsers.add_parser("analyze", help="Threat analysis of observed agent behavior")
    p.add_argument("--hours", type=float, help="Analyze last N hours")
    p.add_argument("--days", type=float, help="Analyze last N days")
    p.add_argument("--json", dest="as_json", action="store_true", help="Output as JSON")
    p.set_defaults(func=run)


def run(args):
    try:
        audit = AuditStore(get_audit_db_path())
    except Exception as e:
        print(f"Error opening audit database: {e}", file=sys.stderr)
        sys.exit(1)

    executions = audit.get_executions_since(hours=args.hours, days=args.days)

    if not executions:
        print("No audit records found. Run your agent in observe mode first.")
        return

    classifier = ThreatClassifier()
    report = classifier.classify(executions)
    mode = load_mode()

    if args.as_json:
        _render_json(report, mode, args)
    else:
        _render_human(report, mode, args)


def _render_human(report, mode, args):
    # Header
    print("agsec threat analysis")
    print("=" * 21)

    # Time window
    if args.hours:
        window = f"Last {args.hours}h"
    elif args.days:
        window = f"Last {args.days}d"
    else:
        window = "All time"
    print(f"Time window: {window} ({report.total_executions} actions)")
    print(f"Mode: {mode}")
    print()

    # Blast radius
    bar_filled = int(report.blast_radius)
    bar_empty = 10 - bar_filled
    bar = "\u2588" * bar_filled + "\u2591" * bar_empty
    print(f"Blast Radius: {report.blast_radius} / 10.0 \u2014 {report.blast_radius_label}")
    print(f"              {bar}")
    print()

    # Threats (allowed through)
    if report.threats:
        grouped = group_findings(report.threats)
        current_severity = None

        for group in grouped:
            sev = group["severity"].upper()
            if sev != current_severity:
                current_severity = sev
                sev_count = report.severity_counts.get(group["severity"], 0)
                print(f"{sev} ({sev_count} unblocked)")

            print(f"  {group['name']} ({group['count']}x)")
            if group["examples"]:
                examples_str = ", ".join(group["examples"][:3])
                if len(examples_str) > 100:
                    examples_str = examples_str[:97] + "..."
                print(f"    \u2192 {examples_str}")
            print(f"    Impact: {group['consequence']}")
            print()
    else:
        print("No unblocked threats detected.")
        print()

    # Caught by policy
    if report.blocked:
        total_blocked = len(report.blocked)
        print(f"Caught by policy ({total_blocked} actions blocked)")
        blocked_grouped = group_findings(report.blocked)
        summaries = [f"{g['count']}x {g['name'].lower()}" for g in blocked_grouped]
        print(f"  {', '.join(summaries)}")
        print()

    # Recommendations
    if report.recommendations:
        print("Recommendations")
        for i, rec in enumerate(report.recommendations, 1):
            print(f"  {i}. {rec}")


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
