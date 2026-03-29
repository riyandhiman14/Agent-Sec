"""agsec validate — validate policy files."""

from __future__ import annotations

import os
import sys

from ...policy import PolicyEngine
from ..config import find_policy_dir
from ..output import error, info, success


def register(subparsers):
    p = subparsers.add_parser("validate", help="Validate policy files")
    p.add_argument("path", nargs="?", help="Policy file or directory (default: auto-discover)")
    p.set_defaults(func=run)


def run(args):
    path = args.path
    if not path:
        try:
            path = find_policy_dir()
        except FileNotFoundError:
            error("No policies directory found.")
            info("Run 'agsec init' to create default policies.")
            sys.exit(1)

    engine = PolicyEngine()

    if os.path.isdir(path):
        results = engine.validate_directory(path)
        if not results:
            files = [f for f in os.listdir(path) if f.endswith((".yaml", ".yml"))]
            success(f"All {len(files)} policy file(s) valid.")
            sys.exit(0)
        for filename, issues in results.items():
            for issue in issues:
                error(f"{filename}: {issue}")
        sys.exit(1)
    elif os.path.isfile(path):
        issues = engine.validate_file(path)
        if not issues:
            success(f"Valid: {path}")
            sys.exit(0)
        for issue in issues:
            error(issue)
        sys.exit(1)
    else:
        error(f"Path not found: {path}")
        sys.exit(1)
