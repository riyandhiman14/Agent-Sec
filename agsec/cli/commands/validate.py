"""agsec validate — validate policy files."""

from __future__ import annotations

import os
import sys

from ...policy import PolicyEngine
from ..config import find_policy_dir


def register(subparsers):
    p = subparsers.add_parser("validate", help="Validate policy files")
    p.add_argument("path", nargs="?", help="Policy file or directory (default: auto-discover)")
    p.set_defaults(func=run)


def run(args):
    path = args.path
    if not path:
        try:
            path = find_policy_dir()
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    engine = PolicyEngine()

    if os.path.isdir(path):
        results = engine.validate_directory(path)
        if not results:
            files = [f for f in os.listdir(path) if f.endswith((".yaml", ".yml"))]
            print(f"All {len(files)} policy file(s) valid.")
            sys.exit(0)
        for filename, issues in results.items():
            for issue in issues:
                print(f"  {filename}: {issue}", file=sys.stderr)
        sys.exit(1)
    elif os.path.isfile(path):
        issues = engine.validate_file(path)
        if not issues:
            print(f"Valid: {path}")
            sys.exit(0)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"Error: Path not found: {path}", file=sys.stderr)
        sys.exit(1)
