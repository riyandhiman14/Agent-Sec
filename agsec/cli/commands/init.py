"""agsec init — scaffold policies directory with default templates."""

from __future__ import annotations

import os
import shutil

from ..config import get_templates_dir


def register(subparsers):
    p = subparsers.add_parser("init", help="Initialize agsec policies in current directory")
    p.add_argument("--dir", default="policies", help="Directory name (default: policies)")
    p.set_defaults(func=run)


def run(args):
    target = os.path.join(os.getcwd(), args.dir)

    if os.path.exists(target):
        print(f"Directory already exists: {target}")
        print("Use 'agsec validate' to check existing policies.")
        return

    templates = get_templates_dir()
    if not os.path.isdir(templates):
        print("Error: Template policies not found. Reinstall agsec.")
        return

    shutil.copytree(templates, target)

    files = sorted(os.listdir(target))
    print(f"Created {target}/ with {len(files)} policy files:")
    for f in files:
        print(f"  {f}")
    print()
    print("Next steps:")
    print("  1. Edit policies to match your needs")
    print("  2. Run 'agsec validate' to check for errors")
    print("  3. Run 'agsec install claude-code' or 'agsec install codex' to activate")
