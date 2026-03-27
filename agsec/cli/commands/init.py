"""agsec init — scaffold policies directory with default templates."""

from __future__ import annotations

import os
import shutil

from ..config import get_templates_dir, set_mode


def register(subparsers):
    p = subparsers.add_parser("init", help="Initialize agsec policies in current directory")
    p.add_argument("--dir", default="policies", help="Directory name (default: policies)")
    p.add_argument("--observe", action="store_true",
                   help="Start in observe mode (audit everything, block nothing)")
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

    # Set mode
    mode = "observe" if args.observe else "enforce"
    config_path = set_mode(mode)

    mode_label = "OBSERVE" if args.observe else "ENFORCE"
    files = sorted(os.listdir(target))
    print(f"Created {target}/ with {len(files)} policy files ({mode_label} mode)")
    for f in files:
        print(f"  {f}")
    print()

    if args.observe:
        print("Observe mode: all actions are ALLOWED but logged.")
        print("Run 'agsec audit --stats' to see what would be blocked.")
        print("Run 'agsec enforce' when ready to start blocking.")
    else:
        print("Next steps:")
        print("  1. Edit policies to match your needs")
        print("  2. Run 'agsec validate' to check for errors")
        print("  3. Run 'agsec install claude-code' or 'agsec install codex' to activate")
