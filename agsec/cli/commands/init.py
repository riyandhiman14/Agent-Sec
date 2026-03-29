"""agsec init — scaffold policies directory with default templates."""

from __future__ import annotations

import os
import shutil

from ..config import get_templates_dir, set_mode
from ..output import error, info, success, warn


def register(subparsers):
    p = subparsers.add_parser("init", help="Initialize agsec policies in current directory")
    p.add_argument("--dir", default="policies", help="Directory name (default: policies)")
    p.add_argument("--observe", action="store_true",
                   help="Start in observe mode (audit everything, block nothing)")
    p.set_defaults(func=run)


def run(args):
    target = os.path.join(os.getcwd(), args.dir)

    if os.path.exists(target):
        warn(f"Directory already exists: {target}")
        info("Use 'agsec validate' to check existing policies.")
        return

    templates = get_templates_dir()
    if not os.path.isdir(templates):
        error("Template policies not found. Reinstall agsec.")
        return

    shutil.copytree(templates, target)

    # Set mode
    mode = "observe" if args.observe else "enforce"
    config_path = set_mode(mode)

    mode_str = "OBSERVE" if args.observe else "ENFORCE"
    files = sorted(os.listdir(target))
    success(f"Created {target}/ with {len(files)} policy files ({mode_str} mode)")
    for f in files:
        info(f"  {f}")

    if args.observe:
        warn("Observe mode: all actions are ALLOWED but logged.")
        info("Run 'agsec audit --stats' to see what would be blocked.")
        info("Run 'agsec enforce' when ready to start blocking.")
    else:
        info("Next steps:")
        info("  1. Edit policies to match your needs")
        info("  2. Run 'agsec validate' to check for errors")
        info("  3. Run 'agsec install claude-code' or 'agsec install codex' to activate")
