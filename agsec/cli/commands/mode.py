"""agsec observe / agsec enforce — switch between modes."""

from __future__ import annotations

from ..config import load_mode, set_mode


def register_observe(subparsers):
    p = subparsers.add_parser("observe", help="Switch to observe mode (audit only, no blocking)")
    p.set_defaults(func=run_observe)


def register_enforce(subparsers):
    p = subparsers.add_parser("enforce", help="Switch to enforce mode (policies enforced)")
    p.set_defaults(func=run_enforce)


def run_observe(args):
    current = load_mode()
    if current == "observe":
        print("Already in OBSERVE mode.")
        return
    config_path = set_mode("observe")
    print("Switched to OBSERVE mode.")
    print("  All actions are allowed but logged.")
    print("  Run 'agsec audit --stats' to see what would be blocked.")
    print("  Run 'agsec enforce' when ready to start blocking.")
    print(f"  Config: {config_path}")


def run_enforce(args):
    current = load_mode()
    if current == "enforce":
        print("Already in ENFORCE mode.")
        return
    config_path = set_mode("enforce")
    print("Switched to ENFORCE mode.")
    print("  Policies are now enforced. Blocked actions will be denied.")
    print(f"  Config: {config_path}")
