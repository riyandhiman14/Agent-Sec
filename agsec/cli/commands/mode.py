"""agsec observe / agsec enforce — switch between modes."""

from __future__ import annotations

from ..config import get_previous_mode, load_mode, set_mode


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


def register_halt(subparsers):
    p = subparsers.add_parser("halt", help="Kill switch: immediately block ALL agent actions")
    p.set_defaults(func=run_halt)


def register_resume(subparsers):
    p = subparsers.add_parser("resume", help="Resume from halt: restore previous mode")
    p.set_defaults(func=run_resume)


def run_halt(args):
    current = load_mode()
    if current == "halt":
        print("Already HALTED. All actions are blocked.")
        return
    config_path = set_mode("halt", store_previous=True)
    print("HALTED. All agent actions are now blocked.")
    print(f"  Previous mode ({current.upper()}) saved. Run 'agsec resume' to restore.")
    print(f"  Config: {config_path}")


def run_resume(args):
    current = load_mode()
    if current != "halt":
        print(f"Not halted. Current mode: {current.upper()}")
        return
    previous = get_previous_mode()
    config_path = set_mode(previous)
    print(f"Resumed. Restored to {previous.upper()} mode.")
    print(f"  Config: {config_path}")
