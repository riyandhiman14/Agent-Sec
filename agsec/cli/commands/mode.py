"""agsec observe / agsec enforce — switch between modes."""

from __future__ import annotations

from ..config import get_previous_mode, load_mode, set_mode
from ..output import error, info, success, warn


def register_observe(subparsers):
    p = subparsers.add_parser("observe", help="Switch to observe mode (audit only, no blocking)")
    p.set_defaults(func=run_observe)


def register_enforce(subparsers):
    p = subparsers.add_parser("enforce", help="Switch to enforce mode (policies enforced)")
    p.set_defaults(func=run_enforce)


def run_observe(args):
    current = load_mode()
    if current == "observe":
        warn("Already in OBSERVE mode.")
        return
    set_mode("observe")
    warn("Switched to OBSERVE mode.")
    info("All actions are allowed but logged.")
    info("Run 'agsec audit --stats' to see what would be blocked.")
    info("Run 'agsec enforce' when ready to start blocking.")


def run_enforce(args):
    current = load_mode()
    if current == "enforce":
        success("Already in ENFORCE mode.")
        return
    set_mode("enforce")
    success("Switched to ENFORCE mode.")
    info("Policies are now enforced. Blocked actions will be denied.")


def register_halt(subparsers):
    p = subparsers.add_parser("halt", help="Kill switch: immediately block ALL agent actions")
    p.set_defaults(func=run_halt)


def register_resume(subparsers):
    p = subparsers.add_parser("resume", help="Resume from halt: restore previous mode")
    p.set_defaults(func=run_resume)


def run_halt(args):
    current = load_mode()
    if current == "halt":
        error("Already HALTED. All actions are blocked.")
        return
    set_mode("halt", store_previous=True)
    error("HALTED. All agent actions are now blocked.")
    info(f"Previous mode ({current.upper()}) saved. Run 'agsec resume' to restore.")


def run_resume(args):
    current = load_mode()
    if current != "halt":
        info(f"Not halted. Current mode: {current.upper()}")
        return
    previous = get_previous_mode()
    set_mode(previous)
    success(f"Resumed. Restored to {previous.upper()} mode.")
