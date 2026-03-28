"""agsec CLI — AI Agent Action Firewall."""

from __future__ import annotations

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="agsec",
        description="AI Agent Action Firewall — enforce policies on agent actions",
    )
    subparsers = parser.add_subparsers(dest="command")

    from .commands import analyze, audit, check, init, install, mode, policy, validate

    init.register(subparsers)
    check.register(subparsers)
    validate.register(subparsers)
    install.register(subparsers)
    install.register_uninstall(subparsers)
    policy.register(subparsers)
    audit.register(subparsers)
    analyze.register(subparsers)
    mode.register_observe(subparsers)
    mode.register_enforce(subparsers)
    mode.register_halt(subparsers)
    mode.register_resume(subparsers)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
