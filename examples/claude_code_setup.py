"""
Claude Code + agsec setup — run this script to set everything up.

Run: pip install agsec
     python examples/claude_code_setup.py
"""

import os
import subprocess
import sys


def main():
    print("=== agsec + Claude Code Setup ===\n")

    # Step 1: Check if policies exist
    has_policies = os.path.isdir("policies") or os.path.isdir(".agsec/policies")

    if not has_policies:
        print("1. Creating policies...")
        result = subprocess.run(
            [sys.executable, "-m", "agsec", "init"],
            capture_output=True, text=True,
        )
        print(f"   {result.stdout.strip().split(chr(10))[0]}")
    else:
        print("1. Policies already exist.")

    # Step 2: Install hook
    print("\n2. Installing Claude Code hook...")
    result = subprocess.run(
        [sys.executable, "-m", "agsec", "install", "claude-code"],
        capture_output=True, text=True,
    )
    print(f"   {result.stdout.strip().split(chr(10))[0]}")

    # Step 3: Show current policies
    print("\n3. Active policies:")
    result = subprocess.run(
        [sys.executable, "-m", "agsec", "policy", "list"],
        capture_output=True, text=True,
    )
    for line in result.stdout.strip().split("\n"):
        print(f"   {line}")

    # Step 4: Validate
    print("\n4. Validating...")
    result = subprocess.run(
        [sys.executable, "-m", "agsec", "validate"],
        capture_output=True, text=True,
    )
    print(f"   {result.stdout.strip()}")

    print("\n=== Done. Restart Claude Code to activate the firewall. ===")


if __name__ == "__main__":
    main()
