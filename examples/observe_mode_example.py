"""
Observe mode example — audit everything, block nothing.

This shows the full observe → enforce workflow:
1. Start in observe mode
2. Agent runs normally, all actions logged
3. Check what would be blocked
4. Switch to enforce when confident

Run: pip install agsec
     python examples/observe_mode_example.py
"""

import json
import os
import subprocess
import sys
import tempfile

def run_agsec(*args, stdin_data=None):
    """Run agsec CLI command and return output."""
    cmd = [sys.executable, "-m", "agsec.cli.main"] + list(args)
    result = subprocess.run(
        cmd,
        input=stdin_data,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def main():
    # Use a temp directory for this demo
    original_dir = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chdir(tmpdir)

        print("=== Observe Mode Demo ===\n")

        # Step 1: Init in observe mode
        print("1. Initialize in observe mode:")
        stdout, _, _ = run_agsec("init", "--observe")
        print(f"   {stdout.split(chr(10))[0]}")
        print()

        # Step 2: Simulate agent actions
        print("2. Simulate agent actions (all will be ALLOWED in observe mode):\n")

        actions = [
            ("Bash", {"command": "ls -la"}, "list files"),
            ("Bash", {"command": "cat .env"}, "read secrets"),
            ("Write", {"file_path": ".env", "content": "SECRET=x"}, "write to .env"),
            ("Bash", {"command": "git push --force origin main"}, "force push"),
            ("Read", {"file_path": "app.py"}, "read source"),
        ]

        policy_dir = os.path.join(tmpdir, "policies")
        for tool_name, tool_input, desc in actions:
            data = json.dumps({
                "tool_name": tool_name,
                "tool_input": tool_input,
            })
            _, stderr, code = run_agsec(
                "check", "--policy-dir", policy_dir,
                stdin_data=data,
            )
            status = "ALLOWED" if code == 0 else "BLOCKED"
            print(f"   {status}  {desc:20s}  ({tool_name}: {json.dumps(tool_input)[:50]})")

        # Step 3: Check audit stats
        print("\n3. Check what would have been blocked:\n")
        stdout, _, _ = run_agsec("audit", "--stats")
        for line in stdout.split("\n"):
            print(f"   {line}")

        # Step 4: Switch to enforce
        print("\n4. Switch to enforce mode:")
        stdout, _, _ = run_agsec("enforce")
        print(f"   {stdout.split(chr(10))[0]}")

        # Step 5: Try the same actions again
        print("\n5. Same actions, now in enforce mode:\n")

        for tool_name, tool_input, desc in actions:
            data = json.dumps({
                "tool_name": tool_name,
                "tool_input": tool_input,
            })
            _, stderr, code = run_agsec(
                "check", "--policy-dir", policy_dir,
                stdin_data=data,
            )
            status = "ALLOWED" if code == 0 else "BLOCKED"
            print(f"   {status}  {desc:20s}  ({tool_name}: {json.dumps(tool_input)[:50]})")

        os.chdir(original_dir)

    print("\n=== Done ===")


if __name__ == "__main__":
    main()
