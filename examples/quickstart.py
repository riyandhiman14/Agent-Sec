"""
agsec quickstart — the simplest possible example.

Run: pip install agsec
     python examples/quickstart.py
"""

import os
import tempfile

from agsec import ControlLayer
from agsec.exceptions import PolicyViolationError


def main():
    # Create a temp policy directory
    with tempfile.TemporaryDirectory() as policy_dir:
        with open(os.path.join(policy_dir, "policy.yaml"), "w") as f:
            f.write("""
version: "1.0"
default: deny

statements:
  - sid: "AllowRead"
    effect: allow
    actions: ["db.read", "db.list"]

  - sid: "BlockDelete"
    effect: deny
    actions: ["db.delete", "db.drop"]
    reason: "Destructive operations blocked"

  - sid: "ReviewWrite"
    effect: review
    actions: ["db.write"]
    conditions:
      params.table:
        op: "=="
        value: "users"
    reason: "User table writes need approval"

  - sid: "AllowWrite"
    effect: allow
    actions: ["db.write"]
""")

        # Create the control layer
        with ControlLayer(policy_dir=policy_dir) as control:

            @control.register_action("db.read")
            def read(table):
                return {"table": table, "rows": 42}

            @control.register_action("db.write")
            def write(table, data):
                return {"table": table, "written": True}

            @control.register_action("db.delete")
            def delete(table, id):
                return {"deleted": id}

            print("=== agsec Quickstart ===\n")

            # ALLOWED: read
            result = control.execute_sync("db.read", {"table": "products"})
            print(f"  db.read('products'):  {result.policy.status.value} -> {result.result}")

            # ALLOWED: write to non-users table
            result = control.execute_sync("db.write", {"table": "products", "data": {"name": "Widget"}})
            print(f"  db.write('products'): {result.policy.status.value} -> {result.result}")

            # REVIEW: write to users table
            result = control.execute_sync("db.write", {"table": "users", "data": {"name": "Bob"}})
            print(f"  db.write('users'):    {result.policy.status.value} (needs approval)")

            # BLOCKED: delete
            try:
                control.execute_sync("db.delete", {"table": "users", "id": 1})
            except PolicyViolationError:
                print(f"  db.delete('users'):   block (destructive operations blocked)")

            # DRY RUN: check without executing
            policy = control.dry_run_sync("db.delete", {"table": "anything"})
            print(f"\n  Dry run db.delete:    {policy.status.value} (sid: {policy.metadata.get('sid')})")


if __name__ == "__main__":
    main()
