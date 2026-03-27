"""
@guard decorator example — protect any Python function.

No framework needed. Works with any code.

Run: pip install agsec
     python examples/guard_decorator_example.py
"""

import asyncio
import os
import tempfile

from agsec import guard
from agsec.exceptions import PolicyViolationError


def main():
    # Create a temp policy directory for this demo
    with tempfile.TemporaryDirectory() as policy_dir:
        # Write a simple policy
        with open(os.path.join(policy_dir, "policy.yaml"), "w") as f:
            f.write("""
version: "1.0"
default: deny

statements:
  - sid: "BlockExternalEmail"
    effect: deny
    actions: ["email.send"]
    conditions:
      params.to:
        op: "regex"
        value: '.*@(?!company\.com$)'
    reason: "External emails are blocked"

  - sid: "AllowEmail"
    effect: allow
    actions: ["email.send"]

  - sid: "AllowSmallPayments"
    effect: allow
    actions: ["payment.charge"]
    conditions:
      params.amount:
        op: "<="
        value: 1000

  - sid: "ReviewLargePayments"
    effect: review
    actions: ["payment.charge"]
    conditions:
      params.amount:
        op: ">"
        value: 1000
    reason: "Large payments need approval"

  - sid: "AllowRead"
    effect: allow
    actions: ["db.read"]

  - sid: "BlockWrite"
    effect: deny
    actions: ["db.write"]
    reason: "Database writes are blocked"
""")

        # --- Decorate your functions ---

        @guard("email.send", policy_dir=policy_dir)
        def send_email(to, subject, body):
            return f"Sent to {to}: {subject}"

        @guard("payment.charge", policy_dir=policy_dir)
        def charge_payment(amount, currency="USD"):
            return f"Charged {currency} {amount}"

        @guard("db.read", policy_dir=policy_dir)
        def read_db(table, query):
            return f"Read {table}: {query}"

        @guard("db.write", policy_dir=policy_dir)
        def write_db(table, data):
            return f"Wrote to {table}"

        @guard("notification.push", policy_dir=policy_dir)
        async def push_notification(user_id, message):
            return f"Notified {user_id}: {message}"

        # --- Test them ---

        print("=== @guard Decorator Examples ===\n")

        # Internal email: ALLOWED
        try:
            result = send_email(to="alice@company.com", subject="Meeting", body="Hi!")
            print(f"  Internal email:   ALLOWED -> {result}")
        except PolicyViolationError as e:
            print(f"  Internal email:   BLOCKED -> {e}")

        # External email: BLOCKED
        try:
            result = send_email(to="hacker@evil.com", subject="Secrets", body="...")
            print(f"  External email:   ALLOWED -> {result}")
        except PolicyViolationError as e:
            print(f"  External email:   BLOCKED")

        # Small payment: ALLOWED
        try:
            result = charge_payment(amount=50)
            print(f"  Small payment:    ALLOWED -> {result}")
        except PolicyViolationError as e:
            print(f"  Small payment:    BLOCKED")

        # Large payment: REVIEW (blocked with review reason)
        try:
            result = charge_payment(amount=50000)
            print(f"  Large payment:    ALLOWED -> {result}")
        except PolicyViolationError as e:
            print(f"  Large payment:    REVIEW REQUIRED")

        # DB read: ALLOWED
        try:
            result = read_db(table="users", query="SELECT *")
            print(f"  DB read:          ALLOWED -> {result}")
        except PolicyViolationError as e:
            print(f"  DB read:          BLOCKED")

        # DB write: BLOCKED
        try:
            result = write_db(table="users", data={"name": "hacker"})
            print(f"  DB write:         ALLOWED -> {result}")
        except PolicyViolationError as e:
            print(f"  DB write:         BLOCKED")

        # Async function: BLOCKED (no allow policy for notification.push)
        try:
            result = asyncio.run(push_notification(user_id="u1", message="hello"))
            print(f"  Push notification: ALLOWED -> {result}")
        except PolicyViolationError as e:
            print(f"  Push notification: BLOCKED (default deny)")


if __name__ == "__main__":
    main()
