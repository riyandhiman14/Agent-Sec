"""
agsec quickstart — load policies from a directory, register actions, execute.
"""

import os
from agsec import ControlLayer

# Load all policies from the policies/ directory
policy_dir = os.path.join(os.path.dirname(__file__), "policies")
control = ControlLayer(policy_dir=policy_dir)


# Register actions
@control.register_action("payment.charge")
def charge_payment(amount, recipient):
    return {"charged": amount, "to": recipient}


@control.register_action("email.send")
def send_email(to, subject, body):
    return {"sent_to": to, "subject": subject}


@control.register_action("db.read")
def db_read(table, query):
    return {"table": table, "rows": 42}


@control.register_action("db.delete")
def db_delete(table, id):
    return {"deleted": id}


# --- Try it out ---

if __name__ == "__main__":
    context = {"auth_token": "valid-token", "user_role": "user"}

    # 1. Allowed: small payment
    result = control.execute_sync("payment.charge", {"amount": 500, "recipient": {"country": "US"}}, context)
    print(f"Small payment: {result.policy.status.value} -> {result.result}")

    # 2. Review: large payment
    result = control.execute_sync("payment.charge", {"amount": 50000, "recipient": {"country": "US"}}, context)
    print(f"Large payment: {result.policy.status.value} (needs review)")

    # 3. Blocked: destructive op as non-admin
    try:
        control.execute_sync("db.delete", {"table": "users", "id": 1}, context)
    except Exception as e:
        print(f"Delete: BLOCKED — {e}")

    # 4. Allowed: read op
    result = control.execute_sync("db.read", {"table": "users", "query": "SELECT *"}, context)
    print(f"Read: {result.policy.status.value} -> {result.result}")

    # 5. Dry-run: check without executing
    policy = control.dry_run_sync("payment.charge", {"amount": 100000, "recipient": {"country": "US"}}, context)
    print(f"Dry-run 100k payment: {policy.status.value} (sid={policy.metadata.get('sid')})")
