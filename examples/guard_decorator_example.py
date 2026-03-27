"""
agsec @guard decorator — protect any Python function with policies.

No framework needed. Works with any code.
"""

import os
from agsec import guard

# Point to policies directory
policy_dir = os.path.join(os.path.dirname(__file__), "policies")


# --- Protect functions with one decorator ---

@guard("email.send", policy_dir=policy_dir)
def send_email(to, subject, body):
    return {"sent_to": to, "subject": subject}


@guard("payment.charge", policy_dir=policy_dir)
def charge_payment(amount, recipient):
    return {"charged": amount, "to": recipient}


@guard("db.read", policy_dir=policy_dir)
def read_database(table, query):
    return {"table": table, "rows": 42}


# --- Async works too ---

@guard("notification.push", policy_dir=policy_dir)
async def send_push(user_id, message):
    return {"sent_to": user_id}


# --- Try it out ---

if __name__ == "__main__":
    from agsec.exceptions import PolicyViolationError

    # Allowed
    result = read_database(table="users", query="SELECT *")
    print(f"DB read: {result}")

    # Allowed (small payment)
    result = charge_payment(amount=50, recipient={"country": "US"})
    print(f"Small payment: {result}")

    # Blocked (large payment triggers review)
    try:
        charge_payment(amount=50000, recipient={"country": "US"})
    except PolicyViolationError as e:
        print(f"Large payment: BLOCKED — {e}")

    # Blocked (email to external domain)
    try:
        send_email(to="hacker@evil.com", subject="secrets", body="...")
    except PolicyViolationError as e:
        print(f"External email: BLOCKED — {e}")
