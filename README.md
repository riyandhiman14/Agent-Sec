# agsec

AI Agent Action Firewall

## Overview

Minimal open-source control layer for agent actions.

## Development

### Setup

```bash
pip install -e .[dev]
pre-commit install
```

Or for minimal install:
```bash
pip install -e .
```

### Quick start

```python
from agsec import ControlLayer, PolicyEngine

control = ControlLayer(policy_engine=PolicyEngine())

@control.register_action("send_email")
def send_email(to, subject, body):
    return {"sent_to": to, "subject": subject}

# simple policy: block high-value payments
control.policy_engine.add_rule(lambda action, params, ctx: ("block" if action == "payment" and params.get("amount",0)>10000 else None))

result = control.execute("send_email", {"to":"x@example.com", "subject":"hi", "body":"hello"})
print(result)
```

### YAML Policy Example

```yaml
rules:
  - action: payment
    status: block
    reason: "High-value payment blocked"
    conditions:
      amount:
        op: ">"
        value: 10000
```

```python
from agsec import ControlLayer

policy_yaml = """
rules:
  - action: payment
    status: block
    reason: "High-value payment blocked"
    conditions:
      amount:
        op: ">"
        value: 10000
"""

control = ControlLayer(policy_yaml=policy_yaml)

@control.register_action("payment")
def payment(amount):
    return {"charged": amount}

try:
    control.execute("payment", {"amount": 15000})
except Exception as e:
    print(e)
```

