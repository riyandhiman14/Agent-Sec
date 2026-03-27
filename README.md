# agsec

AI Agent Action Firewall

## Overview

Minimal open-source control layer for agent actions.

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
