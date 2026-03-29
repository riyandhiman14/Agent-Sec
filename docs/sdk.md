# SDK Usage

Use agsec programmatically in Python without the CLI.

## ControlLayer

The main orchestrator — registers actions, evaluates policies, executes with audit logging.

```python
from agsec import ControlLayer

control = ControlLayer(policy_dir="./policies/")

@control.register_action("payment.charge")
async def charge(amount, recipient):
    return {"charged": amount, "to": recipient}

result = await control.execute(
    "payment.charge",
    {"amount": 500, "recipient": {"country": "US"}},
    context={"user_role": "agent"}
)
print(result.policy.status)  # PolicyStatus.ALLOW
print(result.result)         # {"charged": 500, ...}
```

### Sync Usage

```python
result = control.execute_sync("payment.charge", {"amount": 500, ...})
```

### Dry Run

Check policy without executing:

```python
policy = await control.dry_run("payment.charge", {"amount": 50000})
print(policy.status)   # PolicyStatus.REVIEW

# Sync
policy = control.dry_run_sync("payment.charge", {"amount": 50000})
```

### Hooks

```python
@control.before_hook
def log_action(action, params, context):
    print(f"About to execute: {action}")

@control.after_hook
def log_result(exec_result):
    print(f"Result: {exec_result.result}")
```

### Context Manager

```python
with ControlLayer(policy_dir="./policies/") as control:
    result = control.execute_sync("action", {})
# Connection automatically closed
```

## PolicyEngine

Direct access to the policy evaluation engine.

```python
from agsec.policy import PolicyEngine

engine = PolicyEngine()
engine.load_from_directory("./policies/")

result = engine.evaluate("bash.execute", {"command": "rm -rf /"})
print(result.status)              # PolicyStatus.BLOCK
print(result.reason)              # "Agents should not delete files"
print(result.metadata["sid"])     # "BlockFileDelete"
print(result.metadata["matched_by"])  # "explicit_deny"
```

### LayeredPolicyEngine

Compose multiple policy engines as layers — like AWS IAM permission boundaries. Each layer is a gate: all must allow.

```python
from agsec.policy import PolicyEngine, LayeredPolicyEngine

layered = LayeredPolicyEngine()

# Project policies (default deny)
project = PolicyEngine()
project.load_from_directory("./policies/")
layered.add_layer("project", project)

# Agent-specific restrictions (default allow — can only add restrictions)
from agsec.types import PolicyStatus
agent = PolicyEngine()
agent.load_from_directory("~/.agsec/agents/my-agent/")
agent._default = PolicyStatus.ALLOW
layered.add_layer("agent", agent)

result = layered.evaluate("bash.execute", {"command": "ls"})
```

### Validation

```python
# Validate without loading
issues = engine.validate_directory("./policies/")
# Returns {"filename": ["issue1", "issue2"]} — empty means valid

issues = engine.validate_file("policy.yaml")
```

## AuditStore

SQLite-backed audit logging.

```python
from agsec.audit import AuditStore

with AuditStore("./audit.db") as audit:
    executions = audit.get_executions(action="payment.charge", limit=50)
    stats = audit.get_execution_stats()
    audit.export_to_json("export.json")

    # Time-filtered queries
    recent = audit.get_executions_since(hours=24)

    # Retention
    deleted = audit.prune(days=7)      # delete records older than 7 days
    deleted = audit.clear()             # delete all records
```

Stats returns:
```python
{"total_executions": 142, "allowed": 100, "blocked": 30, "reviewed": 12, "errors": 0}
```

Auto-prune via environment variable:
```bash
export AGSEC_AUDIT_RETENTION_DAYS=7
```

## Types

```python
from agsec.types import PolicyStatus, PolicyResult, ActionExecutionResult

# PolicyStatus enum
PolicyStatus.ALLOW
PolicyStatus.BLOCK
PolicyStatus.REVIEW
```

## Exceptions

All exceptions inherit from `AgsecError`:

```python
from agsec.exceptions import PolicyViolationError, ActionExecutionError

try:
    result = control.execute_sync("action", {})
except PolicyViolationError as e:
    print(e.code)      # "POLICY_VIOLATION"
    print(e.details)   # {"action": "...", "reason": "..."}
except ActionExecutionError as e:
    print(e.original_error)
```
