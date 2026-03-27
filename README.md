# agsec

[![PyPI version](https://badge.fury.io/py/agsec.svg)](https://pypi.org/project/agsec/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**An action firewall for AI agents.** Before an agent can do anything in the real world, it must pass through agsec.

```
Agent wants to act  -->  agsec evaluates policy  -->  allow / block / review  -->  real world
```

---

## The Problem

AI agents interact with the real world — shell commands, file writes, API calls, payments. Each platform handles safety differently: some have permission prompts, some have sandboxes, some have nothing. But none offer:

- **Declarative, auditable policies** — like AWS IAM, but for agent actions
- **Consistent rules across platforms** — same policies for Claude Code, Codex, or your custom agent
- **Granular control** — not just "allow bash" or "block bash", but "block bash commands matching this pattern when this condition is true"
- **Audit trail** — who did what, when, and what policy applied

Built-in controls are binary (allow/block) and platform-specific. Teams running agents in production need policy-as-code with full visibility.

## The Solution

agsec is an **IAM-style policy engine** for agent actions. Define what's allowed, what's blocked, and what needs human review — in YAML files, like AWS IAM policies.

```yaml
# policies/02_bash.yaml
version: "1.0"
default: deny

statements:
  - sid: "BlockFileDelete"
    effect: deny
    actions: ["bash.execute"]
    conditions:
      params.command:
        op: "regex"
        value: "\\brm\\s"
    reason: "Agents should not delete files"

  - sid: "AllowBash"
    effect: allow
    actions: ["bash.execute"]
```

**Deny always wins.** Just like IAM.

---

## Quick Start

### Install

```bash
pip install agsec
```

### 1. Initialize policies

```bash
agsec init
```

Creates a `policies/` directory with 5 default safety policies:

```
policies/
  01_base.yaml       # Default deny, allow reads
  02_bash.yaml       # Block rm, DROP TABLE, secret access
  03_files.yaml      # Block writes to .env, system dirs
  04_web.yaml        # Review external HTTP requests
  05_git.yaml        # Block force push, protected branches
```

### 2. Hook into your agent

```bash
# Claude Code
agsec install claude-code

# OpenAI Codex
agsec install codex
```

That's it. The firewall is active. Every tool call is checked against your policies.

### 3. Manage policies

```bash
# List all active policies
agsec policy list

# Add a new policy interactively
agsec policy add

# Remove a policy
agsec policy remove BlockFileDelete

# Validate policy files
agsec validate
```

### 4. View audit logs

```bash
# Recent actions
agsec audit

# Summary stats
agsec audit --stats
```

---

## How It Works

### Runtime Enforcement

agsec integrates at the **runtime level** of supported agent platforms. Every action the agent attempts — shell commands, file writes, web requests, API calls — is intercepted and evaluated against your policies *before* execution.

The agent **cannot bypass** the firewall. Enforcement happens outside the agent's control.

**Supported platforms:**
- Claude Code
- OpenAI Codex
- Any agent via the Python SDK

### IAM-Style Policy Evaluation

Evaluation order (same as AWS IAM):

1. **Explicit deny always wins** — if any deny rule matches, action is blocked
2. **Review trumps allow** — if a review rule matches, action needs human approval
3. **Explicit allow** — if an allow rule matches, action proceeds
4. **Default policy** — if nothing matches, fall back to default (deny recommended)

---

## Policy Format

Policies are YAML files in a `policies/` directory. All files are loaded and merged automatically.

### Full Schema

```yaml
version: "1.0"
default: deny          # deny | allow

statements:
  - sid: "UniqueId"    # Statement ID (for audit trail)
    effect: deny       # deny | allow | review
    actions:           # Glob patterns
      - "bash.execute"
      - "file.write"
      - "payment.*"
      - "*.delete"
    conditions:        # Optional — when to apply
      params.amount:
        op: ">"
        value: 10000
      context.user_role:
        op: "=="
        value: "admin"
    match: all         # all | any (condition logic)
    reason: "Human-readable explanation"
```

### Action Names

agsec uses a consistent naming scheme for actions:

| Action | What It Covers |
|---|---|
| `bash.execute` | Shell commands |
| `file.write` | File creation |
| `file.edit` | File modification |
| `file.read` | File reading |
| `web.fetch` | HTTP requests |
| `web.search` | Web searches |
| `file.glob` | File pattern search |
| `file.grep` | Content search |
| `agent.spawn` | Sub-agent creation |
| `mcp.*` | Any MCP tool calls |

Use glob patterns in policies: `payment.*`, `*.delete`, `mcp.slack.*`

### Condition Operators

| Operator | Description | Example |
|---|---|---|
| `==` | Equals | `value: "admin"` |
| `!=` | Not equals | `value: "guest"` |
| `>` `<` `>=` `<=` | Comparison | `value: 10000` |
| `in` | In list | `value: ["US", "UK"]` |
| `not_in` | Not in list | `value: ["KP", "IR"]` |
| `contains` | Substring match | `value: ".env"` |
| `starts_with` | Prefix match | `value: "https://api."` |
| `ends_with` | Suffix match | `value: ".com"` |
| `regex` | Regex match | `value: "rm\\s+-rf"` |
| `exists` | Field is present | *(no value needed)* |
| `not_exists` | Field is absent | *(no value needed)* |

### Deep Nested Access

Access nested fields with dot notation:

```yaml
conditions:
  params.recipient.country:
    op: "in"
    value: ["KP", "IR", "SY"]
  context.request.headers.origin:
    op: "ends_with"
    value: ".internal.com"
```

---

## SDK Usage (Programmatic)

Use agsec directly in your Python code, without the CLI:

```python
from agsec import ControlLayer

# Load policies from directory
control = ControlLayer(policy_dir="./policies/")

# Register actions
@control.register_action("payment.charge")
async def charge(amount, recipient):
    return {"charged": amount, "to": recipient}

# Execute with policy enforcement
result = await control.execute(
    "payment.charge",
    {"amount": 500, "recipient": {"country": "US"}},
    context={"user_role": "agent"}
)
print(result.policy.status)  # PolicyStatus.ALLOW
print(result.result)         # {"charged": 500, "to": {"country": "US"}}
```

### Sync Usage

```python
result = control.execute_sync("payment.charge", {"amount": 500, ...})
```

### Dry Run (Check Without Executing)

```python
# Async
policy = await control.dry_run("payment.charge", {"amount": 50000})
print(policy.status)   # PolicyStatus.REVIEW
print(policy.reason)   # "Large payments require review"

# Sync
policy = control.dry_run_sync("payment.charge", {"amount": 50000})
```

### Hooks (Before/After Execution)

```python
control = ControlLayer(policy_dir="./policies/")

@control.before_hook
def log_action(action, params, context):
    print(f"About to execute: {action}")

@control.after_hook
def log_result(exec_result):
    print(f"Result: {exec_result.result}")
```

### Policy Engine Direct Access

```python
from agsec.policy import PolicyEngine

engine = PolicyEngine()
engine.load_from_directory("./policies/")

# Evaluate
result = engine.evaluate("bash.execute", {"command": "rm -rf /"})
print(result.status)              # PolicyStatus.BLOCK
print(result.reason)              # "Agents should not delete files"
print(result.metadata["sid"])     # "BlockFileDelete"
print(result.metadata["matched_by"])  # "explicit_deny"

# Validate policies without loading
issues = engine.validate_directory("./policies/")
```

### Audit Store

```python
from agsec.audit import AuditStore

audit = AuditStore("./audit.db")

# Query logs
executions = audit.get_executions(action="payment.charge", limit=50)

# Get stats
stats = audit.get_execution_stats()
# {"total_executions": 142, "allowed": 100, "blocked": 30, "reviewed": 12, "errors": 0}

# Export
audit.export_to_json("audit_export.json")
```

---

## CLI Reference

| Command | Description |
|---|---|
| `agsec init` | Create `policies/` with default safety policies |
| `agsec policy list` | List all active policy statements |
| `agsec policy add` | Add a new policy (interactive) |
| `agsec policy remove <sid>` | Remove a policy by statement ID |
| `agsec validate [path]` | Validate policy files for errors |
| `agsec install claude-code` | Activate firewall for Claude Code |
| `agsec install codex` | Activate firewall for OpenAI Codex |
| `agsec audit` | View recent audit logs |
| `agsec audit --stats` | View summary statistics |

---

## Default Policies

`agsec init` ships with these out of the box:

**01_base.yaml** - Default deny. Allow read operations and agent spawning.

**02_bash.yaml** - Block `rm` (all forms), `DROP TABLE`, `TRUNCATE`, secret access via `cat .env`, data exfiltration via `curl --data`. Allow other bash.

**03_files.yaml** - Block writes to `.env`, `credentials.json`, `secrets.yaml`, `.ssh/`, `.aws/credentials`, system directories (`/etc/`, `/usr/`). Allow other writes.

**04_web.yaml** - Review all external HTTP fetches. Allow localhost. Allow web search.

**05_git.yaml** - Block `git push --force`, push to `main`/`master`/`production`, `git reset --hard`, `git clean -f`.

---

## Contributing

```bash
git clone https://github.com/riyandhiman14/Agent-Sec.git
cd agsec
pip install -e ".[dev]"
pytest
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
