# agsec

[![PyPI version](https://badge.fury.io/py/agsec.svg)](https://pypi.org/project/agsec/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

AI Agent Action Firewall - A minimal, control layer for agent actions.

## Overview

`agsec` provides a simple yet powerful way to add safety controls to AI agents. It acts as a "firewall" between agents and real-world actions, allowing you to define policies that approve, block, or review actions before execution.

### Why agsec?

- **Agent-neutral**: Works with any agent framework (LangChain, custom, etc.)
- **Declarative policies**: Define rules in YAML or code
- **Extensible**: Plugin system for custom actions and policies
- **Production-ready**: Lightweight, fast, and secure

## Features

- ✅ **Action Registry**: Register and manage agent actions
- ✅ **Policy Engine**: Flexible rule-based decision making
- ✅ **YAML Policies**: Human-readable policy definitions
- ✅ **Context Awareness**: Rules can access parameters and context
- ✅ **Priority & Matching**: Advanced rule evaluation (priority, all/any matching)
- ✅ **Audit Logging**: Built-in logging for all decisions
- ✅ **Python Package**: Easy installation via PyPI

## Installation

### Runtime (for users)

```bash
pip install agsec
```

### Development (for contributors)

```bash
git clone https://github.com/riyandhiman14/Agent-Sec.git
cd agsec
pip install -e .[dev]
pre-commit install
```

## Quick Start

### Basic Usage

```python
from agsec import ControlLayer

# Create control layer
control = ControlLayer()

# Register an action
@control.register_action("send_email")
def send_email(to, subject, body):
    return {"sent_to": to, "status": "success"}

# Execute with default allow policy
result = control.execute("send_email", {"to": "user@example.com", "subject": "Hello", "body": "Hi!"})
print(result.result)  # {"sent_to": "user@example.com", "status": "success"}
```

### With YAML Policies

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
    print(e)  # PolicyViolationError: High-value payment blocked
```

## API Reference

### ControlLayer

Main class for managing agent actions and policies.

```python
ControlLayer(
    policy_engine=None,      # PolicyEngine instance
    action_registry=None,    # ActionRegistry instance
    logger=None,             # Custom logger
    policy_yaml=None,        # YAML policy string
    policy_yaml_path=None    # Path to YAML policy file
)
```

#### Methods

- `register_action(name)`: Decorator to register an action function
- `execute(action, params, context=None)`: Execute an action with policy check

### PolicyEngine

Handles policy evaluation.

#### Methods

- `add_rule(rule)`: Add a programmatic rule function
- `load_rules_from_yaml(yaml_text)`: Load rules from YAML string
- `load_rules_from_yaml_file(path)`: Load rules from YAML file
- `evaluate(action, params, context=None)`: Evaluate policy for action

### Policy Status

- `PolicyStatus.ALLOW`: Allow action execution
- `PolicyStatus.BLOCK`: Block action execution
- `PolicyStatus.REVIEW`: Mark for manual review

### YAML Policy Schema

```yaml
rules:
  - action: "action_name"          # Action to match (* for all)
    status: "allow|block|review"   # Decision
    reason: "Optional reason"      # Human-readable explanation
    priority: 0                    # Higher = evaluated first
    match: "all|any"               # Condition matching mode
    conditions:                    # Parameter/context checks
      param_name:
        op: "==|!=|>|<|>=|<=|in|not_in"
        value: "expected_value"
      context.user_role:
        op: "=="
        value: "admin"
```

## Development

### Setup

```bash
pip install -e .[dev]
pre-commit install
```

### Testing

```bash
pytest
```

### Building

```bash
python -m build
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run `pre-commit run --all-files`
6. Submit a pull request

### Code Style

- Black for formatting
- isort for import sorting
- flake8 for linting
- pytest for testing

## Roadmap

- [ ] Advanced risk scoring
- [ ] Multi-agent coordination

## Support

- Issues: [GitHub Issues](https://github.com/riyandhiman14/Agent-Sec/issues)
- Discussions: [GitHub Discussions](https://github.com/riyandhiman14/Agent-Sec/discussions)

