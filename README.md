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
- ✅ **Audit Logging**: Built-in persistent audit store for compliance
- ✅ **Async Support**: Full async/await support for modern agent stacks
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
import asyncio
from agsec import ControlLayer

async def main():
    # Create control layer
    control = ControlLayer()

    # Register an action (sync or async)
    @control.register_action("send_email")
    async def send_email(to, subject, body):
        # Simulate async email sending
        await asyncio.sleep(0.1)
        return {"sent_to": to, "status": "success"}

    # Execute with default allow policy
    result = await control.execute("send_email", {"to": "user@example.com", "subject": "Hello", "body": "Hi!"})
    print(result.result)  # {"sent_to": "user@example.com", "status": "success"}

    # View audit logs
    executions = control.audit_store.get_executions()
    print(f"Total executions: {len(executions)}")

asyncio.run(main())
```

### With YAML Policies

```python
import asyncio
from agsec import ControlLayer

async def main():
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
    async def payment(amount):
        await asyncio.sleep(0.1)  # Simulate async payment processing
        return {"charged": amount}

    try:
        await control.execute("payment", {"amount": 15000})
    except Exception as e:
        print(e)  # PolicyViolationError: High-value payment blocked

asyncio.run(main())
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

- `register_action(name)`: Decorator to register an action function (supports both sync and async functions)
- `async execute(action, params, context=None)`: Execute an action with policy check (async)

### PolicyEngine

Handles policy evaluation.

#### Methods

- `add_rule(rule)`: Add a programmatic rule function
- `load_rules_from_yaml(yaml_text)`: Load rules from YAML string
- `load_rules_from_yaml_file(path)`: Load rules from YAML file
- `evaluate(action, params, context=None)`: Evaluate policy for action

### AuditStore

Persistent storage for execution logs and compliance.

```python
AuditStore(db_path="audit.db")  # File-based, or ":memory:" for in-memory
```

#### Methods

- `log_execution(execution, context, error)`: Log an execution result
- `get_executions(action, limit, offset)`: Query execution history
- `get_execution_stats()`: Get summary statistics
- `export_to_json(file_path)`: Export logs to JSON

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

## Error Handling

agsec provides a comprehensive exception hierarchy for robust error handling in production environments. All exceptions inherit from `AgsecError` and include structured error codes and detailed context.

### Exception Hierarchy

```
AgsecError (base)
├── ConfigurationError
│   ├── InvalidConfigError
│   ├── MissingConfigError
│   └── ConfigValidationError
├── RegistryError
│   ├── ActionNotFoundError
│   ├── DuplicateActionError
│   ├── InvalidActionError
│   └── RegistryFullError
├── PolicyError
│   ├── PolicyParseError
│   ├── InvalidPolicyError
│   ├── PolicyConflictError
│   ├── PolicyTimeoutError
│   └── PolicyViolationError
├── ActionExecutionError
├── AuditError
│   ├── AuditConnectionError
│   ├── AuditIntegrityError
│   └── AuditStorageError
├── ValidationError
│   ├── ParameterValidationError
│   ├── TypeValidationError
│   └── SchemaValidationError
├── SecurityError
│   ├── SecurityViolationError
│   ├── TamperingError
│   └── IntegrityError
├── InitializationError
│   ├── DependencyError
│   └── EnvironmentError
└── RuntimeError
    ├── TimeoutError
    ├── ResourceError
    └── ConcurrencyError
```

### Error Handling Example

```python
from agsec import ControlLayer
from agsec.exceptions import (
    PolicyViolationError,
    ActionExecutionError,
    ConfigurationError
)

control = ControlLayer()

try:
    result = control.execute("payment", {"amount": 10000})
except PolicyViolationError as e:
    print(f"Policy blocked: {e.details['reason']}")
    # Handle policy violation
except ActionExecutionError as e:
    print(f"Action failed: {e.details['original_error']}")
    # Handle execution error
except ConfigurationError as e:
    print(f"Config error: {e.details}")
    # Handle configuration issues
```

### Error Details

All exceptions provide:
- **Error code**: Machine-readable identifier (e.g., `"POLICY_VIOLATION"`)
- **Structured details**: Context-specific information in `details` dict
- **Descriptive message**: Human-readable error description

Common error codes:
- `ACTION_NOT_FOUND`: Action not registered
- `POLICY_VIOLATION`: Policy blocked the action
- `ACTION_EXECUTION_ERROR`: Action execution failed
- `INVALID_CONFIG`: Configuration file invalid
- `DEPENDENCY_ERROR`: Required dependency missing
- `TIMEOUT_ERROR`: Operation timed out

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

