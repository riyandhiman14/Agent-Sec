# Contributing to agsec

## Setup

```bash
git clone https://github.com/riyandhiman14/Agent-Sec.git
cd agsec
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest                    # all tests
pytest tests/ -q          # quiet mode
pytest tests/ -v          # verbose
pytest tests/test_cli_check.py  # specific file
```

## Code Style

The project uses:
- **Black** for formatting (line length 88)
- **isort** for import sorting
- **flake8** for linting

Run before committing:
```bash
black agsec/ tests/
isort agsec/ tests/
flake8 agsec/ tests/
```

## Project Structure

```
agsec/
  types.py                  # Core types (PolicyStatus, PolicyResult)
  control.py                # ControlLayer orchestrator
  registry.py               # Action registry
  guard.py                  # Generic @guard decorator
  policy/                   # Policy engine
    engine.py               # PolicyEngine (IAM evaluation)
    statement.py            # Statement dataclass
    conditions.py           # Operators, matching
    resolvers.py            # Deep value resolution
    loaders.py              # YAML parsing
  audit/
    store.py                # SQLite audit logging
  exceptions/               # Structured exception hierarchy
  integrations/
    _base.py                # Shared PolicyChecker
    conditions.py           # Fluent API (param, allow, deny, review)
    langchain.py            # LangChain integration
    openai.py               # OpenAI SDK integration
    anthropic.py            # Anthropic SDK integration
  cli/
    main.py                 # CLI entrypoint
    mapping.py              # Tool name -> action mapping
    config.py               # Policy/audit/config discovery
    commands/               # CLI subcommands
  templates/
    policies/               # Default policy files
```

## Adding a New Integration

1. Create `agsec/integrations/your_framework.py`
2. Use `PolicyChecker` from `_base.py` for policy evaluation
3. Use `ToolRule`, `allow`, `deny`, `review`, `param` from `conditions.py` for fluent API
4. Add optional dependency in `pyproject.toml`
5. Write tests in `tests/test_integrations_your_framework.py`
6. Document in `docs/integrations.md`

## Pull Request Process

1. Fork and create a feature branch
2. Write tests for new functionality
3. Ensure all tests pass (`pytest`)
4. Update docs if needed
5. Submit PR against `main`
