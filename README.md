# agsec

[![PyPI version](https://badge.fury.io/py/agsec.svg)](https://pypi.org/project/agsec/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Action firewall for AI agents.** Before an agent can do anything, it passes through agsec.

```
Agent wants to act  -->  agsec evaluates policy  -->  allow / block / review  -->  real world
```

## Why

AI agents get real access to real systems. agsec gives you one policy layer across all of them — declarative YAML policies, runtime enforcement, full audit trail. Like AWS IAM, but for what agents can do.

## Quick Start

```bash
pip install agsec
agsec init                     # create default policies
agsec install claude-code      # activate firewall
```

Done. Every tool call is now checked. `rm -rf` blocked, `.env` writes blocked, force push blocked — out of the box.

### Start in Observe Mode

Not ready to block? Audit everything first, block nothing:

```bash
agsec init --observe           # log only, no blocking
agsec audit --stats            # see what would be blocked
agsec enforce                  # start blocking when ready
```

## Integrations

### Claude Code / Codex (hooks)

```bash
agsec install claude-code
agsec install codex
```

### LangChain (one line)

```python
from agsec.integrations.langchain import guard, allow, deny, review, param

agent = create_react_agent(llm, guard(
    allow(search, calculator),
    review(send_email),
    deny(delete_record),
    deny(payment).when(param("amount") > 10000),
))
```

### OpenAI / Anthropic / OpenRouter (one line)

```python
from agsec.integrations.openai import protect, deny, param

client = protect(OpenAI(),
    deny("delete_user"),
    deny("payment").when(param("amount") > 10000),
)
# Works with OpenRouter, Groq, Together — anything OpenAI-compatible
```

### Any Python function

```python
from agsec import guard

@guard("email.send")
def send_email(to, subject, body):
    ...
```

## Policy Example

```yaml
version: "1.0"
default: deny

statements:
  - sid: "AllowReadOps"
    effect: allow
    actions: ["file.read", "file.glob", "file.grep"]

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

Deny always wins. Same evaluation order as AWS IAM.

## CLI

```bash
agsec init [--observe]         # scaffold policies
agsec install claude-code      # activate for Claude Code
agsec install codex            # activate for Codex
agsec policy list              # see all rules
agsec policy add               # add a rule (interactive)
agsec policy remove <sid>      # remove a rule
agsec validate                 # check for errors
agsec audit [--stats]          # view logs
agsec observe                  # switch to observe mode
agsec enforce                  # switch to enforce mode
```

## Documentation

- [Policy Format](docs/policies.md) — schema, operators, conditions, examples
- [CLI Reference](docs/cli.md) — all commands in detail
- [Integrations](docs/integrations.md) — LangChain, OpenAI, Anthropic, Claude Code, Codex
- [SDK Usage](docs/sdk.md) — programmatic Python API
- [Observe Mode](docs/observe-mode.md) — audit first, enforce later

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and guidelines.

## License

Apache 2.0 — see [LICENSE](LICENSE).
