# Integrations

agsec works with any agent platform. One policy engine, same audit trail everywhere.

## System Agents (Hook-Based)

### Claude Code

```bash
pip install agsec
agsec init
agsec install claude-code
```

Enforcement is at the runtime level. The agent cannot bypass it. Works with Claude Code and Claude Cowork.

### OpenAI Codex

```bash
agsec install codex
```

### Cursor

```bash
agsec install cursor
```

### Windsurf

```bash
agsec install windsurf
```

### Cline

```bash
agsec install cline
```

### GitHub Copilot

```bash
agsec install copilot
```

Installs to both project-level (`.github/hooks/`) and user-level (`~/.copilot/hooks/`). The project-level hook must be committed for the cloud coding agent.

All platforms embed `--agent <platform>` in the hook command, enabling agent-specific policy layers at `~/.agsec/agents/{agent-name}/`.

---

## Python SDK Integrations

### LangChain

```bash
pip install agsec[langchain]
```

```python
from agsec.integrations.langchain import guard, allow, deny, review, param

agent = create_react_agent(llm, guard(
    allow(search, calculator),
    review(send_email),
    deny(delete_record),
    deny(payment).when(param("amount") > 10000),
))
```

Rules:
- Bare tool = allow
- `allow(tool1, tool2)` = explicitly allow
- `deny(tool)` = block
- `review(tool)` = require human approval
- `.when(param("x") > 10)` = conditional

Action names are `tool.{tool_name}`.

Also works with YAML policies:
```python
agent = create_react_agent(llm, guard(
    search, calculator, send_email,
    policy_dir="./policies/",
))
```

### OpenAI SDK

Works with OpenAI, OpenRouter, Groq, Together, Fireworks — anything OpenAI-compatible.

```bash
pip install agsec[openai]
```

```python
from openai import OpenAI
from agsec.integrations.openai import protect, deny, param

client = protect(OpenAI(),
    deny("delete_user"),
    deny("payment").when(param("amount") > 10000),
)

# Use client normally — tool calls are checked automatically
response = client.chat.completions.create(model="gpt-4", messages=[...], tools=[...])
```

OpenRouter:
```python
client = protect(OpenAI(base_url="https://openrouter.ai/api/v1", api_key="..."),
    deny("dangerous_tool"),
)
```

**Non-streaming:** Blocked tool calls are filtered from the response. Check `response._agsec_blocked` for details.

**Streaming:** Chunks flow through unchanged (zero latency impact). Tool calls are accumulated and checked after the stream completes. Check `stream._agsec_blocked` after consuming the stream.

**Important:** Policy checks run only after the full stream is consumed. If you break out of the iteration early (e.g., `for chunk in stream: break`), policy enforcement will not run. Always consume the full stream for enforcement to apply.

```python
stream = client.chat.completions.create(model="gpt-4", messages=[...], tools=[...], stream=True)

for chunk in stream:
    # Chunks arrive in real-time
    ...

# After stream completes, check blocked tool calls
if stream._agsec_blocked:
    print(f"Blocked: {stream._agsec_blocked}")
```

### Anthropic SDK

```bash
pip install agsec[anthropic]
```

```python
from anthropic import Anthropic
from agsec.integrations.anthropic import protect, deny, param

client = protect(Anthropic(),
    deny("delete_user"),
    deny("payment").when(param("amount") > 10000),
)

response = client.messages.create(model="claude-sonnet-4-20250514", messages=[...], tools=[...])
```

Same behavior as OpenAI — blocked `tool_use` blocks are filtered from the response. Text blocks are always preserved. Streaming supported with the same `stream._agsec_blocked` pattern. Same limitation applies: always consume the full stream for enforcement to run.

### Generic Python (any framework)

```python
from agsec import guard

@guard("email.send")
def send_email(to, subject, body):
    ...

@guard("payment.charge", agent="billing-agent")
async def charge(amount, recipient):
    ...
```

Works with sync and async functions. Raises `PolicyViolationError` on block.

---

## Install All

```bash
pip install agsec[all]       # openai + anthropic + langchain + rich
pip install agsec[rich]      # colored CLI output (optional)
```
