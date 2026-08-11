# agsec

[![PyPI version](https://badge.fury.io/py/agsec.svg)](https://pypi.org/project/agsec/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

**Agent security posture management.** Know what your AI agents can do, what they can see, and what they send out.

agsec covers 3 layers of agent security in one `pip install`:

| Layer | Threat | What agsec does |
|-------|--------|----------------|
| **Actions** | Destructive commands, file deletion, force push | Block at runtime via YAML policies |
| **Data visibility** | Agent reads secrets, credentials, SSH keys | Detect and block reads to sensitive files |
| **Exfiltration** | Agent reads secrets then sends them externally | Cross-layer sequence detection |

```
agent wants to act  →  agsec evaluates policy  →  allow / deny / review  →  real world
                                                         ↓
                                            agsec analyze → multi-layer posture report
```

---

## See it in action

### Without agsec — Claude deletes files freely
<p align="center">
  <img src="assets/claude_allowed.gif" alt="Claude deletes files without guardrails" width="720">
</p>

### With agsec — dangerous action blocked
<p align="center">
  <img src="assets/claude_blocked.gif" alt="agsec blocks Claude from deleting files" width="720">
</p>

### agsec analyze — multi-layer threat analysis
<p align="center">
  <img src="assets/agsec_analyse.gif" alt="agsec analyze command" width="720">
</p>

---

## The problem

88% of organizations reported AI agent security incidents in the last year. Claude Code deleted 2.5 years of production data. Replit AI wiped a live database during code freeze. 66% of MCP servers have security findings.

Developers know the risk but YOLO anyway, because the cost of caring (install a tool, write policies, deal with false positives) exceeds the perceived cost of not caring.

agsec makes the cost of caring near zero: 3 commands, 30 seconds, full posture visibility.

---

## 3-command setup

```bash
pip install agsec
agsec init                    # scaffold default policies
agsec install claude-code     # activate enforcement
```

Done. Every tool call is now checked against your policies. Out of the box, the following are blocked:

- `rm`, `rm -rf`, `rmdir` — destructive deletes
- Reads and writes to `.env`, credentials, SSH keys, cloud credentials
- `git push --force`, `git reset --hard` — destructive git
- `DROP TABLE`, `TRUNCATE`, `ALTER DROP` — DDL commands
- `DELETE FROM`, `UPDATE SET`, `INSERT INTO` — DML commands
- `sqlite3 audit.db`, `psql audit.db` — audit database tampering
- `chmod 777`, `mkfs`, `dd`, `shred` — destructive filesystem ops
- Direct push to `main`, `master`, `production` branches

---

## Not ready to block yet? Start in Observe Mode

```bash
agsec init --observe          # log everything, block nothing
agsec analyze                 # multi-layer threat analysis
agsec enforce                 # start blocking when ready
```

Observe mode gives you a full audit trail of every action your agent attempted, with zero disruption to your workflow. `agsec analyze` shows your security posture across all three layers: what got through, what was blocked, and what multi-step attack patterns were detected.

---

## Multi-layer threat analysis

```bash
agsec analyze                 # posture report with blast radius
agsec analyze --hours 4       # last 4 hours only
agsec analyze --json          # machine-readable output
```

The analyze command detects threats across three layers:

**Layer 1 — Actions:** 27+ threat patterns covering destructive commands, file deletion, SQL injection, encoded execution, audit tampering.

**Layer 2 — Data visibility:** Secret file reads, system file access, policy config reconnaissance, credential enumeration, scope violations (file access outside project directory).

**Layer 3 — Exfiltration (cross-layer):** Temporal sequence detection that correlates events across layers:
- Secret read → data upload within 5 minutes (staged exfiltration)
- Policy config read → dangerous action attempt (evasion)
- Sensitive file read → sub-agent spawn (delegation risk)

Each finding includes severity, blast radius score (0-10), concrete consequences, and actionable recommendations.

---

## Write your own policies

```yaml
version: "1.0"
default: deny

statements:
  - sid: "AllowReadOps"
    effect: allow
    actions: ["file.read", "file.glob", "file.grep"]

  - sid: "BlockDeletes"
    effect: deny
    actions: ["bash.execute"]
    conditions:
      params.command:
        op: "regex"
        value: "\\brm\\s"
    reason: "Agents should not delete files"

  - sid: "ReviewLargePayments"
    effect: review               # pause and ask a human
    actions: ["payment.create"]
    conditions:
      params.amount:
        op: "gt"
        value: 10000

  - sid: "AllowBash"
    effect: allow
    actions: ["bash.execute"]
```

Three effects: `allow`, `deny`, `review` (human-in-the-loop pause). Deny always wins, same evaluation logic as AWS IAM. Layered policy evaluation (project + agent layers) where each layer is a gate. Supports 14 condition operators: `==`, `!=`, `>`, `<`, `>=`, `<=`, `in`, `not_in`, `contains`, `starts_with`, `ends_with`, `regex`, `exists`, `not_exists`.

---

## Supported platforms

### System agents — hook-based enforcement

```bash
agsec install claude-code     # Claude Code + Claude Cowork ✓ tested
agsec install codex           # OpenAI Codex
agsec install cursor          # Cursor
agsec install windsurf        # Windsurf (Codeium)
agsec install cline           # Cline
agsec install copilot         # GitHub Copilot (project + user level)
```

Claude Code and Claude Cowork are fully tested. Others are functional, community testing welcome.

### Python frameworks

**LangChain:**

```python
from agsec.integrations.langchain import guard, allow, deny, review, param

agent = create_react_agent(llm, guard(
    allow(search, calculator),
    review(send_email),
    deny(delete_record),
    deny(payment).when(param("amount") > 10000),
))
```

**OpenAI / Anthropic / OpenRouter:**

```python
from agsec.integrations.openai import protect, deny, param

client = protect(OpenAI(),
    deny("delete_user"),
    deny("payment").when(param("amount") > 10000),
)
# Works with OpenRouter, Groq, Together — anything OpenAI-compatible
```

**Any Python function:**

```python
from agsec import guard

@guard("email.send")
def send_email(to, subject, body):
    ...
```

---

## CLI reference

```bash
agsec init [--observe]        # scaffold policies
agsec install <platform>      # activate enforcement
agsec uninstall <platform>    # deactivate

agsec policy list             # view all rules
agsec policy add              # add a rule (interactive)
agsec policy remove <sid>     # remove a rule
agsec validate                # check for errors

agsec audit [--stats]         # view action log
agsec analyze [--hours N]     # multi-layer threat analysis
agsec analyze --all           # full activity report (every action)
agsec status                  # posture status at a glance
agsec observe                 # switch to observe mode
agsec enforce                 # switch to enforce mode

agsec halt                    # kill switch: block ALL actions immediately
agsec resume                  # restore from halt
```

---

## OWASP Agentic Top 10 coverage

agsec addresses 7 of the 10 OWASP Agentic Top 10 risks out of the box. See the [full mapping](docs/owasp-mapping.md).

---

## Documentation

- [Policy Format](docs/policies.md) — schema, operators, conditions, examples
- [CLI Reference](docs/cli.md) — all commands
- [Integrations](docs/integrations.md) — Claude Code, Codex, Cursor, Windsurf, Cline, Copilot, LangChain, OpenAI, Anthropic
- [SDK Usage](docs/sdk.md) — programmatic Python API
- [Observe Mode](docs/observe-mode.md) — audit-first workflow
- [OWASP Mapping](docs/owasp-mapping.md) — compliance reference

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome, especially platform testing reports for Codex, Cursor, Windsurf, and Cline.

## License

Apache 2.0 — see [LICENSE](LICENSE).
