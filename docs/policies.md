# Policy Format

Policies are YAML files in a `policies/` directory. All files are loaded and merged automatically in alphabetical order. Deny from any file wins — same evaluation logic as AWS IAM.

## Schema

```yaml
version: "1.0"
default: deny          # deny | allow

statements:
  - sid: "UniqueId"    # Statement ID (for audit trail + debugging)
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

## Evaluation Order

Same as AWS IAM:

1. **Explicit deny always wins** — any matching deny rule blocks the action
2. **Review trumps allow** — review rules pause for human approval
3. **Explicit allow** — matching allow rule permits the action
4. **Default policy** — if nothing matches, fall back to default (deny recommended)

## Layered Policy Evaluation

Policies are evaluated in layers — project policies + optional agent-specific overlay. Each layer is a gate: ALL must allow for an action to proceed.

```
Project layer (policies/)  →  Agent layer (~/.agsec/agents/{name}/)  →  Result
         ↓                              ↓
    DENY = blocked               DENY = blocked
    ALLOW = next layer           ALLOW = final allow
```

Agent layers can only add restrictions, never widen project permissions. Create agent-specific policies at `~/.agsec/agents/{agent-name}/`.

## Action Names

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
| `notebook.edit` | Notebook editing |
| `mcp.*` | Any MCP tool calls |
| `internal.*` | IDE/platform internals (always allowed) |

Use glob patterns: `payment.*`, `*.delete`, `mcp.slack.*`

## Condition Operators

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

## Deep Nested Access

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

## Input Normalization

String values are automatically decoded before policy evaluation to prevent encoding bypasses:

- **Base64** — pure base64 strings are decoded (e.g., `cm0gLXJmIC8=` → `rm -rf /`)
- **Unicode escapes** — `\u0052` decoded to `R` (catches `D\u0052OP TABLE`)
- **Hex escapes** — `\x72\x6d` decoded to `rm`

This is non-destructive: only decodes if the result is valid printable text.

## Default Policies

`agsec init` ships with 5 policy files:

### 01_base.yaml
- Default deny
- Block reads of secret files (`.env`, credentials, SSH keys, cloud credentials)
- Allow other reads, agent spawn, internal tools

### 02_bash.yaml
- Block `rm` — file deletion
- Block `chmod 777`, `mkfs`, `dd`, `shred` — destructive filesystem
- Block `DROP TABLE`, `TRUNCATE`, `ALTER DROP` — DDL commands
- Block `DELETE FROM`, `UPDATE SET`, `INSERT INTO` — DML commands
- Block `sqlite3 audit.db` — audit database tampering
- Block `cat .env`, `cat credentials` — secret access via bash
- Block `curl --data .env` — data exfiltration
- Block `base64 -d | sh`, `xxd -r | bash`, `python -c eval | sh` — encoded execution
- Allow other bash

### 03_files.yaml
- Block writes to `.env`, credentials, SSH keys, cloud credentials
- Block writes to agsec config and hook files (all 6 platforms)
- Block writes to system directories (`/etc`, `/usr`, `/var`, etc.)
- Allow other file writes and notebook edits

### 04_web.yaml
- Review external HTTP fetches (non-localhost)
- Allow localhost and web search

### 05_git.yaml
- Block force push (`git push --force`)
- Block push to protected branches (main, master, production, release)
- Block destructive git (`reset --hard`, `clean -f`)

## Multiple Policy Files

All `.yaml`/`.yml` files in the policies directory are loaded and merged. Use numbered prefixes for ordering:

```
policies/
  01_base.yaml      # loaded first — sets default
  02_bash.yaml      # bash rules
  03_custom.yaml    # your custom rules
```

A deny in any file overrides an allow in any other file.
