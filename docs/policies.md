# Policy Format

Policies are YAML files in a `policies/` directory. All files are loaded and merged automatically in alphabetical order. Deny from any file wins.

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

## Default Policies

`agsec init` ships with 5 policy files:

- **01_base.yaml** — Default deny. Allow reads, agent spawn, internal tools.
- **02_bash.yaml** — Block `rm`, `DROP TABLE`, secret access, data exfiltration. Allow other bash.
- **03_files.yaml** — Block writes to `.env`, credentials, system dirs, agsec config. Allow other writes.
- **04_web.yaml** — Review external HTTP fetches. Allow localhost and web search.
- **05_git.yaml** — Block force push, protected branches, `reset --hard`.

## Multiple Policy Files

All `.yaml`/`.yml` files in the policies directory are loaded and merged. Use numbered prefixes for ordering:

```
policies/
  01_base.yaml      # loaded first — sets default
  02_bash.yaml      # bash rules
  03_custom.yaml    # your custom rules
```

A deny in any file overrides an allow in any other file.
