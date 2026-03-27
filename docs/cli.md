# CLI Reference

## Setup

### `agsec init [--observe] [--dir DIR]`

Scaffold a policies directory with default safety policies.

```bash
agsec init                # enforce mode (default)
agsec init --observe      # observe mode (audit only, no blocking)
agsec init --dir .agsec/policies  # custom directory
```

### `agsec install claude-code|codex`

Activate the firewall for an agent platform.

```bash
agsec install claude-code
agsec install codex
```

## Policy Management

### `agsec policy list`

Show all active policy statements across all files.

### `agsec policy add`

Add a new policy statement interactively. Walks you through:
1. Effect (deny/allow/review)
2. Actions to match
3. Conditions (pattern matching)
4. Reason and statement ID

Also supports non-interactive mode:
```bash
agsec policy add --no-interactive --sid BlockX --effect deny --actions "bash.execute" --reason "Blocked"
```

### `agsec policy remove <sid>`

Remove a policy statement by its statement ID.

### `agsec validate [path]`

Validate policy files for syntax errors, missing fields, invalid operators.

```bash
agsec validate              # auto-discover policies directory
agsec validate policies/    # specific directory
agsec validate policy.yaml  # single file
```

## Mode

### `agsec observe`

Switch to observe mode. All actions are allowed but every policy decision is logged. Use `agsec audit --stats` to see what would be blocked.

### `agsec enforce`

Switch to enforce mode. Policies are enforced — blocked actions are denied.

## Audit

### `agsec audit [--stats] [--action NAME] [--limit N] [--json]`

Query audit logs.

```bash
agsec audit                # recent 20 actions
agsec audit --stats        # summary statistics
agsec audit --action bash.execute --limit 50
agsec audit --json         # machine-readable output
```

In observe mode, stats show "would block" instead of "blocked".
