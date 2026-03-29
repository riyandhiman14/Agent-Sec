# CLI Reference

## Setup

### `agsec init [--observe] [--dir DIR]`

Scaffold a policies directory with default safety policies.

```bash
agsec init                # enforce mode (default)
agsec init --observe      # observe mode (audit only, no blocking)
agsec init --dir .agsec/policies  # custom directory
```

### `agsec install <platform>`

Activate the firewall for an agent platform.

```bash
agsec install claude-code     # Claude Code + Claude Cowork
agsec install codex           # OpenAI Codex
agsec install cursor          # Cursor
agsec install windsurf        # Windsurf (Codeium)
agsec install cline           # Cline
agsec install copilot         # GitHub Copilot (project + user level)
```

### `agsec uninstall <platform>`

Remove the agsec hook from a platform.

## Status

### `agsec status`

Show firewall status at a glance — mode, installed platforms, policy count, audit stats, last blocked action.

### `agsec --version`

Show the installed agsec version.

## Policy Management

### `agsec policy list`

Show all active policy statements across all files, with colored allow/deny/review markers.

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

Switch to observe mode. All actions are allowed but every policy decision is logged with its actual outcome. Use `agsec audit --stats` to see what would be blocked.

### `agsec enforce`

Switch to enforce mode. Policies are enforced — blocked actions are denied.

### `agsec halt`

Kill switch — immediately block ALL agent actions. Saves previous mode for resume.

### `agsec resume`

Restore from halt — returns to the mode that was active before halt.

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

### `agsec audit --prune [DAYS]`

Delete audit records older than N days. Default: 7 days.

```bash
agsec audit --prune        # delete records older than 7 days
agsec audit --prune 30     # delete records older than 30 days
```

### `agsec audit --clear`

Delete ALL audit records.

You can also auto-prune by setting the environment variable:
```bash
export AGSEC_AUDIT_RETENTION_DAYS=7
```

## Threat Analysis

### `agsec analyze [--hours N] [--days N] [--json]`

Threat analysis with blast radius scoring. Classifies audit logs against 22 built-in threat patterns. Shows severity (CRITICAL/HIGH/MEDIUM/LOW), consequences, and recommendations.

```bash
agsec analyze              # all time
agsec analyze --hours 24   # last 24 hours
agsec analyze --days 7     # last 7 days
agsec analyze --json       # machine-readable output
```

### `agsec analyze --all`

Full activity report — every action grouped by human-readable type (Shell Commands, File Reads, Web Requests, etc.) with actual values. Blocked/review items sorted to top.

```bash
agsec analyze --all              # all activity
agsec analyze --all --hours 1    # last hour
agsec analyze --all --json       # JSON output
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGSEC_MODE` | Override mode (observe/enforce) | from `.agsec.yaml` |
| `AGSEC_AUDIT_DB` | Override audit database path | `~/.agsec/audit.db` |
| `AGSEC_AUDIT_RETENTION_DAYS` | Auto-prune records older than N days | disabled |
