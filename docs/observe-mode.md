# Observe Mode

Observe mode lets you deploy agsec without blocking anything. Every action is allowed, but every policy decision is logged with its actual outcome — including what would have been blocked.

## Why

Deploying a firewall blind is risky. You don't know what your agent actually does until you watch it. Observe mode lets you:

1. See real agent behavior in production
2. Identify what would be blocked by your policies
3. Tune policies based on actual data
4. Switch to enforce when confident

## Setup

### New Project

```bash
agsec init --observe
agsec install claude-code
```

### Existing Project

```bash
agsec observe
```

## The Flow

```
1. agsec init --observe          # deploy with logging only
2. Agent runs normally           # everything is allowed
3. agsec audit --stats           # see what would be blocked
4. agsec analyze                 # threat analysis with blast radius
5. agsec analyze --all           # full activity report
6. Edit policies as needed       # tune based on real data
7. agsec enforce                 # start blocking
```

## Commands

```bash
agsec observe            # switch to observe mode
agsec enforce            # switch to enforce mode
agsec halt               # kill switch — block everything immediately
agsec resume             # restore previous mode after halt
agsec status             # see current mode at a glance
```

## Audit in Observe Mode

```bash
$ agsec audit --stats
Audit Statistics (OBSERVE mode)
  Total:        142
  Allowed:      100
  Would block:  30
  Would review: 12
  Errors:       0
```

The "would block" and "would review" counts show actions that policies evaluated as BLOCK/REVIEW but were allowed through because of observe mode.

## Threat Analysis

```bash
$ agsec analyze --hours 24
```

Shows blast radius, severity breakdown (CRITICAL/HIGH/MEDIUM/LOW), consequences, and recommendations. In observe mode, all findings are treated as threats (since nothing was actually blocked).

```bash
$ agsec analyze --all
```

Full activity report — every action grouped by type (Shell Commands, File Reads, etc.) with actual values. Blocked/review items sorted to top.

## Accurate Outcome Logging

Every audit record stores both the **policy decision** (what the engine said) and the **actual outcome** (what really happened). This means:

- Switching from observe to enforce doesn't corrupt your analysis
- `agsec analyze` accurately shows what got through vs what was blocked, regardless of mode changes

## How It Works

- A `.agsec.yaml` config file stores the current mode
- `agsec check` reads this config before evaluating
- In observe mode: policies are evaluated, decisions are logged with `outcome=allowed`, exit code is always 0
- In enforce mode: policies are evaluated, decisions are logged with actual outcome, blocked actions exit non-zero
- In halt mode: everything is blocked immediately

## Environment Variable Override

```bash
AGSEC_MODE=observe agsec check ...    # force observe
AGSEC_MODE=enforce agsec check ...    # force enforce
```
