# Observe Mode

Observe mode lets you deploy agsec without blocking anything. Every action is allowed, but every policy decision is logged — including what would have been blocked.

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
4. Edit policies as needed       # tune based on real data
5. agsec enforce                 # start blocking
```

## Commands

```bash
agsec observe            # switch to observe mode
agsec enforce            # switch to enforce mode
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

## How It Works

- A `.agsec.yaml` config file stores the current mode
- `agsec check` reads this config before evaluating
- In observe mode: policies are evaluated, decisions are logged, but exit code is always 0 (allow)
- In enforce mode: policies are evaluated, decisions are logged, and blocked actions exit with non-zero

## Environment Variable Override

```bash
AGSEC_MODE=observe agsec check ...    # force observe
AGSEC_MODE=enforce agsec check ...    # force enforce
```
