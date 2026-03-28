# OWASP Agentic Top 10 Coverage

How agsec maps to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

agsec addresses **7 of 10** OWASP Agentic risks. We are transparent about the 3 gaps, which are industry-wide open problems that no tool fully solves today.

## Coverage Summary

| ID | Risk | Coverage | Level |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | Blast radius reduction | MEDIUM |
| ASI02 | Tool Misuse & Exploitation | Core feature | HIGH |
| ASI03 | Identity & Privilege Abuse | Core feature | HIGH |
| ASI04 | Supply Chain Vulnerabilities | Not addressed | NONE |
| ASI05 | Unexpected Code Execution | Policy gating | MEDIUM |
| ASI06 | Memory & Context Poisoning | Not addressed | NONE |
| ASI07 | Insecure Inter-Agent Comms | Not addressed | NONE |
| ASI08 | Cascading Failures | Circuit breaking | HIGH |
| ASI09 | Human-Agent Trust | Review + audit | MEDIUM |
| ASI10 | Rogue Agents | Kill switch + audit | HIGH |

## Detailed Mapping

### ASI01 - Agent Goal Hijack (MEDIUM)

**Risk:** Attackers redirect agent objectives via prompt injection, poisoned data, or deceptive tool outputs.

**What agsec does:**
- Cannot prevent the hijack itself (that's an LLM problem)
- Limits what a hijacked agent can do through default-deny policies
- Every action is checked against policies regardless of the agent's intent
- If an agent is tricked into running `rm -rf /`, the policy blocks it

**agsec features:** Default-deny posture, per-action policy enforcement, condition-based blocking (regex, contains, etc.)

### ASI02 - Tool Misuse & Exploitation (HIGH)

**Risk:** Agent uses legitimate tools in unsafe or unintended ways.

**What agsec does:**
- Per-tool allow/deny/review policies with 14 condition operators
- Glob pattern matching for action groups (`payment.*`, `*.delete`)
- Parameter-level conditions (`deny payment when amount > 10000`)
- Deep nested field access (`params.recipient.country`)
- Observe mode to audit tool usage before enforcing

**agsec features:** PolicyEngine, YAML statements, condition operators, observe mode, audit trail

### ASI03 - Identity & Privilege Abuse (HIGH)

**Risk:** Exploiting inherited credentials, delegated permissions, or agent-to-agent trust chains.

**What agsec does:**
- Agent-scoped policies (different agents get different permissions)
- Default-deny with explicit allow (IAM semantics)
- Per-action authorization, not blanket access
- Full audit trail of every action + policy decision

**agsec features:** Agent overlay policies (`~/.agsec/agents/{name}/`), default-deny, audit store

### ASI04 - Supply Chain Vulnerabilities (NONE)

**Risk:** Malicious or tampered tools, MCP servers, models, or prompt templates.

**What agsec does:** Not addressed. agsec operates at the action execution layer, not the tool supply chain layer. Tool provenance verification, SBOM analysis, and MCP package integrity checking are not in scope.

**Industry note:** This is an unsolved problem industry-wide. No tool provides comprehensive cryptographic provenance for AI agent tool registries. Tools like Microsoft's Agent Governance Toolkit claim coverage through API gateway allow-listing, but that is policy-level gating, not supply chain verification.

### ASI05 - Unexpected Code Execution (MEDIUM)

**Risk:** Agent generates or runs attacker-controlled code.

**What agsec does:**
- Gates all bash/shell execution behind policy check
- Regex-based blocking of dangerous patterns (rm, DROP TABLE, etc.)
- Review effect for human approval before execution
- Default policies block destructive commands out of the box

**Limitation:** Cannot sandbox the execution itself. agsec blocks the action before it runs but does not provide process isolation. Pair with OS-level sandboxing (seccomp, Seatbelt) for defense-in-depth.

### ASI06 - Memory & Context Poisoning (NONE)

**Risk:** Persistent corruption of RAG stores, embeddings, or agent memory.

**What agsec does:** Not addressed. agsec operates at the action layer, not the memory/context layer. Protecting RAG stores, validating memory writes, and detecting semantic drift are separate concerns.

**Industry note:** This is largely unsolved. Some tools (Azure Prompt Shields) catch obvious injection in retrieved content, but semantic poisoning that subtly shifts agent behavior is not reliably detectable.

### ASI07 - Insecure Inter-Agent Communication (NONE)

**Risk:** Spoofed, intercepted, or manipulated agent-to-agent messages.

**What agsec does:** Not addressed. Transport security, message signing, and agent authentication are infrastructure-layer concerns outside agsec's scope.

**Industry note:** Current approaches rely on TLS + identity providers (e.g., Entra ID), which secure the transport but not the semantic content. Agent-level message validation remains an open research problem.

### ASI08 - Cascading Failures (HIGH)

**Risk:** Single fault propagates across multi-agent workflows.

**What agsec does:**
- Per-action enforcement acts as a natural circuit breaker
- Kill switch (`agsec halt`) immediately stops all agent actions
- Observe mode detects anomalous patterns before enforcement
- Default-deny prevents unexpected action propagation

**agsec features:** Kill switch, per-action policies, observe mode, audit trail

### ASI09 - Human-Agent Trust Exploitation (MEDIUM)

**Risk:** Humans over-trust agent outputs or agents manipulate users into unsafe approvals.

**What agsec does:**
- Review effect forces human approval for sensitive actions
- Immutable audit logs of every action with full context
- Observe mode shows what agents actually do before trusting them

**Limitation:** No behavioral detection or UI safeguards against social engineering.

### ASI10 - Rogue Agents (HIGH)

**Risk:** Compromised or misaligned agents act deceptively while appearing legitimate.

**What agsec does:**
- Default-deny bounds what any agent can do, rogue or not
- Kill switch (`agsec halt`) for immediate containment
- Full audit trail enables forensic investigation
- Policy self-protection (agents can't modify policy files or hook configs)

**agsec features:** Kill switch, default-deny, audit store, self-protecting policies

## What's Not Covered

The 3 gaps (ASI04, ASI06, ASI07) require fundamentally different subsystems:

- **Supply chain** needs cryptographic tool provenance, not runtime policy enforcement
- **Memory poisoning** needs memory-layer validation, not action-layer gating
- **Inter-agent security** needs transport and semantic message validation

These are industry-wide open problems. We recommend pairing agsec with complementary tools that address these layers (e.g., MCP scanners for supply chain, prompt shields for memory poisoning, mutual TLS for transport security).
