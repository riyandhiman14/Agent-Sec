# Future Security Items

## 1. Input Normalization Before Policy Evaluation

**Found during:** Internal testing (developer bypassed global hook using base64 encoding)

**Problem:** Policy conditions use pattern matching (regex, contains, etc.) on raw input strings. If inputs are encoded, obfuscated, or use unicode escapes, patterns won't match.

**Bypass examples:**
- Base64: `echo "cm0gLXJmIC8=" | base64 -d | sh` — the command string doesn't contain `rm`
- Unicode escapes in JSON: `D\u0052OP TABLE` (decoded by JSON parser, but other encodings may not be)
- String concatenation: `"r" + "m" + " -rf /"`
- Hex encoding, URL encoding, etc.

**Who's affected:**
- CLI hooks (Claude Code/Codex): Lower risk — the runtime sends tool arguments as-is, agent can't control encoding
- SDK integrations (OpenAI/Anthropic protect()): Higher risk — LLM could generate obfuscated tool arguments
- Generic @guard decorator: Medium risk — depends on caller

**Current mitigation:** None. Same limitation as WAFs, SAST tools, and every pattern-based security tool.

**Future fix options:**
- Normalize inputs before evaluation (decode common encodings, collapse whitespace, lowercase)
- Add a normalization step in PolicyEngine.evaluate() before condition matching
- For bash commands specifically: parse the command into AST instead of regex matching
- For SQL: use a SQL parser instead of string matching
- Add a `normalize: true` flag on policy statements

**Priority:** Medium — this is a known limitation of pattern-based security. Defense-in-depth (multiple layers) is the standard approach. But we should fix it before enterprise customers rely on it.

## 2. Hook Bypass via Settings File Modification

**Problem:** If an agent has file write access, it could modify `.claude/settings.json` to remove the agsec hook.

**Current mitigation:** The hook blocks file writes to sensitive paths, but `.claude/settings.json` is not in the blocked list.

**Future fix:** Add `.claude/settings.json` and `.codex/hooks.json` to the default deny list in `03_files.yaml`.

## 3. Policy File Tampering

**Problem:** If an agent can write to the `policies/` directory, it could modify or delete policy files to weaken enforcement.

**Current mitigation:** None.

**Future fix:** Add `policies/*.yaml` and `.agsec.yaml` to the default deny list. Consider integrity hashing of policy files.

## 4. Streaming Response Bypass

**Problem:** `protect()` for OpenAI/Anthropic raises `NotImplementedError` for streaming. If a developer catches and ignores this, streaming calls bypass all checks.

**Current mitigation:** Explicit error rather than silent pass-through.

**Future fix:** Implement streaming response interception — wrap the stream generator and check tool calls as they appear in chunks.
