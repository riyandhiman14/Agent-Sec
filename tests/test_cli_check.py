"""Tests for agsec check command."""

import json
import subprocess
import sys

import pytest


def _run_check(stdin_data, policy_dir, fmt="generic", extra_args=None):
    """Run agsec check as a subprocess and return (exit_code, stdout, stderr)."""
    cmd = [sys.executable, "-m", "agsec.cli.main", "check", f"--format={fmt}"]
    if extra_args:
        cmd.extend(extra_args)
    env = {"AGSEC_POLICY_DIR": policy_dir, "PATH": "", "AGSEC_AUDIT_DB": ":memory:"}
    result = subprocess.run(
        cmd,
        input=json.dumps(stdin_data),
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _write_policy(tmp_path, content):
    """Create a policy dir with a single file."""
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "policy.yaml").write_text(content)
    return str(policy_dir)


class TestCheckCommand:
    def test_allow_read(self, tmp_path):
        policy_dir = _write_policy(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "AllowRead"
    effect: allow
    actions: ["file.read"]
""")
        code, stdout, stderr = _run_check(
            {"tool_name": "Read", "tool_input": {"file_path": "foo.py"}},
            policy_dir,
        )
        assert code == 0

    def test_block_bash_rm(self, tmp_path):
        policy_dir = _write_policy(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "BlockRM"
    effect: deny
    actions: ["bash.execute"]
    conditions:
      params.command:
        op: "regex"
        value: "rm\\\\s+-rf"
    reason: "rm -rf blocked"
  - sid: "AllowBash"
    effect: allow
    actions: ["bash.execute"]
""")
        code, stdout, stderr = _run_check(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            policy_dir,
        )
        assert code == 1
        data = json.loads(stderr)
        assert data["blocked"] is True
        assert "rm -rf blocked" in data["reason"]

    def test_default_deny_blocks_unknown(self, tmp_path):
        policy_dir = _write_policy(tmp_path, """
version: "1.0"
default: deny
statements: []
""")
        code, _, _ = _run_check(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            policy_dir,
        )
        assert code == 1

    def test_claude_code_format(self, tmp_path):
        policy_dir = _write_policy(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "DenyAll"
    effect: deny
    actions: ["*"]
    reason: "Everything blocked"
""")
        code, stdout, stderr = _run_check(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            policy_dir,
            fmt="claude-code",
        )
        assert code == 2
        data = json.loads(stdout)
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "Everything blocked" in data["hookSpecificOutput"]["permissionDecisionReason"]

    def test_codex_format(self, tmp_path):
        policy_dir = _write_policy(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "DenyAll"
    effect: deny
    actions: ["*"]
    reason: "Blocked"
""")
        code, stdout, stderr = _run_check(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            policy_dir,
            fmt="codex",
        )
        assert code == 2
        data = json.loads(stdout)
        assert data["decision"] == "block"

    def test_review_treated_as_block(self, tmp_path):
        policy_dir = _write_policy(tmp_path, """
version: "1.0"
default: deny
statements:
  - sid: "ReviewAll"
    effect: review
    actions: ["*"]
    reason: "Needs review"
""")
        code, _, stderr = _run_check(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            policy_dir,
        )
        assert code == 2  # review = exit 2
        data = json.loads(stderr)
        assert data["status"] == "review"
