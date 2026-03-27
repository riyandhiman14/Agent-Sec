"""End-to-end tests for shipped default policy templates."""

import os

import pytest

from agsec.cli.config import get_templates_dir
from agsec.policy import PolicyEngine
from agsec.types import PolicyStatus


@pytest.fixture
def engine():
    """Load all default policy templates."""
    e = PolicyEngine()
    e.load_from_directory(get_templates_dir())
    return e


class TestBashPolicies:
    def test_allow_ls(self, engine):
        result = engine.evaluate("bash.execute", {"command": "ls -la"})
        assert result.status == PolicyStatus.ALLOW

    def test_allow_git_status(self, engine):
        result = engine.evaluate("bash.execute", {"command": "git status"})
        assert result.status == PolicyStatus.ALLOW

    def test_allow_pytest(self, engine):
        result = engine.evaluate("bash.execute", {"command": "python -m pytest tests/"})
        assert result.status == PolicyStatus.ALLOW

    def test_block_rm_rf(self, engine):
        result = engine.evaluate("bash.execute", {"command": "rm -rf /"})
        assert result.status == PolicyStatus.BLOCK
        assert result.metadata["sid"] == "BlockFileDelete"

    def test_block_rm_single_file(self, engine):
        result = engine.evaluate("bash.execute", {"command": "rm somefile.txt"})
        assert result.status == PolicyStatus.BLOCK

    def test_block_rm_force(self, engine):
        result = engine.evaluate("bash.execute", {"command": "rm --force --recursive /tmp"})
        assert result.status == PolicyStatus.BLOCK

    def test_block_drop_table(self, engine):
        result = engine.evaluate("bash.execute", {"command": "psql -c 'DROP TABLE users'"})
        assert result.status == PolicyStatus.BLOCK

    def test_block_cat_env(self, engine):
        result = engine.evaluate("bash.execute", {"command": "cat .env"})
        assert result.status == PolicyStatus.BLOCK

    def test_block_force_push(self, engine):
        result = engine.evaluate("bash.execute", {"command": "git push --force origin main"})
        assert result.status == PolicyStatus.BLOCK

    def test_block_push_to_main(self, engine):
        result = engine.evaluate("bash.execute", {"command": "git push origin main"})
        assert result.status == PolicyStatus.BLOCK

    def test_block_git_reset_hard(self, engine):
        result = engine.evaluate("bash.execute", {"command": "git reset --hard HEAD~5"})
        assert result.status == PolicyStatus.BLOCK

    def test_allow_git_push_feature(self, engine):
        result = engine.evaluate("bash.execute", {"command": "git push origin feature/my-branch"})
        assert result.status == PolicyStatus.ALLOW


class TestFilePolicies:
    def test_allow_write_source(self, engine):
        result = engine.evaluate("file.write", {"file_path": "src/main.py", "content": "print('hi')"})
        assert result.status == PolicyStatus.ALLOW

    def test_block_write_env(self, engine):
        result = engine.evaluate("file.write", {"file_path": ".env", "content": "SECRET=x"})
        assert result.status == PolicyStatus.BLOCK

    def test_block_write_credentials(self, engine):
        result = engine.evaluate("file.write", {"file_path": "credentials.json", "content": "{}"})
        assert result.status == PolicyStatus.BLOCK

    def test_block_write_system(self, engine):
        result = engine.evaluate("file.write", {"file_path": "/etc/passwd", "content": "x"})
        assert result.status == PolicyStatus.BLOCK

    def test_allow_edit_source(self, engine):
        result = engine.evaluate("file.edit", {"file_path": "src/utils.py"})
        assert result.status == PolicyStatus.ALLOW

    def test_block_edit_env(self, engine):
        result = engine.evaluate("file.edit", {"file_path": ".env.production"})
        assert result.status == PolicyStatus.BLOCK


class TestReadPolicies:
    def test_allow_read_any(self, engine):
        result = engine.evaluate("file.read", {"file_path": "anything.py"})
        assert result.status == PolicyStatus.ALLOW

    def test_allow_glob(self, engine):
        result = engine.evaluate("file.glob", {"pattern": "**/*.py"})
        assert result.status == PolicyStatus.ALLOW

    def test_allow_grep(self, engine):
        result = engine.evaluate("file.grep", {"pattern": "TODO"})
        assert result.status == PolicyStatus.ALLOW


class TestWebPolicies:
    def test_review_external_fetch(self, engine):
        result = engine.evaluate("web.fetch", {"url": "https://example.com/api"})
        assert result.status == PolicyStatus.REVIEW

    def test_allow_localhost_fetch(self, engine):
        result = engine.evaluate("web.fetch", {"url": "http://localhost:3000/health"})
        assert result.status == PolicyStatus.ALLOW

    def test_allow_web_search(self, engine):
        result = engine.evaluate("web.search", {"query": "python docs"})
        assert result.status == PolicyStatus.ALLOW


class TestDefaultDeny:
    def test_unknown_action_allowed(self, engine):
        """Unknown tools are allowed by default (fail-open for unrecognized tools)."""
        result = engine.evaluate("unknown.something", {"foo": "bar"})
        assert result.status == PolicyStatus.ALLOW

    def test_internal_tools_allowed(self, engine):
        """IDE/internal tools are always allowed."""
        result = engine.evaluate("internal.TaskCreate", {})
        assert result.status == PolicyStatus.ALLOW

    def test_mcp_tool_blocked_by_default(self, engine):
        result = engine.evaluate("mcp.slack.send_message", {"text": "hi"})
        assert result.status == PolicyStatus.BLOCK
