"""Tests for tool-to-action mapping."""

from agsec.cli.mapping import map_tool_to_action


class TestMapping:
    def test_bash(self):
        action, params = map_tool_to_action("Bash", {"command": "ls -la"})
        assert action == "bash.execute"
        assert params["command"] == "ls -la"

    def test_edit(self):
        action, params = map_tool_to_action("Edit", {"file_path": "x.py", "old_string": "a", "new_string": "b"})
        assert action == "file.edit"
        assert params["file_path"] == "x.py"

    def test_write(self):
        action, params = map_tool_to_action("Write", {"file_path": "x.py", "content": "hello"})
        assert action == "file.write"
        assert params["file_path"] == "x.py"

    def test_read(self):
        action, params = map_tool_to_action("Read", {"file_path": "x.py"})
        assert action == "file.read"

    def test_web_fetch(self):
        action, params = map_tool_to_action("WebFetch", {"url": "https://example.com"})
        assert action == "web.fetch"
        assert params["url"] == "https://example.com"

    def test_web_search(self):
        action, params = map_tool_to_action("WebSearch", {"query": "python docs"})
        assert action == "web.search"

    def test_glob(self):
        action, _ = map_tool_to_action("Glob", {"pattern": "**/*.py"})
        assert action == "file.glob"

    def test_grep(self):
        action, _ = map_tool_to_action("Grep", {"pattern": "TODO"})
        assert action == "file.grep"

    def test_agent(self):
        action, _ = map_tool_to_action("Agent", {"prompt": "do something"})
        assert action == "agent.spawn"

    def test_mcp_tool(self):
        action, params = map_tool_to_action("mcp__github__create_issue", {"title": "bug", "body": "fix it"})
        assert action == "mcp.github.create_issue"
        assert params["title"] == "bug"

    def test_unknown_tool(self):
        action, _ = map_tool_to_action("SomethingNew", {})
        assert action == "unknown.SomethingNew"
