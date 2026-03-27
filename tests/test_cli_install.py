"""Tests for agsec install command."""

import json
import os
import subprocess
import sys

import pytest


class TestInstallClaudeCode:
    def test_creates_settings(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "-m", "agsec.cli.main", "install", "claude-code", "--project-dir", str(tmp_path)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        settings_path = tmp_path / ".claude" / "settings.json"
        assert settings_path.is_file()

        with open(settings_path) as f:
            settings = json.load(f)

        assert "hooks" in settings
        assert "PreToolUse" in settings["hooks"]
        hooks = settings["hooks"]["PreToolUse"]
        assert len(hooks) == 1
        assert "agsec" in str(hooks[0])

    def test_idempotent(self, tmp_path):
        cmd = [sys.executable, "-m", "agsec.cli.main", "install", "claude-code", "--project-dir", str(tmp_path)]
        subprocess.run(cmd, capture_output=True, text=True)
        subprocess.run(cmd, capture_output=True, text=True)

        settings_path = tmp_path / ".claude" / "settings.json"
        with open(settings_path) as f:
            settings = json.load(f)

        # Should still have only 1 hook, not duplicated
        assert len(settings["hooks"]["PreToolUse"]) == 1

    def test_merges_with_existing(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        existing = {"some_setting": True}
        with open(claude_dir / "settings.json", "w") as f:
            json.dump(existing, f)

        subprocess.run(
            [sys.executable, "-m", "agsec.cli.main", "install", "claude-code", "--project-dir", str(tmp_path)],
            capture_output=True, text=True,
        )

        with open(claude_dir / "settings.json") as f:
            settings = json.load(f)

        assert settings["some_setting"] is True
        assert "hooks" in settings


class TestInstallCodex:
    def test_creates_hooks_json(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "-m", "agsec.cli.main", "install", "codex", "--project-dir", str(tmp_path)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        hooks_path = tmp_path / ".codex" / "hooks.json"
        assert hooks_path.is_file()

        with open(hooks_path) as f:
            config = json.load(f)

        assert "hooks" in config
        assert any("agsec" in h.get("command", "") for h in config["hooks"])
