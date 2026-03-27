"""Tests for agsec init command."""

import os
import subprocess
import sys

import pytest


class TestInitCommand:
    def test_init_creates_policies(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = subprocess.run(
            [sys.executable, "-m", "agsec.cli.main", "init"],
            capture_output=True, text=True, cwd=str(tmp_path),
        )
        assert result.returncode == 0
        policy_dir = tmp_path / "policies"
        assert policy_dir.is_dir()
        files = sorted(os.listdir(policy_dir))
        assert len(files) == 5
        assert files[0].startswith("01_")
        assert all(f.endswith(".yaml") for f in files)

    def test_init_files_are_valid(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        subprocess.run(
            [sys.executable, "-m", "agsec.cli.main", "init"],
            capture_output=True, text=True, cwd=str(tmp_path),
        )
        result = subprocess.run(
            [sys.executable, "-m", "agsec.cli.main", "validate", str(tmp_path / "policies")],
            capture_output=True, text=True,
        )
        assert result.returncode == 0

    def test_init_existing_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "policies").mkdir()
        result = subprocess.run(
            [sys.executable, "-m", "agsec.cli.main", "init"],
            capture_output=True, text=True, cwd=str(tmp_path),
        )
        assert "already exists" in result.stdout
