"""Tests for agsec status command."""

import json
import subprocess
import sys

import pytest


def _run_status(env_overrides=None):
    """Run agsec status as subprocess."""
    env = {"AGSEC_MODE": "enforce", "AGSEC_AUDIT_DB": ":memory:"}
    if env_overrides:
        env.update(env_overrides)
    result = subprocess.run(
        [sys.executable, "-m", "agsec.cli.main", "status"],
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestStatusCommand:
    def test_status_runs(self):
        code, stdout, stderr = _run_status()
        assert code == 0
        assert "agsec" in stdout.lower()

    def test_status_shows_mode(self):
        code, stdout, _ = _run_status({"AGSEC_MODE": "enforce"})
        assert "ENFORCE" in stdout

    def test_status_shows_observe(self):
        code, stdout, _ = _run_status({"AGSEC_MODE": "observe"})
        assert "OBSERVE" in stdout

    def test_status_shows_version(self):
        code, stdout, _ = _run_status()
        assert "v0." in stdout  # matches v0.2.1 etc


class TestVersionFlag:
    def test_version(self):
        result = subprocess.run(
            [sys.executable, "-m", "agsec.cli.main", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "agsec" in result.stdout
        assert "0.2.3" in result.stdout
