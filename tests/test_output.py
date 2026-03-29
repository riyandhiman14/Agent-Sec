"""Tests for CLI output utilities."""

from agsec.cli.output import (
    RICH,
    mode_label,
    severity_label,
)


class TestOutputFallback:
    def test_mode_label_enforce(self):
        label = mode_label("enforce")
        assert "ENFORCE" in label

    def test_mode_label_observe(self):
        label = mode_label("observe")
        assert "OBSERVE" in label

    def test_mode_label_halt(self):
        label = mode_label("halt")
        assert "HALT" in label

    def test_severity_label_critical(self):
        label = severity_label("critical")
        assert "CRITICAL" in label

    def test_severity_label_low(self):
        label = severity_label("low")
        assert "LOW" in label
