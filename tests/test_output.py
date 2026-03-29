"""Tests for CLI output utilities."""

import io
import sys

from agsec.cli.output import (
    RICH,
    mode_label,
    severity_label,
    table,
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


class TestTableFormatting:
    def test_table_short_row(self, capsys):
        """Table should not crash when a row has fewer columns than headers."""
        if RICH:
            return  # Rich handles this internally
        table("Test", ["Col1", "Col2", "Col3"], [["a", "b"]])
        captured = capsys.readouterr()
        assert "Col1" in captured.out
        assert "a" in captured.out

    def test_table_none_values(self, capsys):
        """Table should handle None values in cells."""
        if RICH:
            return
        table("Test", ["Name", "Value"], [["key", None]])
        captured = capsys.readouterr()
        assert "None" in captured.out

    def test_table_empty_rows(self, capsys):
        """Table with no rows should not crash."""
        if RICH:
            return
        table("Test", ["Col1", "Col2"], [])
        captured = capsys.readouterr()
        assert "Test" in captured.out
