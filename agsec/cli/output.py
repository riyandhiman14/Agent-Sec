"""agsec CLI output utilities — Rich if available, plain text fallback."""

from __future__ import annotations

import sys
from typing import Any, List, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table as RichTable
    from rich.text import Text

    RICH = True
    console = Console(stderr=False)
    err_console = Console(stderr=True)
except ImportError:
    RICH = False
    console = None
    err_console = None


# ---------------------------------------------------------------------------
# Core message functions
# ---------------------------------------------------------------------------


def success(msg: str) -> None:
    if RICH:
        console.print(f"[green]{msg}[/green]")
    else:
        print(f"[+] {msg}")


def error(msg: str) -> None:
    if RICH:
        err_console.print(f"[bold red]{msg}[/bold red]")
    else:
        print(f"[X] {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    if RICH:
        console.print(f"[yellow]{msg}[/yellow]")
    else:
        print(f"[!] {msg}")


def info(msg: str) -> None:
    if RICH:
        console.print(f"[dim]{msg}[/dim]")
    else:
        print(f"    {msg}")


def plain(msg: str) -> None:
    if RICH:
        console.print(msg)
    else:
        print(msg)


# ---------------------------------------------------------------------------
# Status-colored output
# ---------------------------------------------------------------------------


def status_allow(msg: str) -> None:
    if RICH:
        console.print(f"  [green]+[/green] {msg}")
    else:
        print(f"  [+] {msg}")


def status_block(msg: str) -> None:
    if RICH:
        console.print(f"  [red]X[/red] {msg}")
    else:
        print(f"  [X] {msg}")


def status_review(msg: str) -> None:
    if RICH:
        console.print(f"  [yellow]?[/yellow] {msg}")
    else:
        print(f"  [?] {msg}")


# ---------------------------------------------------------------------------
# Headings and structure
# ---------------------------------------------------------------------------


def heading(msg: str) -> None:
    if RICH:
        console.print(f"\n[bold]{msg}[/bold]")
    else:
        print(f"\n{msg}")
        print("=" * len(msg))


def subheading(msg: str) -> None:
    if RICH:
        console.print(f"[bold]{msg}[/bold]")
    else:
        print(msg)


def panel(title: str, content: str) -> None:
    if RICH:
        console.print(Panel(content, title=title, border_style="blue"))
    else:
        print(f"--- {title} ---")
        print(content)
        print()


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------


def table(headers: List[str], rows: List[List[str]], title: Optional[str] = None) -> None:
    if RICH:
        t = RichTable(title=title, show_header=True, header_style="bold")
        for h in headers:
            t.add_column(h)
        for row in rows:
            t.add_row(*[str(c) for c in row])
        console.print(t)
    else:
        if title:
            print(f"\n{title}")
        # Simple column formatting
        if not rows:
            return
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        print(fmt.format(*headers))
        print(fmt.format(*["-" * w for w in widths]))
        for row in rows:
            padded = [str(c) if i < len(row) else "" for i, c in enumerate(row)]
            print(fmt.format(*padded))


# ---------------------------------------------------------------------------
# Mode display
# ---------------------------------------------------------------------------


def mode_label(mode: str) -> str:
    if not RICH:
        return mode.upper()
    colors = {"observe": "yellow", "enforce": "green", "halt": "red"}
    color = colors.get(mode, "white")
    return f"[{color}]{mode.upper()}[/{color}]"


def print_mode(mode: str) -> None:
    if RICH:
        icons = {"observe": "[yellow]![/yellow]", "enforce": "[green]+[/green]", "halt": "[red]X[/red]"}
        icon = icons.get(mode, " ")
        console.print(f"  {icon} Mode: {mode_label(mode)}")
    else:
        print(f"  Mode: {mode.upper()}")


# ---------------------------------------------------------------------------
# Severity colors (for analyze)
# ---------------------------------------------------------------------------


def severity_label(severity: str) -> str:
    if not RICH:
        return severity.upper()
    colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}
    color = colors.get(severity, "white")
    return f"[{color}]{severity.upper()}[/{color}]"
