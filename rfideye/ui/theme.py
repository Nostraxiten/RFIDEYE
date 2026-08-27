"""Colour scheme and shared rich renderables.

Palette contract (from the project brief):

* **green**  - success: device connected, tag read, command allowed.
* **red**    - failure: device missing, tag unsupported, command blocked.
* **amber**  - in progress / advisory: reading, heuristic result, warning.

Everything routes through named styles rather than literal colours so the whole
scheme can be retuned in one place (and so ``NO_COLOR`` is respected).
"""

from __future__ import annotations

import os
from enum import StrEnum
from typing import Final

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

RFIDEYE_THEME: Final[Theme] = Theme(
    {
        # semantic states
        "ok": "bold green",
        "ok.dim": "green",
        "err": "bold red",
        "err.dim": "red",
        "busy": "bold yellow",
        "warn": "yellow",
        # structure
        "title": "bold green",
        "subtitle": "dim white",
        "label": "bold white",
        "value": "bright_white",
        "muted": "dim white",
        "accent": "bold bright_green",
        "danger": "bold white on red",
        "rule": "green",
        "menu.key": "bold bright_green",
        "menu.text": "white",
        "table.header": "bold yellow",
    }
)


class Status(StrEnum):
    """The three UI states, mapped to theme styles."""

    OK = "ok"
    ERROR = "err"
    BUSY = "busy"

    @property
    def glyph(self) -> str:
        return {"ok": "[+]", "err": "[!]", "busy": "[~]"}[self.value]


def build_console(*, no_color: bool | None = None) -> Console:
    """Create the shared console.  Honours ``NO_COLOR`` and ``TERM=dumb``."""
    if no_color is None:
        no_color = bool(os.environ.get("NO_COLOR")) or os.environ.get("TERM") == "dumb"
    return Console(theme=RFIDEYE_THEME, no_color=no_color, highlight=False)


#: Process-wide console.  The CLI may replace it via :func:`set_console`.
console: Console = build_console()


def set_console(new_console: Console) -> None:
    """Replace the shared console (used by ``--no-color``)."""
    global console  # noqa: PLW0603 - single deliberate module-level singleton
    console = new_console


def status_text(status: Status, message: str) -> Text:
    """Return ``[+] message`` styled for the given status."""
    return Text.assemble((f"{status.glyph} ", status.value), (message, status.value))


def status_panel(status: Status, message: str, title: str = "") -> Panel:
    """Wrap a message in a colour-coded panel."""
    return Panel(
        Text(message, style=status.value),
        border_style=status.value,
        title=title or None,
        title_align="left",
    )


def kv_table(title: str = "") -> Table:
    """A two-column label/value table used all over the TUI."""
    table = Table(
        title=title or None,
        title_style="title",
        show_header=False,
        box=None,
        pad_edge=False,
        padding=(0, 2, 0, 0),
    )
    table.add_column(style="label", no_wrap=True)
    table.add_column(style="value", overflow="fold")
    return table


def data_table(*columns: str, title: str = "") -> Table:
    """A bordered table with the project's header styling."""
    table = Table(title=title or None, title_style="title", header_style="table.header",
                  border_style="rule", expand=False)
    for column in columns:
        table.add_column(column, overflow="fold")
    return table


def confidence_style(confidence: float) -> str:
    """Map a 0-1 confidence to a theme style (green / amber / red)."""
    if confidence >= 0.75:
        return "ok"
    if confidence >= 0.4:
        return "busy"
    return "err"
