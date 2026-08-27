"""ASCII welcome banner.

Kept in its own module so the art can be swapped without touching the CLI, and
so a narrow terminal degrades to a compact one-liner instead of wrapping into
unreadable mush.
"""

from __future__ import annotations

from typing import Final

from rich.align import Align
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.text import Text

from rfideye import APP_TAGLINE, __version__

#: 62 columns wide.
_ASCII: Final[str] = r"""
 ____  _____ ___ ____
|  _ \|  ___|_ _|  _ \  ___ _   _  ___
| |_) | |_   | || | | |/ _ \ | | |/ _ \
|  _ <|  _|  | || |_| |  __/ |_| |  __/
|_| \_\_|   |___|____/ \___|\__, |\___|
                            |___/
"""

_MIN_WIDTH: Final[int] = 66

READ_ONLY_BADGE: Final[str] = (
    "READ-ONLY MODE - no write, clone, emulate or simulate commands exist"
)


def render_banner(width: int = 100) -> RenderableType:
    """Return the welcome banner sized for the current terminal.

    Args:
        width: Terminal width in columns.
    """
    if width < _MIN_WIDTH:
        return Panel(
            Text.assemble(
                ("RFIDeye ", "accent"),
                (f"v{__version__} ", "muted"),
                ("| READ-ONLY", "ok"),
            ),
            border_style="rule",
        )

    art = Text(_ASCII.strip("\n"), style="accent")
    subtitle = Text.assemble(
        (f"v{__version__}  ", "muted"),
        (APP_TAGLINE, "subtitle"),
    )
    badge = Text(READ_ONLY_BADGE, style="ok")

    return Panel(
        Group(Align.center(art), Align.center(subtitle), Text(""), Align.center(badge)),
        border_style="rule",
        padding=(1, 2),
    )


LEGAL_NOTICE: Final[str] = (
    "Use only on cards and systems you own or are explicitly authorised to "
    "audit. You are responsible for complying with local law."
)


def render_legal_notice() -> RenderableType:
    """A short, always-visible reminder of the tool's intended use."""
    return Panel(Text(LEGAL_NOTICE, style="warn"), border_style="warn",
                 title="Authorised use only", title_align="left")
