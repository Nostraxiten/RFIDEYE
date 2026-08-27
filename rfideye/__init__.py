"""RFIDeye - a strictly read-only Proxmark3 front-end for RFID/NFC auditing.

RFIDeye wraps the official Iceman ``pm3`` client with a guarded, guided and
colourful terminal interface.  Every command that reaches the hardware is
validated against an explicit allow-list of *read / identify* operations
(see :mod:`rfideye.read_only_guard`).  Writing, cloning, emulating or
simulating tags is impossible by construction - there is no code path for it.
"""

from __future__ import annotations

__all__ = ["APP_NAME", "APP_TAGLINE", "__version__"]

__version__: str = "0.1.0"

APP_NAME: str = "RFIDeye"
APP_TAGLINE: str = "Read-only RFID/NFC identification console for Proxmark3 (Iceman)"
