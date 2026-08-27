"""Unidirectional memory reading: tag -> file.  Never file -> tag.

Scope and limits
----------------
* MIFARE Classic sectors are read **only** with keys the operator supplies
  (``--key`` / ``--keys``).  RFIDeye ships the publicly documented *factory
  default* key list so you can practise on blank or personal tags; it never
  attempts nested, darkside, hardnested or any other key-recovery attack -
  those verbs are blocked by :mod:`rfideye.read_only_guard`.
* Ultralight/NTAG, ISO15693 and T55xx expose their memory without keys; those
  reads are plain ``dump`` commands.
* Nothing here can write.  The only sink is a JSON/CSV file on your disk.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from rfideye.device import DeviceError, Proxmark3
from rfideye.identify import TagIdentity

LOGGER: Final[logging.Logger] = logging.getLogger("rfideye.dump")

#: Publicly documented factory/transport keys shipped by every vendor SDK.
#: Provided for practising on tags you own; see the README's legal notice.
FACTORY_DEFAULT_KEYS: Final[tuple[str, ...]] = (
    "FFFFFFFFFFFF",  # blank / factory default
    "000000000000",
    "A0A1A2A3A4A5",  # NXP MAD sector key A
    "B0B1B2B3B4B5",
    "D3F7D3F7D3F7",  # NDEF public key
    "AABBCCDDEEFF",
)

_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9A-Fa-f]{12}$")
#: ``[=]   4 | 00 11 22 ... | ascii`` - the client's standard block layout.
_BLOCK_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:\[[=+]\]\s*)?(\d{1,3})\s*[|:]\s*([0-9A-Fa-f]{2}(?:[ ][0-9A-Fa-f]{2})+)"
)


@dataclass(slots=True)
class Block:
    """One block/page read from a tag."""

    index: int
    data: str          # space-separated uppercase hex
    readable: bool = True
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "data": self.data,
                "readable": self.readable, "note": self.note}


@dataclass(slots=True)
class MemoryDump:
    """The result of reading whatever a tag was willing to hand over."""

    technology: str
    blocks: list[Block] = field(default_factory=list)
    #: Sector/block indexes that could not be read, with the reason.
    failures: dict[str, str] = field(default_factory=dict)
    key_source: str = "none required"
    partial: bool = False

    @property
    def bytes_read(self) -> int:
        return sum(len(block.data.split()) for block in self.blocks if block.readable)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technology": self.technology,
            "key_source": self.key_source,
            "partial": self.partial,
            "bytes_read": self.bytes_read,
            "blocks": [block.to_dict() for block in self.blocks],
            "failures": dict(self.failures),
        }


def load_keys(source: str | Path | None) -> list[str]:
    """Load MIFARE keys from a file, a literal key, or the factory defaults.

    Args:
        source: ``"factory"`` for the bundled default list, a 12-hex-digit
            literal key, or a path to a newline-separated key file
            (``#`` starts a comment).

    Returns:
        Upper-case, de-duplicated keys, order preserved.

    Raises:
        ValueError: If a key file contains no valid key.
    """
    if source is None:
        return []
    text = str(source)

    if text.lower() == "factory":
        return list(FACTORY_DEFAULT_KEYS)

    if _KEY_RE.match(text):
        return [text.upper()]

    path = Path(text).expanduser()
    if not path.is_file():
        raise ValueError(f"{text!r} is neither a 12-hex-digit key, 'factory', nor a readable file")

    keys: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        candidate = line.split("#", 1)[0].strip().replace(" ", "")
        if _KEY_RE.match(candidate):
            upper = candidate.upper()
            if upper not in keys:
                keys.append(upper)
    if not keys:
        raise ValueError(f"no valid 12-hex-digit keys found in {path}")
    return keys


def parse_blocks(text: str) -> list[Block]:
    """Extract ``index -> hex data`` pairs from client dump output."""
    blocks: list[Block] = []
    for line in text.splitlines():
        match = _BLOCK_RE.match(line)
        if match:
            index = int(match.group(1))
            data = " ".join(match.group(2).split()).upper()
            blocks.append(Block(index=index, data=data))
    return blocks


# --------------------------------------------------------------------------- #
# Per-technology readers
# --------------------------------------------------------------------------- #
def dump_mifare_classic(
    device: Proxmark3, keys: Sequence[str], *, sectors: int = 16
) -> MemoryDump:
    """Read MIFARE Classic sectors using operator-supplied keys.

    For each sector the supplied keys are tried in order, as key A then key B.
    A sector that no supplied key opens is simply recorded as unreadable - the
    tool stops there by design.

    Args:
        device: A connected Proxmark3.
        keys: 12-hex-digit keys the operator already holds.
        sectors: 16 for a 1K tag, 40 for a 4K tag.
    """
    dump = MemoryDump(technology="MIFARE Classic",
                      key_source=f"{len(keys)} operator-supplied key(s)")
    if not keys:
        dump.failures["*"] = "no keys supplied; nothing was attempted"
        dump.partial = True
        return dump

    for sector in range(sectors):
        sector_blocks, note = _read_sector(device, sector, keys)
        if sector_blocks:
            dump.blocks.extend(sector_blocks)
        else:
            dump.failures[f"sector {sector}"] = note
            dump.partial = True
    return dump


def _read_sector(
    device: Proxmark3, sector: int, keys: Sequence[str]
) -> tuple[list[Block], str]:
    """Try every key (A then B) against one sector.  Returns blocks or a reason."""
    for key in keys:
        for key_type in ("-a", "-b"):
            command = f"hf mf rdsc -s {sector} -k {key} {key_type}"
            try:
                result = device.execute(command)
            except DeviceError as exc:
                LOGGER.debug("sector %d read error: %s", sector, exc)
                continue
            blocks = parse_blocks(result.stdout)
            if blocks:
                LOGGER.debug("sector %d opened with key %s (%s)", sector, key, key_type)
                return blocks, ""
    return [], "no supplied key opened this sector"


def dump_ultralight(device: Proxmark3, key: str | None = None) -> MemoryDump:
    """Read every readable page of an Ultralight / NTAG tag."""
    command = "hf mfu dump --ns" + (f" -k {key}" if key else "")
    dump = MemoryDump(technology="MIFARE Ultralight / NTAG",
                      key_source="password" if key else "none required")
    result = device.execute(command, timeout=40)
    dump.blocks = parse_blocks(result.stdout)
    if not dump.blocks:
        dump.failures["*"] = "the client returned no page data"
        dump.partial = True
    return dump


def dump_iso15693(device: Proxmark3) -> MemoryDump:
    """Read every readable block of an ISO15693 vicinity tag."""
    dump = MemoryDump(technology="ISO15693")
    result = device.execute("hf 15 dump --ns", timeout=60)
    dump.blocks = parse_blocks(result.stdout)
    if not dump.blocks:
        dump.failures["*"] = "the client returned no block data"
        dump.partial = True
    return dump


def dump_t55xx(device: Proxmark3) -> MemoryDump:
    """Read every block of a T55xx LF transponder."""
    dump = MemoryDump(technology="T55xx")
    result = device.execute("lf t55xx dump", timeout=60)
    dump.blocks = parse_blocks(result.stdout)
    if not dump.blocks:
        dump.failures["*"] = "the client returned no block data"
        dump.partial = True
    return dump


def dump_for(
    device: Proxmark3, identity: TagIdentity, *, keys: Sequence[str] = ()
) -> MemoryDump:
    """Pick and run the right reader for an already-identified tag.

    Returns an empty, annotated :class:`MemoryDump` for technologies whose
    memory is not readable without issuer keys (DESFire, Calypso, iCLASS).
    """
    product = identity.product.lower()
    technology = identity.technology.lower()

    if "classic" in product:
        sectors = 40 if "4k" in product else 16
        return dump_mifare_classic(device, keys, sectors=sectors)
    if "ultralight" in product or "ntag" in product:
        return dump_ultralight(device)
    if "iso15693" in technology:
        return dump_iso15693(device)
    if "t55" in product:
        return dump_t55xx(device)

    reason = (
        "This technology stores its data behind issuer-held keys "
        "(secure messaging / mutual authentication). RFIDeye reads only what "
        "the tag offers unauthenticated."
    )
    return MemoryDump(technology=identity.technology, failures={"*": reason}, partial=True)
