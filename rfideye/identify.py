"""Tag identification: turn raw client output into a structured description.

The strategy mirrors what an operator does by hand:

1. Ask the HF antenna first (``hf search``), then the LF antenna (``lf search``).
2. From the family that answered, run the *specific* ``info`` command for that
   technology to collect UID / ATQA / SAK / ATS and vendor metadata.
3. Refine the product name from the ATQA+SAK pair, which is what actually
   distinguishes a MIFARE Classic 1K from a DESFire or an Ultralight.

Everything here is pure parsing over strings, so it is fully unit-testable
without hardware - see ``tests/test_identify.py``.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from rfideye.device import CommandResult, Proxmark3

LOGGER: Final[logging.Logger] = logging.getLogger("rfideye.identify")


class Band(StrEnum):
    """Radio band a tag answered on."""

    LF = "LF"          # 125 / 134 kHz
    HF = "HF"          # 13.56 MHz
    UNKNOWN = "unknown"


@dataclass(slots=True)
class TagIdentity:
    """Everything RFIDeye could learn about a tag without writing to it."""

    band: Band = Band.UNKNOWN
    technology: str = "unknown"
    product: str = "unknown"
    uid: str | None = None
    atqa: str | None = None
    sak: str | None = None
    ats: str | None = None
    #: Free-form technology-specific fields (facility code, memory size, ...).
    extra: dict[str, str] = field(default_factory=dict)
    #: Human-readable observations shown under the summary table.
    notes: list[str] = field(default_factory=list)
    #: 0.0 - 1.0 heuristic confidence in :attr:`product`.
    confidence: float = 0.0
    #: Raw client output, keyed by the command that produced it.
    raw: dict[str, str] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )

    @property
    def found(self) -> bool:
        """True when at least one antenna got an answer."""
        return self.band is not Band.UNKNOWN

    def add_note(self, note: str) -> None:
        if note not in self.notes:
            self.notes.append(note)

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        """Serialise to a JSON-friendly mapping."""
        payload: dict[str, Any] = {
            "timestamp": self.timestamp,
            "band": self.band.value,
            "technology": self.technology,
            "product": self.product,
            "uid": self.uid,
            "atqa": self.atqa,
            "sak": self.sak,
            "ats": self.ats,
            "confidence": round(self.confidence, 2),
            "extra": dict(self.extra),
            "notes": list(self.notes),
        }
        if include_raw:
            payload["raw"] = dict(self.raw)
        return payload


# --------------------------------------------------------------------------- #
# ATQA / SAK product table
# --------------------------------------------------------------------------- #
#: SAK -> (product, technology).  ATQA refines a few ambiguous entries below.
_SAK_TABLE: Final[Mapping[int, tuple[str, str]]] = {
    0x00: ("MIFARE Ultralight / NTAG", "ISO14443-A (type 2)"),
    0x08: ("MIFARE Classic 1K", "ISO14443-A"),
    0x09: ("MIFARE Mini 0.3K", "ISO14443-A"),
    0x10: ("MIFARE Plus 2K (SL2)", "ISO14443-A"),
    0x11: ("MIFARE Plus 4K (SL2)", "ISO14443-A"),
    0x18: ("MIFARE Classic 4K", "ISO14443-A"),
    0x19: ("MIFARE Classic 2K", "ISO14443-A"),
    0x20: ("ISO14443-4 smartcard (DESFire / Plus SL3 / JCOP)", "ISO14443-A (type 4)"),
    0x28: ("JCOP 31/41 (ISO14443-4)", "ISO14443-A (type 4)"),
    0x38: ("MIFARE Classic 4K emulated (SmartMX)", "ISO14443-A"),
    0x88: ("MIFARE Classic 1K (Infineon)", "ISO14443-A"),
    0x98: ("Gemplus MPCOS", "ISO14443-A"),
}

#: ATQA -> hint, used to disambiguate SAK 0x00 and 0x20.
_ATQA_HINTS: Final[Mapping[int, str]] = {
    0x0044: "MIFARE Ultralight / Ultralight C / NTAG21x",
    0x0344: "MIFARE DESFire (EV1/EV2/EV3) or Plus in SL3",
    0x0304: "MIFARE Plus / DESFire family",
    0x0004: "MIFARE Classic 1K family",
    0x0002: "MIFARE Classic 4K family",
    0x0048: "MIFARE Classic 4K (7-byte UID)",
}


def _to_int(value: str | None) -> int | None:
    """Parse ``'00 44'`` / ``'0x08'`` / ``'08'`` into an int, or None."""
    if not value:
        return None
    cleaned = value.replace("0x", "").replace("[", "").replace("]", "").replace(" ", "")
    try:
        return int(cleaned, 16)
    except ValueError:
        return None


def describe_atqa_sak(
    atqa: str | None, sak: str | None, ats: str | None = None
) -> tuple[str, str, float]:
    """Map an ATQA/SAK pair to ``(product, technology, confidence)``.

    Args:
        atqa: ATQA as printed by the client, e.g. ``"00 04"``.
        sak: SAK as printed by the client, e.g. ``"08"``.
        ats: ATS bytes, if the tag is ISO14443-4 compliant.

    Returns:
        Product name, technology label and a 0-1 confidence score.
    """
    sak_value = _to_int(sak)
    atqa_value = _to_int(atqa)

    if sak_value is None:
        return "unknown ISO14443-A tag", "ISO14443-A", 0.2

    product, technology = _SAK_TABLE.get(
        sak_value, ("unidentified ISO14443-A tag", "ISO14443-A")
    )
    confidence = 0.85 if sak_value in _SAK_TABLE else 0.3

    # SAK 0x00 and 0x20 cover several very different products; ATQA and the
    # presence of an ATS narrow them down considerably.
    if sak_value == 0x20 and atqa_value == 0x0344:
        product = "MIFARE DESFire (EV1/EV2/EV3) or MIFARE Plus SL3"
        confidence = 0.7
    if sak_value == 0x00 and atqa_value == 0x0044:
        product = "MIFARE Ultralight / Ultralight C / NTAG21x"
        confidence = 0.7
    if ats and "75 77 81 02" in ats:  # classic DESFire EV1 ATS signature
        product = "MIFARE DESFire EV1"
        confidence = 0.9

    return product, technology, confidence


# --------------------------------------------------------------------------- #
# Output parsers - one per client command
# --------------------------------------------------------------------------- #
def _search(pattern: str, text: str, flags: int = re.IGNORECASE) -> str | None:
    match = re.search(pattern, text, flags)
    return match.group(1).strip() if match else None


def parse_14a_info(text: str) -> dict[str, str]:
    """Extract UID / ATQA / SAK / ATS from ``hf 14a info`` output."""
    fields: dict[str, str] = {}
    mapping = {
        "uid": r"^\s*(?:\[[^\]]*\]\s*)?UID\.*\s*:?\s*([0-9A-Fa-f ]+)$",
        "atqa": r"^\s*(?:\[[^\]]*\]\s*)?ATQA\.*\s*:?\s*([0-9A-Fa-f ]+)$",
        "sak": r"^\s*(?:\[[^\]]*\]\s*)?SAK\.*\s*:?\s*([0-9A-Fa-f]{2})",
        "ats": r"^\s*(?:\[[^\]]*\]\s*)?ATS\.*\s*:?\s*([0-9A-Fa-f ]+)$",
    }
    for key, pattern in mapping.items():
        value = _search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if value:
            fields[key] = " ".join(value.split()).upper()

    manufacturer = _search(r"^\s*(?:\[[^\]]*\]\s*)?MANUFACTURER\s*:?\s*(.+)$",
                           text, re.IGNORECASE | re.MULTILINE)
    if manufacturer:
        fields["manufacturer"] = manufacturer
    return fields


def parse_14b_info(text: str) -> dict[str, str]:
    """Extract PUPI / application data from ``hf 14b info`` output."""
    fields: dict[str, str] = {}
    pupi = _search(r"(?:PUPI|UID)\.*\s*:?\s*([0-9A-Fa-f ]{8,})", text)
    if pupi:
        fields["pupi"] = " ".join(pupi.split()).upper()
    app_data = _search(r"Application Data\.*\s*:?\s*([0-9A-Fa-f ]+)", text)
    if app_data:
        fields["application_data"] = " ".join(app_data.split()).upper()
    protocol = _search(r"Protocol Info\.*\s*:?\s*([0-9A-Fa-f ]+)", text)
    if protocol:
        fields["protocol_info"] = " ".join(protocol.split()).upper()
    return fields


def parse_15_info(text: str) -> dict[str, str]:
    """Extract UID / manufacturer / memory layout from ``hf 15 info``."""
    fields: dict[str, str] = {}
    uid = _search(r"UID\.*\s*:?\s*([0-9A-Fa-fE ]{8,})", text)
    if uid:
        fields["uid"] = " ".join(uid.split()).upper()
    manufacturer = _search(r"(?:TYPE|Manufacturer)\.*\s*:?\s*(.+)$", text,
                           re.IGNORECASE | re.MULTILINE)
    if manufacturer:
        fields["manufacturer"] = manufacturer
    blocks = _search(r"(\d+)\s*\(x\s*\d+\s*bytes\)", text)
    if blocks:
        fields["blocks"] = blocks
    return fields


def parse_mfu_info(text: str) -> dict[str, str]:
    """Extract version / signature info from ``hf mfu info``."""
    fields: dict[str, str] = {}
    for key, pattern in {
        "uid": r"UID\.*\s*:?\s*([0-9A-Fa-f ]{8,})",
        "product": r"TYPE\.*\s*:?\s*(.+)$",
        "version": r"Version\.*\s*:?\s*([0-9A-Fa-f ]+)",
    }.items():
        value = _search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if value:
            fields[key] = " ".join(value.split())
    if re.search(r"signature", text, re.IGNORECASE):
        fields["has_signature"] = "yes"
    return fields


def parse_iclass_info(text: str) -> dict[str, str]:
    """Extract CSN and configuration from ``hf iclass info``."""
    fields: dict[str, str] = {}
    csn = _search(r"CSN\.*\s*:?\s*([0-9A-Fa-f ]{8,})", text)
    if csn:
        fields["csn"] = " ".join(csn.split()).upper()
    config = _search(r"Config\.*\s*:?\s*([0-9A-Fa-f ]+)", text)
    if config:
        fields["config"] = " ".join(config.split()).upper()
    return fields


#: LF signatures: regex -> (product, technology).
_LF_SIGNATURES: Final[tuple[tuple[str, tuple[str, str]], ...]] = (
    (r"EM\s*410x?\s*ID", ("EM410x (EM4100/EM4102)", "EM4100 125 kHz")),
    (r"\bEM4x05\b|\bEM4305\b|\bEM4205\b", ("EM4x05 / EM4305", "EM4x05 125 kHz")),
    (r"HID\s*Prox", ("HID Prox", "HID 125 kHz")),
    (r"\bIndala\b", ("Indala", "Indala 125 kHz")),
    (r"\bAWID\b", ("AWID", "AWID 125 kHz")),
    (r"\bioProx\b|\bIO\s*Prox\b", ("Kantech ioProx", "ioProx 125 kHz")),
    (r"\bParadox\b", ("Paradox", "Paradox 125 kHz")),
    (r"\bPyramid\b", ("Farpointe Pyramid", "Pyramid 125 kHz")),
    (r"\bViking\b", ("Viking", "Viking 125 kHz")),
    (r"\bNoralsy\b", ("Noralsy", "Noralsy 125 kHz")),
    (r"\bJablotron\b", ("Jablotron", "Jablotron 125 kHz")),
    (r"\bKeri\b", ("KERI", "KERI 125 kHz")),
    (r"\bNexWatch\b|\bQuadrakey\b", ("NexWatch / Quadrakey", "NexWatch 125 kHz")),
    (r"\bGallagher\b", ("Gallagher", "Gallagher 125 kHz")),
    (r"\bSecurakey\b", ("Securakey", "Securakey 125 kHz")),
    (r"\bVisa2000\b", ("Visa2000", "Visa2000 125 kHz")),
    (r"\bMotorola\b", ("Motorola Flexpass", "Motorola 125 kHz")),
    (r"\bFDX-?B\b", ("FDX-B animal transponder", "ISO11784/85 134 kHz")),
    (r"\bHitag\b", ("NXP Hitag", "Hitag 125 kHz")),
    (r"\bT55[x0-9]{2}\b", ("T55xx programmable transponder", "T55xx 125 kHz")),
)

#: HF signatures found in ``hf search`` output.
_HF_SIGNATURES: Final[tuple[tuple[str, tuple[str, str]], ...]] = (
    (r"ISO\s*14443-?A", ("ISO14443-A tag", "ISO14443-A")),
    (r"ISO\s*14443-?B", ("ISO14443-B tag", "ISO14443-B")),
    (r"ISO\s*15693", ("ISO15693 vicinity tag", "ISO15693")),
    (r"iCLASS|PicoPass", ("HID iCLASS / PicoPass", "iCLASS")),
    (r"\bTopaz\b|\bJewel\b", ("Topaz / Jewel", "ISO14443-A (type 1)")),
    (r"\bFeliCa\b", ("Sony FeliCa", "FeliCa / JIS X 6319-4")),
    (r"\bLEGIC\b", ("LEGIC Prime", "LEGIC")),
    (r"\bCryptoRF\b", ("Atmel CryptoRF", "ISO14443-B")),
)


def _match_signatures(
    text: str, table: tuple[tuple[str, tuple[str, str]], ...]
) -> tuple[str, str] | None:
    for pattern, value in table:
        if re.search(pattern, text, re.IGNORECASE):
            return value
    return None


def parse_lf_search(text: str) -> TagIdentity | None:
    """Turn ``lf search`` output into a :class:`TagIdentity`, or None."""
    if re.search(r"no known 125/134 khz tags found|couldn't identify", text, re.IGNORECASE):
        return None

    matched = _match_signatures(text, _LF_SIGNATURES)
    if matched is None:
        return None

    product, technology = matched
    identity = TagIdentity(band=Band.LF, technology=technology, product=product, confidence=0.8)

    uid = _search(r"(?:EM\s*410x?\s*ID|TAG ID|ID)\.*\s*:?\s*([0-9A-Fa-f]{8,})", text)
    if uid:
        identity.uid = uid.upper()

    facility = _search(r"(?:FC|Facility Code)\s*:?\s*(\d+)", text)
    card = _search(r"(?:CN|Card Number|Card)\s*:?\s*(\d+)", text)
    if facility:
        identity.extra["facility_code"] = facility
    if card:
        identity.extra["card_number"] = card

    if re.search(r"T55[x0-9]{2}", text, re.IGNORECASE) and "T55xx" not in product:
        identity.add_note("Signal is carried by a T55xx-compatible chip.")
    return identity


def parse_hf_search(text: str) -> TagIdentity | None:
    """Turn ``hf search`` output into a :class:`TagIdentity`, or None."""
    if re.search(r"no known/supported 13\.56 mhz tags found", text, re.IGNORECASE):
        return None

    matched = _match_signatures(text, _HF_SIGNATURES)
    if matched is None:
        return None

    product, technology = matched
    identity = TagIdentity(band=Band.HF, technology=technology, product=product, confidence=0.6)

    fields = parse_14a_info(text)
    identity.uid = fields.get("uid")
    identity.atqa = fields.get("atqa")
    identity.sak = fields.get("sak")
    identity.ats = fields.get("ats")
    if identity.sak:
        product, technology, confidence = describe_atqa_sak(
            identity.atqa, identity.sak, identity.ats
        )
        identity.product, identity.technology, identity.confidence = product, technology, confidence
    return identity


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
#: Follow-up ``info`` command per detected technology.
_FOLLOW_UP: Final[Mapping[str, tuple[str, ...]]] = {
    "ISO14443-A": ("hf 14a info",),
    "ISO14443-A (type 1)": ("hf topaz info",),
    "ISO14443-A (type 2)": ("hf 14a info", "hf mfu info"),
    "ISO14443-A (type 4)": ("hf 14a info", "hf mfdes info"),
    "ISO14443-B": ("hf 14b info",),
    "ISO15693": ("hf 15 info",),
    "iCLASS": ("hf iclass info",),
    "FeliCa / JIS X 6319-4": ("hf felica info",),
    "LEGIC": ("hf legic info",),
}


class Identifier:
    """Runs the identification workflow against a connected device."""

    def __init__(self, device: Proxmark3) -> None:
        self._device = device

    def identify(self, *, band: Band | None = None) -> TagIdentity:
        """Detect and describe whatever tag is on the antenna.

        Args:
            band: Restrict the search to one band.  ``None`` tries HF then LF,
                which is the common case for access-control and transit cards.

        Returns:
            A :class:`TagIdentity`; check :attr:`TagIdentity.found`.
        """
        order = [band] if band else [Band.HF, Band.LF]
        for candidate in order:
            identity = self._scan_band(candidate)
            if identity is not None:
                self._enrich(identity)
                return identity

        LOGGER.info("no tag detected on any band")
        return TagIdentity(notes=["No tag detected. Place the card flat on the antenna."])

    def _scan_band(self, band: Band) -> TagIdentity | None:
        command = "hf search" if band is Band.HF else "lf search"
        result: CommandResult = self._device.execute(command, timeout=40)
        parser = parse_hf_search if band is Band.HF else parse_lf_search
        identity = parser(result.stdout)
        if identity is not None:
            identity.raw[command] = result.stdout
        return identity

    def _enrich(self, identity: TagIdentity) -> None:
        """Run the technology-specific ``info`` command and merge its fields."""
        for command in _FOLLOW_UP.get(identity.technology, ()):
            try:
                result = self._device.execute(command, timeout=30)
            except Exception as exc:
                LOGGER.debug("enrichment command %r failed: %s", command, exc)
                continue

            identity.raw[command] = result.stdout
            if command == "hf 14a info":
                self._merge_14a(identity, result.stdout)
            elif command == "hf 14b info":
                identity.extra.update(parse_14b_info(result.stdout))
            elif command == "hf 15 info":
                fields = parse_15_info(result.stdout)
                identity.uid = fields.pop("uid", identity.uid)
                identity.extra.update(fields)
            elif command == "hf mfu info":
                fields = parse_mfu_info(result.stdout)
                if "product" in fields:
                    identity.product = fields.pop("product")
                    identity.confidence = 0.9
                identity.uid = fields.pop("uid", identity.uid)
                identity.extra.update(fields)
            elif command == "hf iclass info":
                fields = parse_iclass_info(result.stdout)
                identity.uid = fields.pop("csn", identity.uid)
                identity.extra.update(fields)
            elif command == "hf mfdes info" and re.search(
                r"desfire", result.stdout, re.IGNORECASE
            ):
                identity.product = "MIFARE DESFire"
                identity.confidence = 0.9

    @staticmethod
    def _merge_14a(identity: TagIdentity, output: str) -> None:
        fields = parse_14a_info(output)
        identity.uid = fields.get("uid", identity.uid)
        identity.atqa = fields.get("atqa", identity.atqa)
        identity.sak = fields.get("sak", identity.sak)
        identity.ats = fields.get("ats", identity.ats)
        if "manufacturer" in fields:
            identity.extra["manufacturer"] = fields["manufacturer"]
        if identity.sak:
            product, technology, confidence = describe_atqa_sak(
                identity.atqa, identity.sak, identity.ats
            )
            identity.product = product
            identity.technology = technology
            identity.confidence = max(identity.confidence, confidence)
