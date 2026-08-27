"""Public-transport card profiling (read-only, no authentication attempts).

European transit ticketing converged on a small set of carriers:

* **Calypso** (ISO14443-B or B-prime; Navigo, OV-chipkaart legacy, Lisboa Viva,
  many Spanish and Italian city cards) - an application standard on top of the
  ISO layer.
* **MIFARE DESFire EV1/EV2** - the dominant modern choice for season passes.
* **MIFARE Ultralight / Ultralight C** - single-ride and short-term tickets.
* **MIFARE Classic 1K** - legacy deployments still in service.
* **FeliCa** - mostly Asia, occasionally on European tourist cards.
* **iCLASS / ISO15693** - rare in transit, common in building access.

What this module does
---------------------
It maps an already-identified tag onto the *most likely* ticketing scheme and
lists which fields are readable without any key, purely from the anticollision
and ATR/ATS layers.  It never authenticates, never guesses keys and never
decodes fare/balance data - reading a passenger's travel history is both
outside the read-only remit and a privacy problem.

The result is a heuristic and is labelled as such in the UI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

from rfideye.identify import Band, TagIdentity


@dataclass(slots=True)
class TransitProfile:
    """A best-effort guess at the ticketing scheme behind a tag."""

    #: e.g. "Calypso", "MIFARE DESFire", "unknown".
    scheme: str = "unknown"
    #: 0.0 - 1.0.
    confidence: float = 0.0
    #: Fields readable with no key at all.
    public_fields: list[str] = field(default_factory=list)
    #: What would be needed (and is deliberately not attempted) to read more.
    locked_behind: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_transit_candidate(self) -> bool:
        return self.scheme != "unknown"

    def to_dict(self) -> dict[str, object]:
        return {
            "scheme": self.scheme,
            "confidence": round(self.confidence, 2),
            "public_fields": list(self.public_fields),
            "locked_behind": list(self.locked_behind),
            "notes": list(self.notes),
        }


#: Signatures that strongly suggest a Calypso card, searched in raw output.
_CALYPSO_MARKERS: Final[tuple[str, ...]] = (
    r"calypso",
    r"1TIC\.ICA",
    r"innovatron",
    r"\bCD97\b",
)

_PRIVACY_NOTE: Final[str] = (
    "Fare history, balance and personal data are protected by issuer keys. "
    "RFIDeye does not attempt to read them."
)


def profile(identity: TagIdentity) -> TransitProfile:
    """Classify a tag against the common transit ticketing schemes.

    Args:
        identity: A populated :class:`~rfideye.identify.TagIdentity`.

    Returns:
        A :class:`TransitProfile`.  ``scheme == "unknown"`` when the tag does
        not look like transit media.
    """
    raw_blob = "\n".join(identity.raw.values())
    product = identity.product.lower()

    if any(re.search(marker, raw_blob, re.IGNORECASE) for marker in _CALYPSO_MARKERS):
        return _calypso(identity, confidence=0.9)

    if identity.technology.startswith("ISO14443-B"):
        # Calypso is by far the most common ISO14443-B card in the wild in
        # Europe, but plain B tags exist too - hence the lower confidence.
        return _calypso(identity, confidence=0.5)

    if "desfire" in product:
        return TransitProfile(
            scheme="MIFARE DESFire",
            confidence=0.75,
            public_fields=["UID (or random UID)", "ATQA / SAK / ATS", "hardware version block"],
            locked_behind=["AES/3DES application keys held by the transit operator"],
            notes=[
                "Season passes and city cards commonly use DESFire EV1/EV2.",
                "Application and file listing may be refused without authentication.",
                _PRIVACY_NOTE,
            ],
        )

    if "ultralight" in product or "ntag" in product:
        return TransitProfile(
            scheme="MIFARE Ultralight family",
            confidence=0.6,
            public_fields=["UID", "OTP and lock bytes", "user pages that are not password-locked"],
            locked_behind=["Ultralight C 3DES key or EV1 PWD/PACK, when configured"],
            notes=[
                "Typical of single-ride and limited-use paper/plastic tickets.",
                _PRIVACY_NOTE,
            ],
        )

    if "classic" in product:
        return TransitProfile(
            scheme="MIFARE Classic (legacy transit)",
            confidence=0.5,
            public_fields=["UID", "ATQA / SAK", "manufacturer block 0 (usually readable)"],
            locked_behind=["Sector keys A/B - supply your own with --key for cards you own"],
            notes=[
                "Legacy scheme; still deployed in some networks.",
                "RFIDeye will not recover unknown keys. Supply keys you already hold.",
                _PRIVACY_NOTE,
            ],
        )

    if "felica" in product:
        return TransitProfile(
            scheme="FeliCa",
            confidence=0.7,
            public_fields=["IDm / PMm", "system and service codes"],
            locked_behind=["Service-level authentication for stored-value areas"],
            notes=["Common on Asian transit networks (Suica, Octopus).", _PRIVACY_NOTE],
        )

    if identity.band is Band.LF:
        return TransitProfile(
            scheme="unknown",
            notes=["LF tags are not used for modern transit ticketing."],
        )

    return TransitProfile(scheme="unknown", notes=["No transit ticketing signature recognised."])


def _calypso(identity: TagIdentity, *, confidence: float) -> TransitProfile:
    """Build the Calypso profile, including any public PUPI/ATR fields found."""
    public = ["PUPI (ISO14443-B pseudo-unique identifier)", "Protocol and application data bytes"]
    if "application_data" in identity.extra:
        public.append(f"Application data: {identity.extra['application_data']}")

    return TransitProfile(
        scheme="Calypso",
        confidence=confidence,
        public_fields=public,
        locked_behind=[
            "Calypso session keys held by the transit authority",
            "Environment, contract and event files require a secure session",
        ],
        notes=[
            "Calypso is the dominant European transit standard "
            "(Navigo, Lisboa Viva, many Spanish and Italian city cards).",
            "The PUPI is often randomised per session, so it is not a stable identifier.",
            _PRIVACY_NOTE,
        ],
    )
