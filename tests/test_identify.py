"""Parser and identification tests - no hardware, only strings."""

from __future__ import annotations

import pytest

from rfideye import demo
from rfideye.device import DemoTransport, Proxmark3, parse_version
from rfideye.identify import (
    Band,
    Identifier,
    describe_atqa_sak,
    parse_14a_info,
    parse_14b_info,
    parse_hf_search,
    parse_lf_search,
    parse_mfu_info,
)


def _demo_device(**overrides: str) -> Proxmark3:
    responses = dict(demo.DEMO_RESPONSES)
    responses.update(overrides)
    return Proxmark3(DemoTransport(responses))


# --------------------------------------------------------------------------- #
# ATQA / SAK table
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("atqa", "sak", "expected"),
    [
        ("00 04", "08", "MIFARE Classic 1K"),
        ("00 02", "18", "MIFARE Classic 4K"),
        ("00 04", "09", "MIFARE Mini 0.3K"),
        ("00 44", "00", "MIFARE Ultralight / Ultralight C / NTAG21x"),
        ("03 44", "20", "MIFARE DESFire (EV1/EV2/EV3) or MIFARE Plus SL3"),
    ],
)
def test_describe_atqa_sak(atqa: str, sak: str, expected: str) -> None:
    product, _technology, confidence = describe_atqa_sak(atqa, sak)
    assert product == expected
    assert 0.0 < confidence <= 1.0


def test_describe_atqa_sak_without_sak_is_low_confidence() -> None:
    _product, _technology, confidence = describe_atqa_sak("00 04", None)
    assert confidence < 0.5


def test_desfire_ats_signature_raises_confidence() -> None:
    product, _technology, confidence = describe_atqa_sak(
        "03 44", "20", "06 75 77 81 02 80"
    )
    assert product == "MIFARE DESFire EV1"
    assert confidence >= 0.9


# --------------------------------------------------------------------------- #
# Field parsers
# --------------------------------------------------------------------------- #
def test_parse_14a_info() -> None:
    fields = parse_14a_info(demo.HF_14A_INFO)
    assert fields["uid"] == "04 3B 1A 2C 5E 60 80"
    assert fields["atqa"] == "00 44"
    assert fields["sak"] == "00"
    assert "NXP" in fields["manufacturer"]


def test_parse_14b_info() -> None:
    fields = parse_14b_info(demo.HF_14B_INFO)
    assert fields["pupi"] == "8A 24 55 01"
    assert fields["application_data"] == "05 00 00 00"


def test_parse_mfu_info() -> None:
    fields = parse_mfu_info(demo.HF_MFU_INFO)
    assert fields["product"].startswith("NTAG 215")
    assert fields["uid"] == "04 3B 1A 2C 5E 60 80"


# --------------------------------------------------------------------------- #
# Search parsers
# --------------------------------------------------------------------------- #
def test_parse_hf_search_detects_iso14443a() -> None:
    identity = parse_hf_search(demo.HF_SEARCH_MIFARE)
    assert identity is not None
    assert identity.band is Band.HF
    assert identity.uid == "04 3B 1A 2C 5E 60 80"
    assert "Ultralight" in identity.product


def test_parse_hf_search_detects_iso14443b() -> None:
    identity = parse_hf_search(demo.HF_SEARCH_CALYPSO)
    assert identity is not None
    assert identity.technology == "ISO14443-B"


def test_parse_hf_search_empty() -> None:
    assert parse_hf_search(demo.HF_SEARCH_EMPTY) is None


def test_parse_lf_search_detects_em410x() -> None:
    identity = parse_lf_search(demo.LF_SEARCH_EM410X)
    assert identity is not None
    assert identity.band is Band.LF
    assert identity.product.startswith("EM410x")
    assert identity.uid == "1A2B3C4D5E"


def test_parse_lf_search_empty() -> None:
    assert parse_lf_search(demo.LF_SEARCH_EMPTY) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("[+] HID Prox TAG ID: 2006ec0c86 FC: 118 CN: 1603", "HID Prox"),
        ("[+] Indala (len 64) Raw: a0000000c2c436c1", "Indala"),
        ("[+] AWID - len: 26 FC: 123 Card: 1337", "AWID"),
        ("[+] Chipset detection: T55xx", "T55xx programmable transponder"),
    ],
)
def test_lf_signature_table(text: str, expected: str) -> None:
    identity = parse_lf_search(text)
    assert identity is not None
    assert identity.product == expected


# --------------------------------------------------------------------------- #
# Full workflow against the demo transport
# --------------------------------------------------------------------------- #
def test_identifier_end_to_end_hf() -> None:
    identity = Identifier(_demo_device()).identify()
    assert identity.found
    assert identity.band is Band.HF
    # The follow-up ``hf mfu info`` should have refined the product name.
    assert identity.product.startswith("NTAG 215")
    assert identity.confidence >= 0.9
    assert "hf search" in identity.raw


def test_identifier_falls_back_to_lf() -> None:
    device = _demo_device(**{"hf search": demo.HF_SEARCH_EMPTY})
    identity = Identifier(device).identify()
    assert identity.band is Band.LF
    assert identity.product.startswith("EM410x")


def test_identifier_reports_nothing_found() -> None:
    device = _demo_device(
        **{"hf search": demo.HF_SEARCH_EMPTY, "lf search": demo.LF_SEARCH_EMPTY}
    )
    identity = Identifier(device).identify()
    assert not identity.found
    assert identity.notes


def test_identifier_can_be_restricted_to_one_band() -> None:
    identity = Identifier(_demo_device()).identify(band=Band.LF)
    assert identity.band is Band.LF


def test_parse_version_detects_iceman() -> None:
    firmware = parse_version(demo.HW_VERSION)
    assert firmware.is_iceman
    assert "Iceman" in firmware.client
    assert "RDV4" in firmware.hardware


def test_parse_version_flags_unknown_fork() -> None:
    firmware = parse_version("[=] Client .......... proxmark3 v3.1.0\n")
    assert not firmware.is_iceman
