"""Report rendering and transit-profiling tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from rfideye.identify import Band, TagIdentity
from rfideye.report import (
    READ_ONLY_STATEMENT,
    ReportMeta,
    render_html,
    render_markdown,
    write_report,
)
from rfideye.storage import History
from rfideye.transit import profile as transit_profile


@pytest.fixture
def records(tmp_path: Path):
    identity = TagIdentity(
        band=Band.HF,
        technology="ISO14443-B",
        product="ISO14443-B tag",
        uid="8A245501",
        confidence=0.6,
        notes=["PUPI may be randomised."],
        extra={"application_data": "05 00 00 00"},
        raw={"hf 14b info": "[=] Calypso card detected"},
    )
    with History(tmp_path / "r.db", session_id="sess01") as history:
        history.record(identity, transit_profile(identity))
        yield history.for_session()


@pytest.fixture
def meta() -> ReportMeta:
    return ReportMeta(
        session_id="sess01",
        device_port="/dev/ttyACM0",
        device_description="Proxmark3 RDV4",
        firmware="Iceman/master/v4.18994 (Iceman)",
        operator_note="Audit of my own transit card.",
    )


def test_markdown_report_contains_the_read_only_statement(records, meta) -> None:
    text = render_markdown(records, meta)
    assert READ_ONLY_STATEMENT in text
    assert "8A245501" in text
    assert "Calypso" in text
    assert "sess01" in text


def test_markdown_includes_the_operator_note(records, meta) -> None:
    assert "Audit of my own transit card." in render_markdown(records, meta)


def test_html_report_is_self_contained(records, meta) -> None:
    html = render_html(records, meta)
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    # No external assets: a report must open offline.
    assert "http://" not in html and "https://" not in html
    assert "8A245501" in html


def test_html_escapes_user_supplied_text(records) -> None:
    meta = ReportMeta(session_id="s", operator_note="<script>alert(1)</script>")
    html = render_html(records, meta)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_write_report_to_a_directory(tmp_path: Path, records, meta, fmt: str) -> None:
    path = write_report(records, meta, tmp_path / "reports", fmt=fmt)
    assert path.exists()
    assert path.suffix == f".{fmt}"
    assert path.read_text(encoding="utf-8")


def test_write_report_rejects_unknown_formats(tmp_path: Path, records, meta) -> None:
    with pytest.raises(ValueError):
        write_report(records, meta, tmp_path / "x.pdf", fmt="pdf")


# --------------------------------------------------------------------------- #
# Transit profiling
# --------------------------------------------------------------------------- #
def test_calypso_is_detected_from_raw_output() -> None:
    identity = TagIdentity(
        band=Band.HF, technology="ISO14443-B", product="ISO14443-B tag",
        raw={"hf 14b info": "[=] Answers to Calypso"},
    )
    result = transit_profile(identity)
    assert result.scheme == "Calypso"
    assert result.confidence >= 0.9
    assert result.locked_behind


def test_plain_iso14443b_is_a_weak_calypso_candidate() -> None:
    identity = TagIdentity(band=Band.HF, technology="ISO14443-B", product="ISO14443-B tag")
    result = transit_profile(identity)
    assert result.scheme == "Calypso"
    assert result.confidence < 0.9


def test_desfire_profile() -> None:
    identity = TagIdentity(band=Band.HF, technology="ISO14443-A (type 4)",
                           product="MIFARE DESFire EV1")
    result = transit_profile(identity)
    assert result.scheme == "MIFARE DESFire"
    assert any("AES" in item for item in result.locked_behind)


def test_lf_tags_are_not_transit_media() -> None:
    identity = TagIdentity(band=Band.LF, technology="EM4100 125 kHz", product="EM410x")
    result = transit_profile(identity)
    assert not result.is_transit_candidate


def test_profiles_never_promise_to_read_private_data() -> None:
    """No profile may claim fare history or balance is readable."""
    for product, technology in (
        ("MIFARE DESFire EV1", "ISO14443-A (type 4)"),
        ("MIFARE Ultralight C", "ISO14443-A (type 2)"),
        ("MIFARE Classic 1K", "ISO14443-A"),
        ("Sony FeliCa", "FeliCa"),
    ):
        result = transit_profile(
            TagIdentity(band=Band.HF, technology=technology, product=product)
        )
        blob = " ".join(result.public_fields).lower()
        assert "balance" not in blob
        assert "history" not in blob
