"""History persistence and export tests."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from rfideye.identify import Band, TagIdentity
from rfideye.storage import History, export_csv, export_json, iter_identities, new_session_id
from rfideye.transit import profile as transit_profile


@pytest.fixture
def identity() -> TagIdentity:
    return TagIdentity(
        band=Band.HF,
        technology="ISO14443-A",
        product="MIFARE Classic 1K",
        uid="DEADBEEF",
        atqa="00 04",
        sak="08",
        confidence=0.85,
        extra={"manufacturer": "NXP"},
        notes=["Legacy scheme."],
    )


@pytest.fixture
def history(tmp_path: Path) -> History:
    with History(tmp_path / "test.db") as store:
        yield store


def test_record_and_read_back(history: History, identity: TagIdentity) -> None:
    row_id = history.record(identity, transit_profile(identity))
    assert row_id > 0

    records = history.recent()
    assert len(records) == 1
    record = records[0]
    assert record.uid == "DEADBEEF"
    assert record.product == "MIFARE Classic 1K"
    assert record.extra["manufacturer"] == "NXP"
    assert record.transit is not None
    assert record.transit["scheme"].startswith("MIFARE Classic")


def test_session_scoping(tmp_path: Path, identity: TagIdentity) -> None:
    path = tmp_path / "test.db"
    with History(path, session_id="aaa") as first:
        first.record(identity)
    with History(path, session_id="bbb") as second:
        second.record(identity)
        assert len(second.for_session()) == 1
        assert len(second.for_session("aaa")) == 1
        assert second.count() == 2


def test_seen_before(history: History, identity: TagIdentity) -> None:
    history.record(identity)
    assert history.seen_before("DEADBEEF") is False  # first sighting only
    history.record(identity)
    assert history.seen_before("DEADBEEF") is True
    assert history.seen_before(None) is False


def test_by_uid_is_case_insensitive(history: History, identity: TagIdentity) -> None:
    history.record(identity)
    assert len(history.by_uid("deadbeef")) == 1


def test_stats(history: History, identity: TagIdentity) -> None:
    history.record(identity)
    history.record(identity)
    assert history.stats() == {"MIFARE Classic 1K": 2}


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #
def test_export_json_from_identities(tmp_path: Path, identity: TagIdentity) -> None:
    path = export_json([identity], tmp_path / "out.json", include_raw=True)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["read_only"] is True
    assert payload["records"][0]["uid"] == "DEADBEEF"


def test_export_json_to_directory_generates_a_name(
    tmp_path: Path, identity: TagIdentity
) -> None:
    path = export_json([identity], tmp_path / "dumps")
    assert path.parent.name == "dumps"
    assert path.suffix == ".json"


def test_export_csv(tmp_path: Path, history: History, identity: TagIdentity) -> None:
    history.record(identity)
    path = export_csv(history.recent(), tmp_path / "out.csv")
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    assert rows[0]["uid"] == "DEADBEEF"
    assert rows[0]["notes"] == "Legacy scheme."


def test_iter_identities_roundtrip(history: History, identity: TagIdentity) -> None:
    history.record(identity)
    restored = list(iter_identities(history.recent()))
    assert restored[0].band is Band.HF
    assert restored[0].uid == "DEADBEEF"


def test_new_session_id_is_unique() -> None:
    assert new_session_id() != new_session_id()
