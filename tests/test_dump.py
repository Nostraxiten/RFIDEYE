"""Memory-reading tests: key handling, block parsing, and the write ban."""

from __future__ import annotations

from pathlib import Path

import pytest

from rfideye import demo
from rfideye.device import DemoTransport, Proxmark3
from rfideye.dump import (
    FACTORY_DEFAULT_KEYS,
    dump_for,
    dump_mifare_classic,
    dump_ultralight,
    load_keys,
    parse_blocks,
)
from rfideye.identify import Band, TagIdentity

SECTOR_OUTPUT = """\
[=] ----+-------------------------------------------------+-----------------
[=]   0 | 04 3B 1A 2C 5E 60 80 04 00 46 59 25 58 49 10 23 | .;.,^`...FY%XI.#
[=]   1 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
[=]   2 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
[=]   3 | 00 00 00 00 00 00 FF 07 80 69 FF FF FF FF FF FF | .........i......
"""


def _device(**responses: str) -> Proxmark3:
    merged = dict(demo.DEMO_RESPONSES)
    merged.update(responses)
    return Proxmark3(DemoTransport(merged))


# --------------------------------------------------------------------------- #
# Key input
# --------------------------------------------------------------------------- #
def test_load_keys_accepts_a_literal_key() -> None:
    assert load_keys("a0a1a2a3a4a5") == ["A0A1A2A3A4A5"]


def test_load_keys_factory_list() -> None:
    assert load_keys("factory") == list(FACTORY_DEFAULT_KEYS)


def test_load_keys_from_a_file(tmp_path: Path) -> None:
    keyfile = tmp_path / "keys.dic"
    keyfile.write_text(
        "# my own tags\n"
        "FFFFFFFFFFFF\n"
        "a0a1a2a3a4a5   # MAD key\n"
        "not-a-key\n"
        "FFFFFFFFFFFF\n",
        encoding="utf-8",
    )
    assert load_keys(keyfile) == ["FFFFFFFFFFFF", "A0A1A2A3A4A5"]


def test_load_keys_without_input_is_empty() -> None:
    assert load_keys(None) == []


def test_load_keys_rejects_garbage(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_keys("definitely not a key or a file")

    empty = tmp_path / "empty.dic"
    empty.write_text("# nothing here\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_keys(empty)


# --------------------------------------------------------------------------- #
# Block parsing
# --------------------------------------------------------------------------- #
def test_parse_blocks() -> None:
    blocks = parse_blocks(SECTOR_OUTPUT)
    assert [block.index for block in blocks] == [0, 1, 2, 3]
    assert blocks[0].data.startswith("04 3B 1A 2C")


def test_parse_blocks_ignores_noise() -> None:
    assert parse_blocks("[!] failed to authenticate\nnothing here\n") == []


# --------------------------------------------------------------------------- #
# Readers
# --------------------------------------------------------------------------- #
def test_mifare_classic_without_keys_reads_nothing() -> None:
    dump = dump_mifare_classic(_device(), keys=[], sectors=4)
    assert dump.blocks == []
    assert dump.partial
    assert "no keys supplied" in dump.failures["*"]


def test_mifare_classic_with_a_working_key() -> None:
    responses = {
        f"hf mf rdsc -s {sector} -k FFFFFFFFFFFF -a": SECTOR_OUTPUT for sector in range(2)
    }
    dump = dump_mifare_classic(_device(**responses), keys=["FFFFFFFFFFFF"], sectors=2)
    assert len(dump.blocks) == 8
    assert not dump.partial
    assert dump.bytes_read == 8 * 16


def test_mifare_classic_records_sectors_it_cannot_open() -> None:
    responses = {"hf mf rdsc -s 0 -k FFFFFFFFFFFF -a": SECTOR_OUTPUT}
    dump = dump_mifare_classic(_device(**responses), keys=["FFFFFFFFFFFF"], sectors=2)
    assert dump.partial
    assert "sector 1" in dump.failures


def test_ultralight_dump() -> None:
    dump = dump_ultralight(_device())
    assert [block.index for block in dump.blocks] == [0, 1, 2, 3]


def test_dump_for_refuses_technologies_that_need_issuer_keys() -> None:
    identity = TagIdentity(band=Band.HF, technology="ISO14443-B", product="Calypso card")
    dump = dump_for(_device(), identity)
    assert dump.blocks == []
    assert "issuer-held keys" in dump.failures["*"]


def test_dump_to_dict_is_json_safe() -> None:
    dump = dump_ultralight(_device())
    payload = dump.to_dict()
    assert payload["technology"].startswith("MIFARE Ultralight")
    assert isinstance(payload["blocks"], list)
