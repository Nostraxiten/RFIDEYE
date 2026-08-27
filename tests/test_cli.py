"""End-to-end CLI smoke tests, driven entirely through ``--demo`` mode."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rfideye.cli import app

runner = CliRunner()


@pytest.fixture
def env(tmp_path: Path) -> list[str]:
    """Global options that isolate every run inside tmp_path."""
    return ["--demo", "--no-color", "--data-dir", str(tmp_path)]


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "RFIDeye" in result.stdout


def test_commands_lists_the_allow_list() -> None:
    result = runner.invoke(app, ["--no-color", "commands"])
    assert result.exit_code == 0
    assert "hf 14a info" in result.stdout
    assert "blocked" in result.stdout.lower()


def test_scan_in_demo_mode(env: list[str]) -> None:
    result = runner.invoke(app, [*env, "scan"])
    assert result.exit_code == 0
    assert "NTAG 215" in result.stdout


def test_scan_writes_json(env: list[str], tmp_path: Path) -> None:
    out = tmp_path / "scan.json"
    result = runner.invoke(app, [*env, "scan", "--json", str(out)])
    assert result.exit_code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["read_only"] is True
    assert payload["records"][0]["band"] == "HF"


def test_scan_band_option_is_validated(env: list[str]) -> None:
    result = runner.invoke(app, [*env, "scan", "--band", "uhf"])
    assert result.exit_code != 0


def test_history_is_empty_then_populated(env: list[str]) -> None:
    empty = runner.invoke(app, [*env, "history"])
    assert "No scans recorded yet" in empty.stdout

    runner.invoke(app, [*env, "scan"])
    populated = runner.invoke(app, [*env, "history"])
    assert "NTAG 215" in populated.stdout


def test_dump_exports_memory(env: list[str], tmp_path: Path) -> None:
    out = tmp_path / "dump.json"
    result = runner.invoke(app, [*env, "dump", "--json", str(out)])
    assert result.exit_code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["memory"]["technology"].startswith("MIFARE Ultralight")
    assert payload["memory"]["blocks"]


def test_report_requires_scans(env: list[str]) -> None:
    result = runner.invoke(app, [*env, "report"])
    assert result.exit_code == 1


def test_report_html(env: list[str], tmp_path: Path) -> None:
    runner.invoke(app, [*env, "scan"])
    out = tmp_path / "report.html"
    # --last works across sessions, so the scan above is picked up.
    result = runner.invoke(app, [*env, "report", "--format", "html",
                                 "--last", "5", "--output", str(out)])
    assert result.exit_code == 0
    assert "<!doctype html>" in out.read_text(encoding="utf-8")


def test_doctor_runs_without_hardware(env: list[str]) -> None:
    result = runner.invoke(app, [*env, "doctor"])
    assert result.exit_code == 0
    assert "Environment" in result.stdout
