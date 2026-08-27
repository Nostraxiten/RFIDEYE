"""Device layer tests: client lookup, argv construction, guard enforcement."""

from __future__ import annotations

from pathlib import Path

import pytest

from rfideye import demo
from rfideye.config import ENV_PM3_BIN
from rfideye.device import (
    ClientNotFoundError,
    DemoTransport,
    DeviceError,
    DeviceInfo,
    Pm3Transport,
    Proxmark3,
    find_client,
)
from rfideye.read_only_guard import GuardViolation


def test_find_client_rejects_a_bogus_explicit_path(tmp_path: Path) -> None:
    with pytest.raises(ClientNotFoundError):
        find_client(str(tmp_path / "nope"))


def test_find_client_honours_the_environment(tmp_path: Path, monkeypatch) -> None:
    fake = tmp_path / "pm3"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv(ENV_PM3_BIN, str(fake))
    assert find_client() == fake


def test_pm3_transport_builds_a_safe_argv() -> None:
    client = Path("/usr/local/bin/pm3")
    transport = Pm3Transport(client, "/dev/ttyACM0")
    argv = transport.build_argv(["hw version", "hf search"])
    assert argv == [
        str(client), "-p", "/dev/ttyACM0",
        "-c", "hw version",
        "-c", "hf search",
    ]
    # Commands are separate argv entries, never concatenated into a shell line.
    assert all(";" not in item for item in argv)


def test_execute_runs_allowed_commands() -> None:
    device = Proxmark3(DemoTransport(dict(demo.DEMO_RESPONSES)))
    result = device.execute("hw version")
    assert result.ok
    assert "Iceman" in result.stdout


@pytest.mark.parametrize(
    "command",
    [
        "hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 00",
        "hf mf sim",
        "lf hid clone -r 2006ec0c86",
        "script run whatever",
    ],
)
def test_execute_refuses_non_read_only_commands(command: str) -> None:
    """The device object has no path that bypasses the guard."""
    device = Proxmark3(DemoTransport(dict(demo.DEMO_RESPONSES)))
    with pytest.raises(GuardViolation):
        device.execute(command)


def test_execute_batch_validates_every_command() -> None:
    device = Proxmark3(DemoTransport(dict(demo.DEMO_RESPONSES)))
    with pytest.raises(GuardViolation):
        device.execute_batch(["hw version", "hf mf wrbl --blk 0"])


def test_proxmark3_has_no_raw_execution_api() -> None:
    """Guards against someone adding a bypass later."""
    forbidden_names = {"execute_raw", "raw", "send", "write", "unsafe_execute"}
    assert forbidden_names.isdisjoint(dir(Proxmark3))


def test_execute_without_a_transport_raises() -> None:
    with pytest.raises(DeviceError):
        Proxmark3().execute("hw version")


def test_refresh_firmware_parses_the_demo_output() -> None:
    device = Proxmark3(DemoTransport(dict(demo.DEMO_RESPONSES)),
                       DeviceInfo("demo://offline", "demo"))
    firmware = device.refresh_firmware()
    assert firmware.is_iceman
    assert device.firmware is firmware


def test_device_info_usb_id_formatting() -> None:
    assert DeviceInfo("/dev/ttyACM0", "pm3", 0x9AC4, 0x4B8F).usb_id == "9ac4:4b8f"
    assert DeviceInfo("/dev/ttyACM0", "pm3").usb_id == "unknown"
