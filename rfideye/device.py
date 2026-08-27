"""Proxmark3 discovery, connection management and guarded command execution.

Responsibilities
----------------
* Autodetect the device over USB (VID/PID first, then port description, then a
  platform glob) so the user never has to pass ``-p /dev/ttyACM0`` by hand.
* Locate the official Iceman ``pm3`` client on ``PATH`` (or via
  ``RFIDEYE_PM3_BIN``) and query firmware / hardware revision.
* Execute commands - but **only** after :func:`rfideye.read_only_guard.validate`
  has approved them.  :class:`Proxmark3` has no other way to talk to the
  hardware, and no method accepts a pre-validated or raw command.
* Recover transparently when the device is unplugged mid-session.

Why ``subprocess`` and not a native protocol implementation: the Iceman client
already speaks the (frequently changing) USB protocol and does all the demod
work.  Re-implementing it would be a large attack surface for no benefit, and
would make it possible to send frames the guard never inspected.
"""

from __future__ import annotations

import glob
import logging
import os
import re
import shutil
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol

from rfideye import read_only_guard
from rfideye.config import ENV_PM3_BIN

LOGGER: Final[logging.Logger] = logging.getLogger("rfideye.device")

#: USB identifiers known to belong to a Proxmark3 (vid, pid, human label).
KNOWN_USB_IDS: Final[tuple[tuple[int, int, str], ...]] = (
    (0x9AC4, 0x4B8F, "Proxmark3 (CDC)"),
    (0x2D2D, 0x504D, "Proxmark3 RDV4"),
    (0x1D50, 0x60E9, "Proxmark3 (OpenMoko allocation)"),
)

#: Substrings that identify a Proxmark3 by its USB product/manufacturer string.
DESCRIPTION_HINTS: Final[tuple[str, ...]] = ("proxmark", "pm3", "iceman")

#: Serial-port globs used as a last resort, per platform.
PORT_GLOBS: Final[dict[str, tuple[str, ...]]] = {
    "posix": ("/dev/ttyACM*", "/dev/ttyUSB*", "/dev/tty.usbmodem*"),
    "nt": (),
}

DEFAULT_TIMEOUT: Final[float] = 25.0


class DeviceError(RuntimeError):
    """Base class for every recoverable hardware-layer problem."""


class ClientNotFoundError(DeviceError):
    """The Iceman ``pm3`` client could not be located."""


class DeviceNotFoundError(DeviceError):
    """No Proxmark3 was found on any serial port."""


class CommandFailedError(DeviceError):
    """The client returned a non-zero exit status or timed out."""


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """A serial port that looks like a Proxmark3."""

    port: str
    description: str
    vid: int | None = None
    pid: int | None = None
    serial_number: str | None = None
    #: How the port was found: ``usb-id``, ``description`` or ``glob``.
    match: str = "glob"

    @property
    def usb_id(self) -> str:
        if self.vid is None or self.pid is None:
            return "unknown"
        return f"{self.vid:04x}:{self.pid:04x}"


@dataclass(frozen=True, slots=True)
class FirmwareInfo:
    """Parsed output of ``hw version``."""

    client: str = "unknown"
    bootrom: str = "unknown"
    os_image: str = "unknown"
    hardware: str = "unknown"
    is_iceman: bool = False
    raw: str = ""

    @property
    def summary(self) -> str:
        flavour = "Iceman" if self.is_iceman else "unknown fork"
        return f"{self.os_image} ({flavour})"


@dataclass(frozen=True, slots=True)
class CommandResult:
    """The outcome of one guarded command."""

    command: str
    stdout: str
    stderr: str
    returncode: int
    duration: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def lines(self) -> list[str]:
        return [line.rstrip() for line in self.stdout.splitlines()]


class Transport(Protocol):
    """Anything able to run already-validated commands against a device.

    Kept as a Protocol so the test-suite (and ``--demo`` mode) can substitute a
    fake without ever touching real hardware.
    """

    def run(self, commands: Sequence[str], timeout: float) -> CommandResult:  # pragma: no cover
        ...


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def find_client(explicit: str | None = None) -> Path:
    """Locate the Iceman ``pm3`` client binary.

    Search order: explicit argument, ``RFIDEYE_PM3_BIN``, ``PATH``, then a few
    conventional install locations.

    Raises:
        ClientNotFoundError: If no executable client is found.
    """
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    env_value = os.environ.get(ENV_PM3_BIN)
    if env_value:
        candidates.append(env_value)

    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return path
        raise ClientNotFoundError(f"{candidate!r} is not an executable pm3 client")

    for name in ("pm3", "proxmark3"):
        found = shutil.which(name)
        if found:
            return Path(found)

    for fallback in (
        Path.home() / "proxmark3" / "pm3",
        Path("/usr/local/bin/pm3"),
        Path("/opt/proxmark3/pm3"),
    ):
        if fallback.is_file() and os.access(fallback, os.X_OK):
            return fallback

    raise ClientNotFoundError(
        "The Iceman pm3 client was not found. Install it from "
        "https://github.com/RfidResearchGroup/proxmark3 and make sure 'pm3' is "
        f"on your PATH, or set {ENV_PM3_BIN}=/path/to/pm3"
    )


def discover_devices() -> list[DeviceInfo]:
    """Return every serial port that plausibly hosts a Proxmark3.

    Ports are returned best-match first: USB VID/PID matches, then product
    string matches, then bare platform globs.
    """
    found: list[DeviceInfo] = []
    seen: set[str] = set()

    try:
        from serial.tools import list_ports  # noqa: PLC0415 - optional at import time
    except ImportError:  # pragma: no cover - pyserial is a hard dependency
        LOGGER.warning("pyserial is not installed; falling back to port globbing")
        list_ports = None  # type: ignore[assignment]

    if list_ports is not None:
        for port in list_ports.comports():
            label = " ".join(
                str(value)
                for value in (port.description, port.manufacturer, port.product)
                if value
            ).lower()

            for vid, pid, name in KNOWN_USB_IDS:
                if port.vid == vid and port.pid == pid:
                    found.append(
                        DeviceInfo(port.device, name, port.vid, port.pid,
                                   port.serial_number, match="usb-id")
                    )
                    seen.add(port.device)
                    break
            else:
                if any(hint in label for hint in DESCRIPTION_HINTS):
                    found.append(
                        DeviceInfo(port.device, port.description or "Proxmark3?", port.vid,
                                   port.pid, port.serial_number, match="description")
                    )
                    seen.add(port.device)

    for pattern in PORT_GLOBS.get(os.name, ()):
        for path in sorted(glob.glob(pattern)):
            if path not in seen:
                found.append(DeviceInfo(path, "serial port (unverified)", match="glob"))
                seen.add(path)

    LOGGER.debug("discovered %d candidate port(s): %s", len(found), [d.port for d in found])
    return found


# --------------------------------------------------------------------------- #
# Transports
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Pm3Transport:
    """Runs commands by invoking the official client once per batch.

    Args:
        client: Path to the ``pm3`` executable.
        port: Serial port of the device.
    """

    client: Path
    port: str

    def build_argv(self, commands: Sequence[str]) -> list[str]:
        """Build the argument vector.  Split out so tests can assert on it."""
        argv = [str(self.client), "-p", self.port]
        for command in commands:
            argv += ["-c", command]
        return argv

    def run(self, commands: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
        argv = self.build_argv(commands)
        joined = " ; ".join(commands)
        LOGGER.info("exec: %s", joined)
        started = time.monotonic()
        try:
            # shell=False is essential: the command list is passed as argv, so
            # even a hypothetical guard bypass could not reach a shell.
            proc = subprocess.run(  # noqa: S603 - argv is fully validated upstream
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise CommandFailedError(f"'{joined}' timed out after {timeout:.0f}s") from exc
        except OSError as exc:
            raise CommandFailedError(f"could not launch the pm3 client: {exc}") from exc

        duration = time.monotonic() - started
        result = CommandResult(joined, proc.stdout or "", proc.stderr or "",
                               proc.returncode, duration)
        LOGGER.debug("exit=%d in %.2fs", result.returncode, duration)
        return result


@dataclass(slots=True)
class DemoTransport:
    """Offline transport that replays canned client output.

    Used by the test-suite and by ``rfideye --demo`` so the interface can be
    explored (and screenshotted) without hardware.  It is read-only by
    construction: it has no device at all.
    """

    responses: dict[str, str] = field(default_factory=dict)

    def run(self, commands: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
        chunks = [self.responses.get(command, f"[!] no demo data for '{command}'")
                  for command in commands]
        return CommandResult(" ; ".join(commands), "\n".join(chunks), "", 0, 0.0)


# --------------------------------------------------------------------------- #
# High-level device object
# --------------------------------------------------------------------------- #
_VERSION_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "client": re.compile(r"^\s*(?:\[[^\]]*\]\s*)?Client\s*[.:]*\s*(.+)$", re.MULTILINE),
    "bootrom": re.compile(r"^\s*(?:\[[^\]]*\]\s*)?bootrom\s*[.:]*\s*(.+)$",
                          re.MULTILINE | re.IGNORECASE),
    "os_image": re.compile(r"^\s*(?:\[[^\]]*\]\s*)?os\s*[.:]+\s*(.+)$",
                           re.MULTILINE | re.IGNORECASE),
    "hardware": re.compile(r"(?:hardware|device).*?:\s*(.+)$", re.MULTILINE | re.IGNORECASE),
}


def parse_version(output: str) -> FirmwareInfo:
    """Parse ``hw version`` output into a :class:`FirmwareInfo`.

    The client's exact layout changes between releases, so every field is
    optional and falls back to ``unknown`` rather than raising.
    """
    values: dict[str, str] = {}
    for field_name, pattern in _VERSION_PATTERNS.items():
        match = pattern.search(output)
        if match:
            values[field_name] = match.group(1).strip()

    lowered = output.lower()
    is_iceman = any(marker in lowered for marker in ("iceman", "rrg", "rfidresearchgroup"))

    return FirmwareInfo(
        client=values.get("client", "unknown"),
        bootrom=values.get("bootrom", "unknown"),
        os_image=values.get("os_image", "unknown"),
        hardware=values.get("hardware", "unknown"),
        is_iceman=is_iceman,
        raw=output,
    )


class Proxmark3:
    """A connected (or connectable) Proxmark3.

    Every public execution method funnels through :meth:`execute`, which calls
    the read-only guard first.  There is deliberately no ``execute_raw``.
    """

    def __init__(
        self,
        transport: Transport | None = None,
        info: DeviceInfo | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._transport = transport
        self._info = info
        self._firmware: FirmwareInfo | None = None
        self.timeout = timeout

    # -- properties -------------------------------------------------------- #
    @property
    def connected(self) -> bool:
        return self._transport is not None

    @property
    def info(self) -> DeviceInfo | None:
        return self._info

    @property
    def firmware(self) -> FirmwareInfo | None:
        return self._firmware

    # -- lifecycle --------------------------------------------------------- #
    @classmethod
    def autodetect(
        cls,
        *,
        client: str | None = None,
        port: str | None = None,
        retries: int = 3,
        retry_delay: float = 2.0,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> Proxmark3:
        """Find the client and the device, then return a connected instance.

        Args:
            client: Explicit path to ``pm3`` (otherwise autodetected).
            port: Explicit serial port (otherwise autodetected).
            retries: How many discovery attempts before giving up.
            retry_delay: Seconds to wait between attempts.
            timeout: Per-command timeout.

        Raises:
            ClientNotFoundError: The Iceman client is missing.
            DeviceNotFoundError: No candidate port after all retries.
        """
        client_path = find_client(client)

        last_error: Exception | None = None
        for attempt in range(1, retries + 1):
            if port:
                chosen = DeviceInfo(port, "user-specified port", match="manual")
            else:
                candidates = discover_devices()
                chosen = candidates[0] if candidates else None
            if chosen is not None:
                LOGGER.info("using %s (%s, match=%s)", chosen.port, chosen.description, chosen.match)
                device = cls(Pm3Transport(client_path, chosen.port), chosen, timeout=timeout)
                device.refresh_firmware()
                return device

            last_error = DeviceNotFoundError("no Proxmark3 found on any serial port")
            LOGGER.warning("attempt %d/%d: no device found", attempt, retries)
            if attempt < retries:
                time.sleep(retry_delay)

        raise DeviceNotFoundError(str(last_error))

    def reconnect(self, *, retries: int = 3, retry_delay: float = 2.0) -> bool:
        """Re-run discovery after a disconnection.  Returns ``True`` on success."""
        if not isinstance(self._transport, Pm3Transport):
            return False
        client = self._transport.client
        for attempt in range(1, retries + 1):
            candidates = discover_devices()
            if candidates:
                self._info = candidates[0]
                self._transport = Pm3Transport(client, self._info.port)
                LOGGER.info("reconnected on %s", self._info.port)
                self.refresh_firmware()
                return True
            LOGGER.warning("reconnect attempt %d/%d failed", attempt, retries)
            time.sleep(retry_delay)
        return False

    # -- execution --------------------------------------------------------- #
    def execute(self, command: str, *, timeout: float | None = None) -> CommandResult:
        """Validate and run a single command.

        Args:
            command: A Proxmark3 client command.
            timeout: Override the per-command timeout.

        Raises:
            GuardViolation: The command is not read-only (nothing is sent).
            DeviceError: There is no transport, or the client failed.
        """
        validated = read_only_guard.validate(command)
        return self._dispatch([validated], timeout)

    def execute_batch(
        self, commands: Sequence[str], *, timeout: float | None = None
    ) -> CommandResult:
        """Validate and run several commands in a single client invocation.

        Launching ``pm3`` costs about a second, so batching matters a lot for
        the continuous-scan loop.
        """
        validated = [read_only_guard.validate(command) for command in commands]
        return self._dispatch(validated, timeout)

    def _dispatch(self, commands: Sequence[str], timeout: float | None) -> CommandResult:
        if self._transport is None:
            raise DeviceError("no device connected")
        try:
            return self._transport.run(commands, timeout or self.timeout)
        except CommandFailedError:
            # A vanished device usually shows up as a launch/timeout failure.
            LOGGER.warning("command failed; attempting one reconnect")
            if self.reconnect(retries=1, retry_delay=1.0) and self._transport is not None:
                return self._transport.run(commands, timeout or self.timeout)
            raise

    def refresh_firmware(self) -> FirmwareInfo:
        """Query and cache ``hw version``."""
        result = self.execute("hw version")
        self._firmware = parse_version(result.stdout)
        if not self._firmware.is_iceman:
            LOGGER.warning(
                "connected firmware does not identify as the Iceman fork; "
                "output parsing may be unreliable"
            )
        return self._firmware

    def ping(self) -> bool:
        """Cheap liveness probe used by the continuous-scan loop."""
        try:
            return self.execute("hw status", timeout=10).ok
        except DeviceError:
            return False


TROUBLESHOOTING: Final[str] = """\
No Proxmark3 detected. Checklist:

  1. Cable      - use a data cable, not a charge-only one; try another port.
  2. Permissions- your user must be in the 'dialout' group:
                    sudo usermod -aG dialout $USER   (then log out and back in)
                  or install the udev rules shipped with the Iceman repo.
  3. Client     - 'pm3' must be on your PATH (or set RFIDEYE_PM3_BIN).
  4. Firmware   - flash the Iceman firmware:
                    https://github.com/RfidResearchGroup/proxmark3
  5. Port busy  - close any other pm3 client or serial monitor.
  6. Bootloader - a solid red LED usually means the device sits in bootrom;
                  re-flash the full image.
"""
