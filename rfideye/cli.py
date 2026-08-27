"""Command line and interactive menu.

Two ways in, one code path:

* ``rfideye scan`` / ``dump`` / ``watch`` / ``history`` / ``report`` / ``doctor``
  for scripting and one-shot use.
* ``rfideye`` with no arguments for the guided, colour-coded menu.

Both build the same :class:`AppState` and call the same helpers, so behaviour
cannot diverge between the two front-ends.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import typer
from rich.prompt import Prompt
from rich.text import Text

from rfideye import APP_NAME, __version__, read_only_guard
from rfideye.config import Paths, setup_logging
from rfideye.demo import DEMO_RESPONSES
from rfideye.device import (
    DEFAULT_TIMEOUT,
    TROUBLESHOOTING,
    ClientNotFoundError,
    DemoTransport,
    DeviceError,
    DeviceInfo,
    DeviceNotFoundError,
    Proxmark3,
    discover_devices,
    find_client,
)
from rfideye.dump import MemoryDump, dump_for, load_keys
from rfideye.identify import Band, Identifier, TagIdentity
from rfideye.report import ReportMeta, write_report
from rfideye.storage import History, export_csv, export_json, new_session_id
from rfideye.transit import TransitProfile
from rfideye.transit import profile as transit_profile
from rfideye.ui import banner, theme
from rfideye.ui.theme import Status, confidence_style, data_table, kv_table, status_panel

LOGGER: Final[logging.Logger] = logging.getLogger("rfideye.cli")

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help=f"{APP_NAME} - read-only RFID/NFC identification console for Proxmark3.",
)


@dataclass(slots=True)
class AppState:
    """Everything a command needs, assembled once by the root callback."""

    paths: Paths
    session_id: str
    port: str | None = None
    client: str | None = None
    demo: bool = False
    timeout: float = DEFAULT_TIMEOUT
    device: Proxmark3 | None = None
    history: History | None = None

    def open_history(self) -> History:
        """Open the SQLite history lazily (commands that never scan skip it)."""
        if self.history is None:
            self.history = History(self.paths.database, session_id=self.session_id)
        return self.history


def _state(ctx: typer.Context) -> AppState:
    """Fetch the AppState attached by the root callback."""
    state = ctx.obj
    if not isinstance(state, AppState):  # pragma: no cover - defensive
        raise RuntimeError("application state was not initialised")
    return state


# --------------------------------------------------------------------------- #
# Device helpers
# --------------------------------------------------------------------------- #
def connect(state: AppState, *, quiet: bool = False) -> Proxmark3 | None:
    """Connect (once) and return the device, or None after printing why not."""
    if state.device is not None:
        return state.device

    console = theme.console
    if state.demo:
        info = DeviceInfo("demo://offline", "Demo transport (no hardware)", match="demo")
        state.device = Proxmark3(DemoTransport(dict(DEMO_RESPONSES)), info)
        state.device.refresh_firmware()
        if not quiet:
            console.print(status_panel(Status.BUSY,
                                       "Running in DEMO mode - no device is being contacted.",
                                       title="Demo"))
        return state.device

    try:
        with console.status("[busy]Looking for a Proxmark3...", spinner="dots"):
            state.device = Proxmark3.autodetect(
                client=state.client, port=state.port, timeout=state.timeout
            )
    except ClientNotFoundError as exc:
        console.print(status_panel(Status.ERROR, str(exc), title="pm3 client not found"))
        return None
    except DeviceNotFoundError:
        console.print(status_panel(Status.ERROR, TROUBLESHOOTING, title="No device"))
        return None
    except DeviceError as exc:
        console.print(status_panel(Status.ERROR, str(exc), title="Device error"))
        return None

    if not quiet:
        _print_device(state.device)
    return state.device


def _print_device(device: Proxmark3) -> None:
    """Show port, firmware and the Iceman-fork check."""
    console = theme.console
    info, firmware = device.info, device.firmware
    table = kv_table()
    table.add_row("Port", info.port if info else "unknown")
    table.add_row("Detected via", info.match if info else "unknown")
    table.add_row("USB ID", info.usb_id if info else "unknown")
    if firmware:
        table.add_row("Client", firmware.client)
        table.add_row("Firmware", firmware.os_image)
        table.add_row("Hardware", firmware.hardware)
    console.print(theme.status_text(Status.OK, "Proxmark3 connected"))
    console.print(table)

    if firmware and not firmware.is_iceman:
        console.print(
            status_panel(
                Status.ERROR,
                "This firmware does not identify itself as the Iceman fork "
                "(RfidResearchGroup/proxmark3). RFIDeye parses Iceman output, so "
                "identification may be incomplete or wrong.",
                title="Unsupported firmware",
            )
        )


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #
def render_identity(identity: TagIdentity, transit: TransitProfile | None = None) -> None:
    """Print a full, colour-coded description of one tag."""
    console = theme.console

    if not identity.found:
        console.print(status_panel(Status.ERROR, "\n".join(identity.notes) or "No tag detected.",
                                   title="Nothing on the antenna"))
        return

    console.print(theme.status_text(Status.OK, f"{identity.band.value} tag identified"))

    table = kv_table()
    table.add_row("Product", Text(identity.product, style=confidence_style(identity.confidence)))
    table.add_row("Technology", identity.technology)
    table.add_row("Confidence", Text(f"{identity.confidence:.0%}",
                                     style=confidence_style(identity.confidence)))
    for label, value in (("UID", identity.uid), ("ATQA", identity.atqa),
                         ("SAK", identity.sak), ("ATS", identity.ats)):
        if value:
            table.add_row(label, value)
    for key, value in identity.extra.items():
        table.add_row(key.replace("_", " ").title(), str(value))
    console.print(table)

    for note in identity.notes:
        console.print(Text(f"  - {note}", style="muted"))

    if transit and transit.is_transit_candidate:
        console.print()
        console.print(Text("Public-transport profile (heuristic)", style="title"))
        transit_table = kv_table()
        transit_table.add_row("Scheme", Text(transit.scheme,
                                             style=confidence_style(transit.confidence)))
        transit_table.add_row("Confidence", f"{transit.confidence:.0%}")
        transit_table.add_row("Readable without keys", "\n".join(transit.public_fields) or "-")
        transit_table.add_row("Not read (needs issuer keys)",
                              "\n".join(transit.locked_behind) or "-")
        console.print(transit_table)
        for note in transit.notes:
            console.print(Text(f"  - {note}", style="muted"))


def scan_once(state: AppState, device: Proxmark3, *, band: Band | None = None,
              record: bool = True) -> tuple[TagIdentity, TransitProfile] | None:
    """Identify one tag, print it, persist it.  Returns None on device error."""
    console = theme.console
    try:
        with console.status("[busy]Reading the antenna...", spinner="dots"):
            identity = Identifier(device).identify(band=band)
    except read_only_guard.GuardViolation as exc:  # pragma: no cover - defensive
        console.print(status_panel(Status.ERROR, f"Blocked by the read-only guard: {exc.reason}",
                                   title="Command refused"))
        return None
    except DeviceError as exc:
        console.print(status_panel(Status.ERROR, str(exc), title="Device error"))
        return None

    tprofile = transit_profile(identity)
    render_identity(identity, tprofile)

    if record and identity.found:
        history = state.open_history()
        history.record(identity, tprofile)
        if history.seen_before(identity.uid):
            console.print(Text("  - This UID is already in your history.", style="warn"))
    return identity, tprofile


# --------------------------------------------------------------------------- #
# Root callback
# --------------------------------------------------------------------------- #
@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    port: str | None = typer.Option(None, "--port", "-p",
                                       help="Serial port (default: autodetect)."),
    client: str | None = typer.Option(None, "--client",
                                         help="Path to the Iceman pm3 binary."),
    data_dir: Path | None = typer.Option(None, "--data-dir",
                                            help="Override the data directory."),
    log_level: str = typer.Option("info", "--log-level",
                                  help="debug | info | warning | error."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colours."),
    demo: bool = typer.Option(False, "--demo",
                              help="Offline demo mode: no hardware is contacted."),
    timeout: float = typer.Option(DEFAULT_TIMEOUT, "--timeout",
                                  help="Per-command timeout in seconds."),
    version: bool = typer.Option(False, "--version", help="Print the version and exit."),
) -> None:
    """Set up shared state; run the interactive menu when no subcommand is given."""
    if version:
        typer.echo(f"{APP_NAME} {__version__}")
        raise typer.Exit()

    if no_color:
        theme.set_console(theme.build_console(no_color=True))

    paths = Paths(data_dir.expanduser()) if data_dir else Paths.default()
    paths.ensure()
    setup_logging(paths, log_level, console=log_level == "debug")

    state = AppState(paths=paths, session_id=new_session_id(), port=port,
                     client=client, demo=demo, timeout=timeout)
    ctx.obj = state

    if ctx.invoked_subcommand is None:
        interactive_menu(state)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    ctx: typer.Context,
    band: str | None = typer.Option(None, "--band", help="Restrict to 'lf' or 'hf'."),
    json_out: Path | None = typer.Option(None, "--json", help="Also write JSON here."),
    csv_out: Path | None = typer.Option(None, "--csv", help="Also write CSV here."),
) -> None:
    """Identify the tag currently on the antenna."""
    state = _state(ctx)
    device = connect(state)
    if device is None:
        raise typer.Exit(code=2)

    outcome = scan_once(state, device, band=_parse_band(band))
    if outcome is None:
        raise typer.Exit(code=1)

    identity, _ = outcome
    if json_out:
        theme.console.print(theme.status_text(
            Status.OK, f"JSON written to {export_json([identity], json_out, include_raw=True)}"))
    if csv_out:
        theme.console.print(theme.status_text(
            Status.OK, f"CSV written to {export_csv([identity], csv_out)}"))


@app.command()
def watch(
    ctx: typer.Context,
    interval: float = typer.Option(1.5, "--interval", help="Seconds between polls."),
    band: str | None = typer.Option(None, "--band", help="Restrict to 'lf' or 'hf'."),
) -> None:
    """Continuous scan: process every tag presented to the reader (Ctrl+C to stop)."""
    state = _state(ctx)
    console = theme.console
    device = connect(state)
    if device is None:
        raise typer.Exit(code=2)

    console.print(status_panel(Status.BUSY,
                               "Continuous scan running. Present a tag. Press Ctrl+C to stop.",
                               title="Watch mode"))
    last_uid: str | None = None
    seen = 0
    try:
        while True:
            try:
                identity = Identifier(device).identify(band=_parse_band(band))
            except DeviceError as exc:
                console.print(theme.status_text(Status.ERROR, f"{exc} - retrying"))
                time.sleep(interval * 2)
                continue

            if identity.found and identity.uid != last_uid:
                last_uid = identity.uid
                seen += 1
                console.rule(style="rule")
                tprofile = transit_profile(identity)
                render_identity(identity, tprofile)
                state.open_history().record(identity, tprofile)
            elif not identity.found:
                last_uid = None
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print()
        console.print(theme.status_text(Status.OK, f"Watch stopped after {seen} tag(s)."))


@app.command("dump")
def dump_cmd(
    ctx: typer.Context,
    keys: str | None = typer.Option(
        None, "--keys",
        help="MIFARE keys you already hold: a 12-hex key, a key file, or 'factory'.",
    ),
    json_out: Path | None = typer.Option(None, "--json", help="JSON output path."),
    csv_out: Path | None = typer.Option(None, "--csv", help="CSV output path."),
    yes: bool = typer.Option(False, "--yes", help="Skip the ownership confirmation."),
) -> None:
    """Read the readable memory of a tag and export it (tag -> file only)."""
    state = _state(ctx)
    console = theme.console
    device = connect(state)
    if device is None:
        raise typer.Exit(code=2)

    if keys and not yes and not _confirm_ownership():
        raise typer.Exit(code=3)

    try:
        key_list = load_keys(keys)
    except ValueError as exc:
        console.print(status_panel(Status.ERROR, str(exc), title="Bad key input"))
        raise typer.Exit(code=2) from exc

    outcome = scan_once(state, device)
    if outcome is None:
        raise typer.Exit(code=1)
    identity, _ = outcome
    if not identity.found:
        raise typer.Exit(code=1)

    with console.status("[busy]Reading tag memory...", spinner="dots"):
        memory = dump_for(device, identity, keys=key_list)

    table = data_table("Block", "Data", title=f"{memory.technology} memory")
    for block in memory.blocks:
        table.add_row(str(block.index), block.data)
    if memory.blocks:
        console.print(table)
        console.print(theme.status_text(Status.OK, f"{memory.bytes_read} bytes read"))
    for target, reason in memory.failures.items():
        console.print(theme.status_text(Status.ERROR, f"{target}: {reason}"))

    identity.extra["dump_blocks"] = str(len(memory.blocks))
    identity.extra["dump_key_source"] = memory.key_source

    destination = json_out or state.paths.dump_dir
    path = export_json([identity], destination, include_raw=True)
    _append_memory(path, memory)
    console.print(theme.status_text(Status.OK, f"JSON written to {path}"))
    if csv_out:
        console.print(theme.status_text(Status.OK,
                                        f"CSV written to {export_csv([identity], csv_out)}"))


def _append_memory(path: Path, memory: MemoryDump) -> None:
    """Merge the memory dump into the JSON file written by ``export_json``."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["memory"] = memory.to_dict()
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


@app.command("history")
def history_cmd(
    ctx: typer.Context,
    limit: int = typer.Option(20, "--limit", "-n", help="How many rows to show."),
    uid: str | None = typer.Option(None, "--uid", help="Filter by UID."),
    json_out: Path | None = typer.Option(None, "--json", help="Export the rows as JSON."),
    csv_out: Path | None = typer.Option(None, "--csv", help="Export the rows as CSV."),
) -> None:
    """Show (and optionally export) previously scanned tags."""
    state = _state(ctx)
    console = theme.console
    history = state.open_history()
    records = history.by_uid(uid) if uid else history.recent(limit)

    if not records:
        console.print(theme.status_text(Status.BUSY, "No scans recorded yet."))
        return

    table = data_table("#", "Timestamp (UTC)", "Band", "Product", "UID", "Conf.",
                       title=f"Scan history ({history.count()} total)")
    for record in records:
        table.add_row(
            str(record.id), record.timestamp, record.band, record.product,
            record.uid or "-",
            Text(f"{record.confidence:.0%}", style=confidence_style(record.confidence)),
        )
    console.print(table)

    if json_out:
        console.print(theme.status_text(Status.OK,
                                        f"JSON written to {export_json(records, json_out)}"))
    if csv_out:
        console.print(theme.status_text(Status.OK,
                                        f"CSV written to {export_csv(records, csv_out)}"))


@app.command("report")
def report_cmd(
    ctx: typer.Context,
    fmt: str = typer.Option("md", "--format", "-f", help="md | html."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output path."),
    session: str | None = typer.Option(None, "--session",
                                          help="Session ID (default: the current one)."),
    note: str = typer.Option("", "--note", help="Operator note for the header."),
    last: int = typer.Option(0, "--last",
                             help="Report the last N scans instead of a session."),
) -> None:
    """Generate a Markdown or HTML report of a scanning session."""
    state = _state(ctx)
    console = theme.console
    history = state.open_history()
    records = history.recent(last)[::-1] if last else history.for_session(session)

    if not records:
        console.print(theme.status_text(Status.ERROR, "Nothing to report for that selection."))
        raise typer.Exit(code=1)

    device = state.device
    meta = ReportMeta(
        session_id=session or state.session_id,
        device_port=device.info.port if device and device.info else "n/a",
        device_description=device.info.description if device and device.info else "n/a",
        firmware=device.firmware.summary if device and device.firmware else "n/a",
        operator_note=note,
    )
    try:
        path = write_report(records, meta, output or state.paths.report_dir, fmt=fmt)
    except ValueError as exc:
        console.print(status_panel(Status.ERROR, str(exc), title="Bad format"))
        raise typer.Exit(code=2) from exc
    console.print(theme.status_text(Status.OK, f"Report written to {path}"))


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Diagnose the environment: client, serial ports, permissions, firmware."""
    state = _state(ctx)
    console = theme.console
    console.print(banner.render_banner(console.width))

    table = kv_table("Environment")
    try:
        client_path = find_client(state.client)
        table.add_row("pm3 client", Text(str(client_path), style="ok"))
    except ClientNotFoundError as exc:
        table.add_row("pm3 client", Text(str(exc), style="err"))

    table.add_row("Data directory", str(state.paths.data_dir))
    table.add_row("Log file", str(state.paths.log_file))
    table.add_row("Database", str(state.paths.database))
    console.print(table)

    ports = discover_devices()
    if ports:
        port_table = data_table("Port", "Description", "USB ID", "Matched by",
                                title="Candidate serial ports")
        for info in ports:
            port_table.add_row(info.port, info.description, info.usb_id, info.match)
        console.print(port_table)
    else:
        console.print(status_panel(Status.ERROR, TROUBLESHOOTING, title="No serial ports"))

    device = connect(state, quiet=True)
    if device is not None:
        _print_device(device)
        try:
            tune = device.execute("hw tune", timeout=40)
            console.print(status_panel(Status.OK, tune.stdout.strip() or "no output",
                                       title="Antenna tuning"))
        except DeviceError as exc:
            console.print(theme.status_text(Status.ERROR, f"hw tune failed: {exc}"))


@app.command("commands")
def commands_cmd() -> None:
    """List every command RFIDeye is allowed to send (the full allow-list)."""
    console = theme.console
    table = data_table("Command", "What it does", title="Read-only allow-list")
    for rule in read_only_guard.allowed_commands():
        table.add_row(Text(rule.name, style="ok"), rule.summary)
    console.print(table)
    console.print(
        status_panel(
            Status.ERROR,
            "Anything not listed above is refused before it reaches the device: "
            "write, clone, restore, simulate, emulate, sniff and every key-recovery "
            "attack are blocked and logged.",
            title="Everything else is blocked",
        )
    )


# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #
_MENU: Final[tuple[tuple[str, str], ...]] = (
    ("1", "Connect / show device status"),
    ("2", "Identify the tag on the antenna"),
    ("3", "Continuous scan (watch mode)"),
    ("4", "Read memory and export (JSON/CSV)"),
    ("5", "Show scan history"),
    ("6", "Generate a session report"),
    ("7", "Show the read-only allow-list"),
    ("8", "Environment doctor"),
    ("0", "Quit"),
)


def _parse_band(value: str | None) -> Band | None:
    if not value:
        return None
    normalised = value.strip().lower()
    if normalised == "lf":
        return Band.LF
    if normalised == "hf":
        return Band.HF
    raise typer.BadParameter("--band accepts 'lf' or 'hf'")


def _confirm_ownership() -> bool:
    """Ask the operator to confirm they may audit this card."""
    console = theme.console
    console.print(
        status_panel(
            Status.BUSY,
            "Supplying keys means you already hold them. Confirm that this card is "
            "yours, or that you have written authorisation from its issuer.",
            title="Authorisation check",
        )
    )
    answer = Prompt.ask(Text("Do you have authorisation for this card?", style="warn"),
                        choices=["y", "n"], default="n")
    if answer != "y":
        console.print(theme.status_text(Status.ERROR, "Aborted."))
        return False
    return True


def interactive_menu(state: AppState) -> None:
    """The guided TUI loop."""
    console = theme.console
    console.print(banner.render_banner(console.width))
    console.print(banner.render_legal_notice())

    while True:
        console.print()
        table = data_table("Key", "Action", title="Main menu")
        for key, label in _MENU:
            table.add_row(Text(key, style="menu.key"), Text(label, style="menu.text"))
        console.print(table)

        choice = Prompt.ask(Text("Select", style="accent"),
                            choices=[key for key, _ in _MENU], default="2")
        console.print()

        if choice == "0":
            console.print(theme.status_text(Status.OK, "Bye."))
            if state.history:
                state.history.close()
            return
        _dispatch_menu(state, choice)


def _dispatch_menu(state: AppState, choice: str) -> None:
    """Run one menu action.  Errors are reported, never fatal."""
    console = theme.console
    try:
        if choice == "1":
            device = connect(state)
            if device is None:
                console.print(theme.status_text(Status.ERROR, "Not connected."))
        elif choice == "2":
            device = connect(state)
            if device:
                scan_once(state, device)
        elif choice == "3":
            device = connect(state)
            if device:
                _menu_watch(state, device)
        elif choice == "4":
            _menu_dump(state)
        elif choice == "5":
            _menu_history(state)
        elif choice == "6":
            _menu_report(state)
        elif choice == "7":
            commands_cmd()
        elif choice == "8":
            doctor_state(state)
    except KeyboardInterrupt:
        console.print()
        console.print(theme.status_text(Status.BUSY, "Cancelled."))
    except DeviceError as exc:
        console.print(status_panel(Status.ERROR, str(exc), title="Device error"))


def _menu_watch(state: AppState, device: Proxmark3) -> None:
    console = theme.console
    console.print(status_panel(Status.BUSY, "Present tags to the reader. Ctrl+C to stop.",
                               title="Watch mode"))
    last_uid: str | None = None
    try:
        while True:
            identity = Identifier(device).identify()
            if identity.found and identity.uid != last_uid:
                last_uid = identity.uid
                console.rule(style="rule")
                tprofile = transit_profile(identity)
                render_identity(identity, tprofile)
                state.open_history().record(identity, tprofile)
            elif not identity.found:
                last_uid = None
            time.sleep(1.5)
    except KeyboardInterrupt:
        console.print()
        console.print(theme.status_text(Status.OK, "Watch stopped."))


def _menu_dump(state: AppState) -> None:
    console = theme.console
    device = connect(state)
    if device is None:
        return

    keys_input = Prompt.ask(
        Text("MIFARE keys (12-hex key, key file, 'factory', or blank for none)", style="warn"),
        default="",
    ).strip()
    if keys_input and not _confirm_ownership():
        return
    try:
        key_list = load_keys(keys_input or None)
    except ValueError as exc:
        console.print(status_panel(Status.ERROR, str(exc), title="Bad key input"))
        return

    outcome = scan_once(state, device)
    if outcome is None or not outcome[0].found:
        return
    identity = outcome[0]

    with console.status("[busy]Reading tag memory...", spinner="dots"):
        memory = dump_for(device, identity, keys=key_list)

    if memory.blocks:
        table = data_table("Block", "Data", title=f"{memory.technology} memory")
        for block in memory.blocks:
            table.add_row(str(block.index), block.data)
        console.print(table)
    for target, reason in memory.failures.items():
        console.print(theme.status_text(Status.ERROR, f"{target}: {reason}"))

    path = export_json([identity], state.paths.dump_dir, include_raw=True)
    _append_memory(path, memory)
    csv_path = export_csv([identity], state.paths.dump_dir)
    console.print(theme.status_text(Status.OK, f"JSON: {path}"))
    console.print(theme.status_text(Status.OK, f"CSV : {csv_path}"))


def _menu_history(state: AppState) -> None:
    console = theme.console
    history = state.open_history()
    records = history.recent(20)
    if not records:
        console.print(theme.status_text(Status.BUSY, "No scans recorded yet."))
        return
    table = data_table("#", "Timestamp (UTC)", "Band", "Product", "UID", "Conf.",
                       title=f"Last {len(records)} scans of {history.count()}")
    for record in records:
        table.add_row(str(record.id), record.timestamp, record.band, record.product,
                      record.uid or "-",
                      Text(f"{record.confidence:.0%}",
                           style=confidence_style(record.confidence)))
    console.print(table)


def _menu_report(state: AppState) -> None:
    console = theme.console
    history = state.open_history()
    records = history.for_session()
    if not records:
        console.print(theme.status_text(Status.ERROR,
                                        "This session has no scans yet - scan something first."))
        return
    fmt = Prompt.ask(Text("Format", style="accent"), choices=["md", "html"], default="md")
    note = Prompt.ask(Text("Operator note (optional)", style="warn"), default="")
    device = state.device
    meta = ReportMeta(
        session_id=state.session_id,
        device_port=device.info.port if device and device.info else "n/a",
        device_description=device.info.description if device and device.info else "n/a",
        firmware=device.firmware.summary if device and device.firmware else "n/a",
        operator_note=note,
    )
    path = write_report(records, meta, state.paths.report_dir, fmt=fmt)
    console.print(theme.status_text(Status.OK, f"Report written to {path}"))


def doctor_state(state: AppState) -> None:
    """Menu-friendly wrapper around the ``doctor`` command."""
    console = theme.console
    table = kv_table("Environment")
    try:
        table.add_row("pm3 client", Text(str(find_client(state.client)), style="ok"))
    except ClientNotFoundError as exc:
        table.add_row("pm3 client", Text(str(exc), style="err"))
    table.add_row("Data directory", str(state.paths.data_dir))
    table.add_row("Log file", str(state.paths.log_file))
    console.print(table)

    ports = discover_devices()
    if ports:
        port_table = data_table("Port", "Description", "USB ID", "Matched by",
                                title="Candidate serial ports")
        for info in ports:
            port_table.add_row(info.port, info.description, info.usb_id, info.match)
        console.print(port_table)
    else:
        console.print(status_panel(Status.ERROR, TROUBLESHOOTING, title="No serial ports"))


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
