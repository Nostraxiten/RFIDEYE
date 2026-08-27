# RFIDeye

**A strictly read-only RFID/NFC identification console for the Proxmark3 (Iceman firmware).**
It identifies, describes and exports what a tag says about itself — and it physically cannot write, clone, emulate or simulate one.

<img width="648" height="363" alt="image" src="https://github.com/user-attachments/assets/d6890139-573c-4d14-9b82-17dd0df22b69" />

---

##  Legal notice and intended use

RFIDeye is an **auditing and diagnostic** tool, published for education and for defensive security work.

* Use it **only** on cards, tags and systems that **you own**, or for which you hold **explicit written authorisation** from the owner or system administrator.
* Reading, cloning or manipulating third-party credentials — transport cards, building badges, hotel keys, payment media — without authorisation is a criminal offence in most jurisdictions.
* RFIDeye deliberately provides **no** write, clone, emulation or key-recovery capability. It will not help you forge or duplicate a credential, and that is by design, not by omission.
* Key-recovery attacks (`nested`, `hardnested`, `darkside`, `autopwn`, `loclass`, …) and passive interception (`sniff`) are blocked at the command layer.
* You are solely responsible for complying with the law where you are. The authors accept **no liability** for misuse.

If you need to *write* to a tag, use the official Proxmark3 client directly. That is a deliberate boundary, not an inconvenience to be worked around.

---

## Features

**Device handling**

* Automatic Proxmark3 detection over USB (VID/PID → product string → port glob) — no `-p /dev/ttyACM0` needed.
* Retry with a clear troubleshooting checklist when nothing is found (udev rules, cable, firmware, busy port).
* Firmware/hardware readout with an explicit warning if the connected firmware is not the Iceman fork.
* Transparent reconnection if the device is unplugged mid-session.

**Identification**

* Automatic band detection: LF (125/134 kHz) and HF (13.56 MHz).
* Technology identification: ISO14443-A/B, ISO15693, MIFARE Classic (Mini/1K/2K/4K), Ultralight / Ultralight C / NTAG, MIFARE Plus, DESFire, iCLASS / PicoPass, Topaz, FeliCa, LEGIC, EM410x, EM4x05, HID Prox, Indala, AWID, ioProx, Paradox, Pyramid, Viking, Noralsy, Jablotron, KERI, NexWatch, Gallagher, Securakey, Visa2000, Motorola, FDX-B, Hitag and T55xx.
* UID / ATQA / SAK / ATS decoding, with an ATQA+SAK product table that separates a Classic 1K from a DESFire from an NTAG.
* **Public-transport module**: heuristically profiles Calypso, MIFARE DESFire, Ultralight-family, Classic-legacy and FeliCa ticketing, and states exactly which fields are readable without any key — and which are not, and why.

**Reading and export**

* Reads blocks/sectors that are public, or that open with **keys you supply yourself** (`--keys`). A documented factory-default key list is bundled for practising on your own or blank tags; nothing is ever brute-forced.
* Export to JSON and CSV. The data path is one-way: tag → file.
* Sectors that no supplied key opens are reported as unreadable. The tool stops there.

**Interface**

* Rich-powered TUI with a red / green / amber scheme: green = success, red = failure or blocked command, amber = in progress or heuristic.
* Interactive numbered menu, ASCII banner, spinners during device operations.
* Full CLI with subcommands for scripting.

**Persistence and reporting**

* SQLite scan history (timestamp, UID, type, confidence, outcome), with "you have seen this UID before" detection.
* Markdown or self-contained HTML session reports, including an explicit read-only statement.
* Continuous-scan (watch) mode: present tags one after another and see each result live.
* Levelled logging (`debug`/`info`/`warning`/`error`) to a rotating file, separate from the TUI output.

**Internal safety rails**

* Every command is validated by an allow-list guard before it reaches the device (`rfideye/read_only_guard.py`). Three layers: lexical (no shell metacharacters), deny-list (write/clone/emulate/attack vocabulary), allow-list (longest-prefix match + per-flag value regexes).
* Blocked attempts are logged at `WARNING` with the offending command.
* `rfideye commands` prints the complete allow-list — the tool's full capability surface, in one screen.
* The test suite asserts that write, clone, emulate, simulate, sniff and key-recovery commands are refused, and a dedicated CI job makes that a merge blocker.

---

## Requirements

| | |
| --- | --- |
| **Hardware** | A Proxmark3 (RDV4, Easy, RDV2 …) |
| **Firmware** | [Iceman / RfidResearchGroup fork](https://github.com/RfidResearchGroup/proxmark3) — RFIDeye parses its client output |
| **Client** | The `pm3` binary on your `PATH` (or `RFIDEYE_PM3_BIN=/path/to/pm3`) |
| **Python** | 3.11 or newer |
| **OS** | Linux (developed on Kali/Debian). macOS should work; Windows is untested for hardware access |
| **Permissions** | Your user must be able to open the serial port — `dialout` group or the Iceman udev rules |

---

## Installation

### 1. Install the Iceman firmware and client

Follow the official instructions — RFIDeye does not bundle or replace them:

```bash
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
make clean && make -j$(nproc)
sudo make install
```

Flash the firmware to the device (see the Iceman repo's compilation guide for your board), then confirm the client is reachable:

```bash
pm3 --version
```

### 2. Serial-port permissions (Linux)

```bash
sudo usermod -aG dialout $USER
```

Log out and back in. The Iceman repo also ships udev rules (`driver/77-pm3-usb-device-blacklist.rules`); install them if your distribution's ModemManager grabs the port.

### 3. Install RFIDeye

```bash
git clone https://github.com/Nostraxiten/RFIDEYE.git
cd RFIDEYE
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Or install it as an isolated tool:

```bash
pipx install .
```

### 4. Verify the setup

```bash
rfideye doctor
```

`doctor` reports the client path, the data directory, every candidate serial port and — if a device answers — its firmware and antenna tuning.

### 5. Try it without hardware

```bash
rfideye --demo scan
```

Demo mode replays canned client output so you can explore the interface with no Proxmark3 attached.

---

## Usage

### Interactive menu

```bash
rfideye
```

```
+- Main menu -----------------------------------------+
| Key | Action                                        |
|-----|-----------------------------------------------|
| 1   | Connect / show device status                  |
| 2   | Identify the tag on the antenna               |
| 3   | Continuous scan (watch mode)                  |
| 4   | Read memory and export (JSON/CSV)             |
| 5   | Show scan history                             |
| 6   | Generate a session report                     |
| 7   | Show the read-only allow-list                 |
| 8   | Environment doctor                            |
| 0   | Quit                                          |
+-----------------------------------------------------+
```

### Command line

```bash
# Identify whatever is on the antenna
rfideye scan

# Restrict the search to one band
rfideye scan --band lf

# Identify and export in one go
rfideye scan --json ~/audit/card.json --csv ~/audit/card.csv

# Continuous scan: process every tag presented to the reader
rfideye watch --interval 1.5

# Read memory using keys you already hold (asks for confirmation)
rfideye dump --keys ~/mykeys.dic --json ~/audit/dump.json

# Practise on your own blank tags with the bundled factory defaults
rfideye dump --keys factory

# Review and export the history
rfideye history --limit 50
rfideye history --uid 043B1A2C5E6080

# Produce a report of the current session
rfideye report --format html --note "Audit of my own access badge"

# Print every command the tool is allowed to send
rfideye commands

# Diagnose the environment
rfideye doctor
```

### Global options

| Option | Purpose |
| --- | --- |
| `-p, --port` | Force a serial port instead of autodetecting |
| `--client` | Path to the `pm3` binary |
| `--data-dir` | Override where history, logs, dumps and reports live |
| `--log-level` | `debug` / `info` / `warning` / `error` |
| `--no-color` | Plain output (also honours `NO_COLOR`) |
| `--demo` | Offline demo mode; no hardware is contacted |
| `--timeout` | Per-command timeout in seconds |

### Where your data goes

```
~/.local/share/rfideye/
├── rfideye.db          # scan history (SQLite)
├── logs/rfideye.log    # rotating log, 5 × 1 MiB
├── dumps/              # JSON / CSV exports
└── reports/            # Markdown / HTML session reports
```

Override with `--data-dir` or `RFIDEYE_DATA_DIR`.

### Example output

```
[+] HF tag identified
Product        NTAG 215 504bytes (NT2H1511G0DU)
Technology     ISO14443-A (type 2)
Confidence     90%
UID            04 3B 1A 2C 5E 60 80
ATQA           00 44
SAK            00
Manufacturer   NXP Semiconductors Germany

Public-transport profile (heuristic)
Scheme                        MIFARE Ultralight family
Confidence                    60%
Readable without keys         UID
                              OTP and lock bytes
                              user pages that are not password-locked
Not read (needs issuer keys)  Ultralight C 3DES key or EV1 PWD/PACK, when configured
  - Fare history, balance and personal data are protected by issuer keys.
    RFIDeye does not attempt to read them.
```

---

## Screenshots

Place your captures in `docs/screenshots/` and they will render here.

| | |
| --- | --- |
| Main menu | `docs/screenshots/menu.png` |
| Tag identification | `docs/screenshots/identify.png` |
| Watch mode | `docs/screenshots/watch.png` |
| HTML session report | `docs/screenshots/report.png` |

<!--
![Main menu](docs/screenshots/menu.png)
![Tag identification](docs/screenshots/identify.png)
![Watch mode](docs/screenshots/watch.png)
![HTML report](docs/screenshots/report.png)
-->

---

## Project structure

```
rfideye/
├── rfideye/
│   ├── cli.py               # entry point, subcommands and interactive menu
│   ├── config.py            # data directory layout and logging setup
│   ├── device.py            # autodetection, connection, guarded execution
│   ├── identify.py          # band detection, output parsers, ATQA/SAK table
│   ├── transit.py           # public-transport ticketing profiler
│   ├── dump.py              # tag → file memory reading and key handling
│   ├── read_only_guard.py   # the allow-list guard (the security kernel)
│   ├── storage.py           # SQLite history, JSON/CSV export
│   ├── report.py            # Markdown / HTML session reports
│   ├── demo.py              # canned client output for --demo and tests
│   └── ui/
│       ├── theme.py         # red / green / amber rich theme
│       └── banner.py        # ASCII banner and legal notice
├── tests/                   # pytest suite, incl. the read-only guarantee
├── docs/screenshots/
├── .github/workflows/ci.yml # ruff + pytest + read-only guarantee job
└── pyproject.toml
```

### How the read-only guarantee works

Every command passes through `read_only_guard.validate()` before reaching the device, and `Proxmark3` exposes no other execution path — there is no `execute_raw`.

1. **Lexical** — the string may only contain `[A-Za-z0-9 _.:,/=+-]`. Shell metacharacters, quotes and newlines are rejected, so nothing can smuggle a second command into `pm3 -c`. The client is also invoked with `shell=False` and an argv list.
2. **Deny** — a curated blocklist of write / clone / emulate / attack vocabulary. Redundant with layer 3 on purpose: it produces a precise audit log of *what* was attempted.
3. **Allow** — longest-prefix match against the rule table, then every flag, option value and positional argument is validated against a regex. Unknown flags are refused; filenames are restricted to a basename charset, so `-f ../../etc/passwd` never gets through.

Run `rfideye commands` to see the entire allow-list, or read [`rfideye/read_only_guard.py`](rfideye/read_only_guard.py) — it is deliberately short enough to audit in one sitting.

---

## Contributing

Contributions are welcome — bug reports, new tag signatures, better parsers for firmware revisions, translations.

**One rule is not negotiable:** pull requests that add write, clone, emulation, simulation, sniffing or key-recovery capability will be closed. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow, coding standards and the test requirements for touching the guard.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

* The [Proxmark3 RDV4 / Iceman project](https://github.com/RfidResearchGroup/proxmark3) and its maintainers, whose client does the actual radio work.
* The original [Proxmark3 project](https://github.com/Proxmark/proxmark3) by Jonathan Westhues.
* The RFID research community, whose public documentation of ATQA/SAK values, tag families and ticketing standards makes identification tooling possible.
* [`rich`](https://github.com/Textualize/rich) and [`typer`](https://github.com/fastapi/typer) for the interface layer.
