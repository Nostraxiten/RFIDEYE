"""Human-readable session reports in Markdown or self-contained HTML.

A report is what you hand to whoever asked for the audit: the device used, the
tags seen, what was readable and - importantly - an explicit statement that the
session was read-only.

Both renderers take the same :class:`~rfideye.storage.ScanRecord` list, so the
Markdown and HTML outputs never drift apart.
"""

from __future__ import annotations

import html
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from rfideye import APP_NAME, __version__
from rfideye.storage import ScanRecord

LOGGER: Final[logging.Logger] = logging.getLogger("rfideye.report")

READ_ONLY_STATEMENT: Final[str] = (
    "This session was performed with RFIDeye in read-only mode. Every command "
    "sent to the Proxmark3 was validated against an allow-list of read and "
    "identify operations; no write, clone, emulate or key-recovery command is "
    "reachable from this tool."
)


@dataclass(frozen=True, slots=True)
class ReportMeta:
    """Context shown in the report header."""

    session_id: str
    device_port: str = "unknown"
    device_description: str = "unknown"
    firmware: str = "unknown"
    operator_note: str = ""

    @property
    def generated_at(self) -> str:
        return datetime.now(UTC).isoformat(timespec="seconds")


def _summary_counts(records: Sequence[ScanRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.product] = counts.get(record.product, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def render_markdown(records: Sequence[ScanRecord], meta: ReportMeta) -> str:
    """Render a session report as Markdown."""
    lines: list[str] = [
        f"# {APP_NAME} session report",
        "",
        f"- **Session ID:** `{meta.session_id}`",
        f"- **Generated:** {meta.generated_at}",
        f"- **Tool version:** {APP_NAME} {__version__}",
        f"- **Device:** {meta.device_description} on `{meta.device_port}`",
        f"- **Firmware:** {meta.firmware}",
        f"- **Tags recorded:** {len(records)}",
        "",
        f"> {READ_ONLY_STATEMENT}",
        "",
    ]
    if meta.operator_note:
        lines += ["## Operator note", "", meta.operator_note, ""]

    counts = _summary_counts(records)
    if counts:
        lines += ["## Summary", "", "| Tag type | Count |", "| --- | ---: |"]
        lines += [f"| {product} | {count} |" for product, count in counts.items()]
        lines.append("")

    lines += [
        "## Scans",
        "",
        "| # | Time (UTC) | Band | Product | UID | ATQA | SAK | Conf. |",
        "| ---: | --- | --- | --- | --- | --- | --- | ---: |",
    ]
    for position, record in enumerate(records, start=1):
        lines.append(
            f"| {position} | {record.timestamp} | {record.band} | {record.product} | "
            f"`{record.uid or '-'}` | {record.atqa or '-'} | {record.sak or '-'} | "
            f"{record.confidence:.0%} |"
        )
    lines.append("")

    detailed = [record for record in records if record.notes or record.transit or record.extra]
    if detailed:
        lines += ["## Details", ""]
        for record in detailed:
            lines.append(f"### Scan {record.id} - {record.product}")
            lines.append("")
            for key, value in record.extra.items():
                lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
            if record.transit:
                lines.append(
                    f"- **Transit scheme (heuristic):** {record.transit.get('scheme')} "
                    f"({float(record.transit.get('confidence', 0)):.0%} confidence)"
                )
                for item in record.transit.get("locked_behind", []):
                    lines.append(f"  - Not read (requires): {item}")
            for note in record.notes:
                lines.append(f"- {note}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
_CSS: Final[str] = """
:root { color-scheme: light dark;
        --bg:#0f1115; --fg:#e6e6e6; --muted:#9aa0a6;
        --ok:#3ddc84; --err:#ff5f56; --amber:#ffb454; --line:#2a2f3a; }
* { box-sizing: border-box; }
body { margin:0; padding:2rem; background:var(--bg); color:var(--fg);
       font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
h1 { color:var(--ok); border-bottom:2px solid var(--ok); padding-bottom:.4rem; }
h2 { color:var(--amber); margin-top:2rem; }
h3 { color:var(--fg); margin-bottom:.25rem; }
.meta { display:grid; grid-template-columns:max-content 1fr; gap:.25rem 1.25rem;
        color:var(--muted); margin:1rem 0 2rem; }
.meta b { color:var(--fg); }
.banner { border-left:4px solid var(--ok); background:rgba(61,220,132,.08);
          padding:.75rem 1rem; margin:1.5rem 0; }
.wrap { overflow-x:auto; }
table { border-collapse:collapse; width:100%; min-width:720px; margin:.5rem 0 1.5rem; }
th,td { border:1px solid var(--line); padding:.4rem .6rem; text-align:left; }
th { background:rgba(255,255,255,.04); color:var(--amber); }
td.num { text-align:right; }
code { color:var(--ok); }
.low { color:var(--err); }
ul { margin:.25rem 0 1rem 1.1rem; }
footer { margin-top:3rem; color:var(--muted); font-size:.85em;
         border-top:1px solid var(--line); padding-top:1rem; }
"""


def _cell(value: str | None) -> str:
    return html.escape(value) if value else "-"


def render_html(records: Sequence[ScanRecord], meta: ReportMeta) -> str:
    """Render a self-contained HTML session report (no external assets)."""
    counts = _summary_counts(records)

    rows = "\n".join(
        "<tr>"
        f"<td class='num'>{position}</td>"
        f"<td>{_cell(record.timestamp)}</td>"
        f"<td>{_cell(record.band)}</td>"
        f"<td>{_cell(record.product)}</td>"
        f"<td><code>{_cell(record.uid)}</code></td>"
        f"<td>{_cell(record.atqa)}</td>"
        f"<td>{_cell(record.sak)}</td>"
        f"<td class='num{' low' if record.confidence < 0.5 else ''}'>"
        f"{record.confidence:.0%}</td>"
        "</tr>"
        for position, record in enumerate(records, start=1)
    )

    summary_rows = "\n".join(
        f"<tr><td>{html.escape(product)}</td><td class='num'>{count}</td></tr>"
        for product, count in counts.items()
    )

    details: list[str] = []
    for record in records:
        if not (record.notes or record.transit or record.extra):
            continue
        items = [
            f"<li><b>{html.escape(key.replace('_', ' ').title())}:</b> "
            f"{html.escape(str(value))}</li>"
            for key, value in record.extra.items()
        ]
        if record.transit:
            items.append(
                "<li><b>Transit scheme (heuristic):</b> "
                f"{html.escape(str(record.transit.get('scheme')))}</li>"
            )
        items += [f"<li>{html.escape(note)}</li>" for note in record.notes]
        details.append(
            f"<h3>Scan {record.id} - {html.escape(record.product)}</h3>"
            f"<ul>{''.join(items)}</ul>"
        )

    note_block = (
        f"<h2>Operator note</h2><p>{html.escape(meta.operator_note)}</p>"
        if meta.operator_note
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{APP_NAME} session {html.escape(meta.session_id)}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>{APP_NAME} session report</h1>
<div class="meta">
  <b>Session ID</b><span>{html.escape(meta.session_id)}</span>
  <b>Generated</b><span>{meta.generated_at}</span>
  <b>Tool</b><span>{APP_NAME} {__version__}</span>
  <b>Device</b><span>{html.escape(meta.device_description)}
      ({html.escape(meta.device_port)})</span>
  <b>Firmware</b><span>{html.escape(meta.firmware)}</span>
  <b>Tags recorded</b><span>{len(records)}</span>
</div>
<div class="banner">{html.escape(READ_ONLY_STATEMENT)}</div>
{note_block}
<h2>Summary</h2>
<div class="wrap"><table>
<thead><tr><th>Tag type</th><th>Count</th></tr></thead>
<tbody>{summary_rows}</tbody>
</table></div>
<h2>Scans</h2>
<div class="wrap"><table>
<thead><tr><th>#</th><th>Time (UTC)</th><th>Band</th><th>Product</th><th>UID</th>
<th>ATQA</th><th>SAK</th><th>Confidence</th></tr></thead>
<tbody>{rows}</tbody>
</table></div>
{"<h2>Details</h2>" + "".join(details) if details else ""}
<footer>Generated by {APP_NAME} {__version__} - read-only RFID auditing.</footer>
</body>
</html>
"""


def write_report(
    records: Sequence[ScanRecord],
    meta: ReportMeta,
    destination: Path,
    *,
    fmt: str = "md",
) -> Path:
    """Render and write a report.

    Args:
        records: Scans to include.
        meta: Header context.
        destination: Target file, or a directory to generate a name in.
        fmt: ``"md"`` or ``"html"``.

    Returns:
        The path written.

    Raises:
        ValueError: For an unknown format.
    """
    if fmt not in {"md", "html"}:
        raise ValueError(f"unsupported report format {fmt!r}; use 'md' or 'html'")

    if destination.is_dir() or destination.suffix == "":
        destination.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        destination = destination / f"rfideye-session-{meta.session_id}-{stamp}.{fmt}"
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)

    content = render_markdown(records, meta) if fmt == "md" else render_html(records, meta)
    destination.write_text(content, encoding="utf-8")
    LOGGER.info("report written to %s", destination)
    return destination
