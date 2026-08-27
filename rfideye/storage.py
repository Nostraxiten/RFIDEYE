"""Persistence: SQLite scan history plus JSON / CSV export.

Only ``sqlite3``, ``json`` and ``csv`` from the standard library are used - a
scan log is a few thousand rows at most, so an ORM would be pure overhead.

The schema is intentionally denormalised (one row per scan, JSON blobs for the
variable-shaped parts) because the interesting queries are all "show me the
last N scans" or "have I seen this UID before".
"""

from __future__ import annotations

import csv
import json
import logging
import sqlite3
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Final

from rfideye.identify import Band, TagIdentity
from rfideye.transit import TransitProfile

LOGGER: Final[logging.Logger] = logging.getLogger("rfideye.storage")

SCHEMA_VERSION: Final[int] = 1

_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    band        TEXT    NOT NULL,
    technology  TEXT    NOT NULL,
    product     TEXT    NOT NULL,
    uid         TEXT,
    atqa        TEXT,
    sak         TEXT,
    ats         TEXT,
    confidence  REAL    NOT NULL DEFAULT 0,
    extra       TEXT    NOT NULL DEFAULT '{}',
    notes       TEXT    NOT NULL DEFAULT '[]',
    transit     TEXT,
    outcome     TEXT    NOT NULL DEFAULT 'ok'
);
CREATE INDEX IF NOT EXISTS idx_scans_uid     ON scans(uid);
CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


@dataclass(frozen=True, slots=True)
class ScanRecord:
    """One persisted scan, as read back from the database."""

    id: int
    session_id: str
    timestamp: str
    band: str
    technology: str
    product: str
    uid: str | None
    atqa: str | None
    sak: str | None
    ats: str | None
    confidence: float
    extra: dict[str, Any]
    notes: list[str]
    transit: dict[str, Any] | None
    outcome: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ScanRecord:
        return cls(
            id=row["id"],
            session_id=row["session_id"],
            timestamp=row["timestamp"],
            band=row["band"],
            technology=row["technology"],
            product=row["product"],
            uid=row["uid"],
            atqa=row["atqa"],
            sak=row["sak"],
            ats=row["ats"],
            confidence=row["confidence"],
            extra=json.loads(row["extra"]),
            notes=json.loads(row["notes"]),
            transit=json.loads(row["transit"]) if row["transit"] else None,
            outcome=row["outcome"],
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "band": self.band,
            "technology": self.technology,
            "product": self.product,
            "uid": self.uid,
            "atqa": self.atqa,
            "sak": self.sak,
            "ats": self.ats,
            "confidence": self.confidence,
            "extra": self.extra,
            "notes": self.notes,
            "outcome": self.outcome,
        }
        if self.transit:
            payload["transit"] = self.transit
        return payload


def new_session_id() -> str:
    """Return a short, unique identifier for one RFIDeye run."""
    return uuid.uuid4().hex[:12]


class History:
    """SQLite-backed scan history.  Usable as a context manager."""

    def __init__(self, path: Path, *, session_id: str | None = None) -> None:
        self.path = path
        self.session_id = session_id or new_session_id()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self._conn.commit()
        LOGGER.debug("history opened at %s (session %s)", path, self.session_id)

    # -- context manager ---------------------------------------------------- #
    def __enter__(self) -> History:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    # -- writes ------------------------------------------------------------- #
    def record(
        self,
        identity: TagIdentity,
        transit: TransitProfile | None = None,
        *,
        outcome: str = "ok",
    ) -> int:
        """Persist one scan and return its row id."""
        cursor = self._conn.execute(
            """
            INSERT INTO scans (session_id, timestamp, band, technology, product, uid,
                               atqa, sak, ats, confidence, extra, notes, transit, outcome)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                self.session_id,
                identity.timestamp,
                identity.band.value,
                identity.technology,
                identity.product,
                identity.uid,
                identity.atqa,
                identity.sak,
                identity.ats,
                identity.confidence,
                json.dumps(identity.extra, ensure_ascii=False),
                json.dumps(identity.notes, ensure_ascii=False),
                json.dumps(transit.to_dict(), ensure_ascii=False) if transit else None,
                outcome,
            ),
        )
        self._conn.commit()
        return int(cursor.lastrowid or 0)

    # -- reads -------------------------------------------------------------- #
    def recent(self, limit: int = 20) -> list[ScanRecord]:
        """Return the most recent scans, newest first."""
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [ScanRecord.from_row(row) for row in rows]

    def for_session(self, session_id: str | None = None) -> list[ScanRecord]:
        """Return every scan of one session, oldest first."""
        rows = self._conn.execute(
            "SELECT * FROM scans WHERE session_id = ? ORDER BY id ASC",
            (session_id or self.session_id,),
        ).fetchall()
        return [ScanRecord.from_row(row) for row in rows]

    def by_uid(self, uid: str) -> list[ScanRecord]:
        """Return every time a given UID was seen."""
        rows = self._conn.execute(
            "SELECT * FROM scans WHERE uid = ? ORDER BY id DESC", (uid.upper(),)
        ).fetchall()
        return [ScanRecord.from_row(row) for row in rows]

    def seen_before(self, uid: str | None) -> bool:
        """True if this UID already exists in the history (before the current row)."""
        if not uid:
            return False
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE uid = ?", (uid.upper(),)
        ).fetchone()
        return bool(row["n"] > 1)

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()
        return int(row["n"])

    def stats(self) -> dict[str, int]:
        """Scan counts grouped by product, most frequent first."""
        rows = self._conn.execute(
            "SELECT product, COUNT(*) AS n FROM scans GROUP BY product ORDER BY n DESC"
        ).fetchall()
        return {row["product"]: row["n"] for row in rows}


# --------------------------------------------------------------------------- #
# Exporters
# --------------------------------------------------------------------------- #
_CSV_COLUMNS: Final[tuple[str, ...]] = (
    "timestamp", "band", "technology", "product", "uid", "atqa", "sak",
    "confidence", "outcome", "notes",
)


def _timestamped_name(prefix: str, suffix: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{stamp}{suffix}"


def export_json(
    records: Sequence[ScanRecord] | Sequence[TagIdentity],
    destination: Path,
    *,
    include_raw: bool = False,
) -> Path:
    """Write records to a JSON file (directory paths get a generated filename).

    Args:
        records: Either persisted :class:`ScanRecord` rows or live
            :class:`~rfideye.identify.TagIdentity` objects.
        destination: Target file, or a directory to generate a name in.
        include_raw: Include the verbatim client output (identities only).

    Returns:
        The path actually written.
    """
    path = _resolve(destination, "rfideye-dump", ".json")
    payload = {
        "tool": "RFIDeye",
        "exported_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "read_only": True,
        "records": [_as_dict(record, include_raw=include_raw) for record in records],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    LOGGER.info("exported %d record(s) to %s", len(records), path)
    return path


def export_csv(
    records: Sequence[ScanRecord] | Sequence[TagIdentity], destination: Path
) -> Path:
    """Write records to a flat CSV file (nested fields are flattened to text)."""
    path = _resolve(destination, "rfideye-dump", ".csv")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            data = _as_dict(record)
            data["notes"] = " | ".join(data.get("notes") or [])
            data.setdefault("outcome", "ok")
            writer.writerow(data)
    LOGGER.info("exported %d record(s) to %s", len(records), path)
    return path


def _resolve(destination: Path, prefix: str, suffix: str) -> Path:
    """Turn a directory into a timestamped filename; leave files untouched."""
    if destination.is_dir() or destination.suffix == "":
        destination.mkdir(parents=True, exist_ok=True)
        return destination / _timestamped_name(prefix, suffix)
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def _as_dict(record: ScanRecord | TagIdentity, *, include_raw: bool = False) -> dict[str, Any]:
    if isinstance(record, TagIdentity):
        return record.to_dict(include_raw=include_raw)
    return record.to_dict()


def iter_identities(records: Iterable[ScanRecord]) -> Iterable[TagIdentity]:
    """Rehydrate persisted rows into :class:`TagIdentity` objects (for reports)."""
    for record in records:
        yield TagIdentity(
            band=Band(record.band) if record.band in {b.value for b in Band} else Band.UNKNOWN,
            technology=record.technology,
            product=record.product,
            uid=record.uid,
            atqa=record.atqa,
            sak=record.sak,
            ats=record.ats,
            extra=dict(record.extra),
            notes=list(record.notes),
            confidence=record.confidence,
            timestamp=record.timestamp,
        )
