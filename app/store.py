"""Embedded event store — one DuckDB file, no external DB.

Mirrors Tares' core design decision (single daemon, single embedded DuckDB, no broker) but the
schema here is intentionally narrow: security-domain events keyed by an entity (an IP address or
a username), each carrying a source, an event_type, a rendered text line, and the original
lossless payload. `read_timeline` is the one correlated read every consumer (HTTP, MCP, triggers)
goes through.
"""
from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import duckdb


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Event:
    entity: str            # the correlation key: an IP, a username, a hash — whatever ties sources together
    source: str             # "auth_log" | "threat_intel" | "finding"
    event_type: str         # "login_failed" | "ip_reputation" | "velocity_alert" | ...
    text: str                # one rendered line an agent (or human) reads
    payload: dict = field(default_factory=dict)   # original, lossless
    event_time: datetime = field(default_factory=now_utc)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)


class Store:
    """Thread-safe wrapper around one DuckDB file. Single writer, matching Tares' own model."""

    def __init__(self, path: str = "ioctimeline.duckdb", read_only: bool = False):
        self._lock = threading.Lock()
        self._con = duckdb.connect(path, read_only=read_only)
        if not read_only:
            self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._con.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id VARCHAR PRIMARY KEY,
                    entity VARCHAR NOT NULL,
                    source VARCHAR NOT NULL,
                    event_type VARCHAR NOT NULL,
                    text VARCHAR NOT NULL,
                    payload VARCHAR NOT NULL,
                    event_time TIMESTAMP NOT NULL
                )
                """
            )
            self._con.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity)"
            )

    def write(self, event: Event) -> None:
        with self._lock:
            self._con.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    event.id,
                    event.entity,
                    event.source,
                    event.event_type,
                    event.text,
                    json.dumps(event.payload, default=str),
                    event.event_time,
                ],
            )

    def read_timeline(self, entity: str, window_seconds: int | None = None) -> list[dict]:
        """The one correlated read: every event for this entity, across every source, time-ordered."""
        with self._lock:
            if window_seconds:
                rows = self._con.execute(
                    """
                    SELECT id, entity, source, event_type, text, payload, event_time
                    FROM events
                    WHERE entity = ? AND event_time >= now() - to_seconds(?)
                    ORDER BY event_time ASC
                    """,
                    [entity, window_seconds],
                ).fetchall()
            else:
                rows = self._con.execute(
                    """
                    SELECT id, entity, source, event_type, text, payload, event_time
                    FROM events
                    WHERE entity = ?
                    ORDER BY event_time ASC
                    """,
                    [entity],
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_recent(self, entity: str, source: str, event_type: str, window_seconds: int) -> int:
        """Used by the velocity trigger: how many matching events for this entity in the last N seconds."""
        with self._lock:
            (n,) = self._con.execute(
                """
                SELECT count(*) FROM events
                WHERE entity = ? AND source = ? AND event_type = ?
                  AND event_time >= now() - to_seconds(?)
                """,
                [entity, source, event_type, window_seconds],
            ).fetchone()
        return n

    def list_entities(self, since_seconds: int | None = None) -> list[str]:
        with self._lock:
            if since_seconds:
                rows = self._con.execute(
                    "SELECT DISTINCT entity FROM events WHERE event_time >= now() - to_seconds(?)",
                    [since_seconds],
                ).fetchall()
            else:
                rows = self._con.execute("SELECT DISTINCT entity FROM events").fetchall()
        return [r[0] for r in rows]

    def list_flagged(self) -> list[dict]:
        """Entities with a 'finding' event written back onto their timeline."""
        with self._lock:
            rows = self._con.execute(
                """
                SELECT id, entity, source, event_type, text, payload, event_time
                FROM events WHERE source = 'finding'
                ORDER BY event_time DESC
                """
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    @staticmethod
    def _row_to_dict(row) -> dict:
        id_, entity, source, event_type, text, payload, event_time = row
        return {
            "id": id_,
            "entity": entity,
            "source": source,
            "event_type": event_type,
            "text": text,
            "payload": json.loads(payload),
            "event_time": event_time.isoformat() if hasattr(event_time, "isoformat") else str(event_time),
        }
