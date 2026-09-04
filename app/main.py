"""IOCTimeline — a self-hostable event-correlation engine for security data.

Architecture deliberately mirrors GlassFlow Tares: one embedded DuckDB file, no external DB or
broker, sources write onto a per-entity timeline, a trigger reads the correlated timeline and
writes findings back onto it, and an MCP server serves the same correlated read to an agent.
Applied here to a domain from my own background (SIEM correlation, IOC enrichment, bot/credential-
stuffing detection) rather than Tares' infra/observability domain.

Run: uvicorn app.main:app --reload
"""
from __future__ import annotations

import logging
import os
import random
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .store import Event, Store, now_utc
from .threatfeed import sync_feed
from .triggers import check_velocity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ioctimeline")

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = os.environ.get("DATA_PATH", str(BASE_DIR / "ioctimeline.duckdb"))
FEED_PATH = os.environ.get("FEED_PATH", str(BASE_DIR / "data" / "threat_feed.json"))

store = Store(DATA_PATH)
_seen_indicators: set[str] = set()

app = FastAPI(title="IOCTimeline", description="Correlated security event timeline, self-hosted.")

static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.on_event("startup")
def _startup() -> None:
    written = sync_feed(store, FEED_PATH, _seen_indicators)
    logger.info("startup: loaded %d threat-intel indicator(s)", written)


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

class AuthEvent(BaseModel):
    ip: str
    username: str
    result: str  # "failed" | "success"
    event_time: datetime | None = None


@app.post("/ingest/auth")
def ingest_auth(evt: AuthEvent):
    """Push endpoint for auth-log events (the pattern Tares' webhook connector uses)."""
    event_type = "login_failed" if evt.result == "failed" else "login_success"
    text = f"login {evt.result} for user={evt.username} from ip={evt.ip}"
    store.write(
        Event(
            entity=evt.ip,
            source="auth_log",
            event_type=event_type,
            text=text,
            payload=evt.model_dump(mode="json"),
            event_time=evt.event_time or now_utc(),
        )
    )
    finding = None
    if event_type == "login_failed":
        finding = check_velocity(store, evt.ip)
    return {"ok": True, "finding": finding}


@app.post("/threat-intel/sync")
def resync_feed():
    """Re-poll the threat-intel feed on demand (also runs on startup)."""
    written = sync_feed(store, FEED_PATH, _seen_indicators)
    return {"written": written}


# ---------------------------------------------------------------------------
# Reads — the correlated timeline, the one thing every consumer (HTTP, MCP, console) goes through
# ---------------------------------------------------------------------------

@app.get("/entities/{entity}/timeline")
def get_timeline(entity: str, window_seconds: int | None = None):
    timeline = store.read_timeline(entity, window_seconds=window_seconds)
    if not timeline:
        raise HTTPException(status_code=404, detail="no events for this entity")
    return {"entity": entity, "events": timeline}


@app.get("/entities")
def list_entities(since_seconds: int | None = 3600):
    return {"entities": store.list_entities(since_seconds=since_seconds)}


@app.get("/findings")
def list_findings():
    return {"findings": store.list_flagged()}


# ---------------------------------------------------------------------------
# Demo — replays a canned credential-stuffing scenario so the whole loop is visible in one call
# ---------------------------------------------------------------------------

@app.post("/demo/simulate")
def simulate():
    """Replay: an IP already on the threat-intel feed bursts 6 failed logins across usernames.
    Expect: threat_intel event on ingest, 6 auth_log events, then a finding written onto the
    timeline once the velocity threshold is crossed."""
    attacker_ip = "185.220.101.7"  # present in data/threat_feed.json
    usernames = ["admin", "root", "jsmith", "info", "svc-backup", "test"]
    results = []
    for user in usernames:
        evt = AuthEvent(ip=attacker_ip, username=user, result="failed")
        results.append(ingest_auth(evt))
    return {"attacker_ip": attacker_ip, "steps": results}


@app.get("/", response_class=HTMLResponse)
def console():
    index = static_dir / "index.html"
    if index.exists():
        return index.read_text()
    return "<h1>IOCTimeline</h1><p>See /docs for the API.</p>"
