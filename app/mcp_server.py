"""MCP server — a thin proxy over HTTP to the running FastAPI daemon (app.main).

This mirrors Tares' actual split: a single daemon (`taresd`) owns the one DuckDB writer connection,
and a separate thin MCP proxy (`tares-mcp`) talks to it — never opens the DuckDB file itself.
DuckDB allows exactly one writer per file (Tares documents this as "runs one DuckDB writer per
instance"); a second process opening the file directly, even read-only, contends with that lock in
practice. Going over HTTP instead sidesteps it entirely and matches how Tares itself is composed.

Run alongside `uvicorn app.main:app` (default http://127.0.0.1:8000):
    python -m app.mcp_server
Then point a client at it, e.g. in Claude Code:
    claude mcp add ioctimeline -- python -m app.mcp_server
Override the daemon URL with IOCTIMELINE_API_URL if it's not on localhost:8000.
"""
from __future__ import annotations

import json
import os

import httpx
from mcp.server.fastmcp import FastMCP

API_URL = os.environ.get("IOCTIMELINE_API_URL", "http://127.0.0.1:8000")

mcp = FastMCP("ioctimeline")


@mcp.tool()
def read(entity: str, window_seconds: int | None = None) -> str:
    """Read the correlated timeline for one entity (an IP or a username): every auth-log event,
    threat-intel enrichment, and finding for it, time-ordered, in one call."""
    params = {"window_seconds": window_seconds} if window_seconds else {}
    resp = httpx.get(f"{API_URL}/entities/{entity}/timeline", params=params, timeout=10)
    if resp.status_code == 404:
        return f"No events found for entity '{entity}'."
    resp.raise_for_status()
    events = resp.json()["events"]
    return "\n".join(f"[{e['event_time']}] ({e['source']}) {e['text']}" for e in events)


@mcp.tool()
def list_flagged_entities() -> str:
    """List every entity that currently has a finding (a trigger-written alert) on its timeline."""
    resp = httpx.get(f"{API_URL}/findings", timeout=10)
    resp.raise_for_status()
    findings = resp.json()["findings"]
    if not findings:
        return "No entities currently flagged."
    return json.dumps(findings, indent=2)


@mcp.tool()
def list_entities(since_seconds: int = 3600) -> str:
    """List entities with any activity in the last N seconds (default 1 hour)."""
    resp = httpx.get(f"{API_URL}/entities", params={"since_seconds": since_seconds}, timeout=10)
    resp.raise_for_status()
    return json.dumps(resp.json()["entities"])


if __name__ == "__main__":
    mcp.run(transport="stdio")
