# IOCTimeline

A small, self-hostable event-correlation engine for security data: auth logs and threat-intel
enrichment land on one time-ordered timeline per entity (an IP or a username), a trigger watches
for credential-stuffing velocity and writes a finding back onto that timeline, and an MCP server
serves the same correlated read to an agent — one call instead of separately querying an auth log
and a threat-intel lookup.

## Why this shape

The architecture deliberately mirrors [GlassFlow Tares](https://github.com/glassflow/tares):
a single embedded DuckDB file, no external database or broker, sources write onto a per-entity
timeline, a trigger reads the correlated timeline and writes a finding back onto it, and an MCP
layer serves that same correlated read to an agent. Tares' own connector catalog covers
infrastructure/observability (Prometheus, GitHub, Postgres, Vercel, OTLP) — there's nothing for
correlating security signals. This applies the same pattern to a domain I've actually worked in:
SIEM integration, IOC enrichment pipelines, and bot/credential-stuffing detection (see
`app/triggers.py` for the rule).

One deliberate divergence, found the hard way: DuckDB allows exactly one writer per file (Tares
documents this too — "runs one DuckDB writer per instance"). A second process can't safely open
the same file read-only alongside an active writer in practice, so the MCP server here is a thin
HTTP proxy to the FastAPI daemon rather than a second direct DB reader — which turns out to match
how Tares itself is composed (`taresd` + a thin `tares-mcp` proxy), not a workaround.

## Run it

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 for a minimal console, or:

```bash
curl -X POST http://127.0.0.1:8000/demo/simulate
curl http://127.0.0.1:8000/entities/185.220.101.7/timeline
```

replays a burst of failed logins from an IP already listed in the sample threat-intel feed
(`data/threat_feed.json`) and shows the finding fire once the 5th failed login lands.

### Connect an agent over MCP

```bash
# with the API already running:
python -m app.mcp_server   # stdio transport
```

```bash
claude mcp add ioctimeline -- python -m app.mcp_server
```

Then ask: *"Use ioctimeline: what happened with 185.220.101.7?"*

## What's real vs. illustrative

- The correlation engine, trigger, DuckDB store, HTTP API, and MCP server all run and are tested
  end-to-end (see the demo scenario).
- The threat-intel feed is a static local JSON file rather than a live external feed — the loader
  (`app/threatfeed.py`) is written so swapping in a URL fetch (MISP, OTX, AbuseIPDB export) is a
  one-function change; kept local here to stay dependency-free and match Tares' own "no external
  services required" stance for a self-hosted demo.

## Structure

```
app/
  store.py       DuckDB-backed event store, the one correlated read
  threatfeed.py  threat-intel enrichment source (incremental, cursor by indicator)
  triggers.py    velocity rule -> writes a finding back onto the timeline
  main.py        FastAPI: ingestion, correlated reads, demo scenario
  mcp_server.py  MCP proxy over HTTP to the FastAPI daemon
data/threat_feed.json   sample IOC feed
demo/simulate.py        standalone demo runner
```
