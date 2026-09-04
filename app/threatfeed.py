"""Threat-intel enrichment source.

Loads a local IOC feed (JSON — the shape a MISP/OTX/AbuseIPDB export normalizes to: indicator,
type, threat_type, confidence, source, first_seen) and writes one `ip_reputation` event per
indicator onto that indicator's timeline. Runs on startup and on a poll interval, incremental
(only emits indicators it hasn't already written), the same pattern Tares' own poll connectors use
for their cursor.

Kept file-based and dependency-free on purpose: this mirrors Tares' "no external DB, no broker"
stance — point it at a feed URL instead of a file and the rest is unchanged (see `fetch_feed`).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from .store import Event, Store

logger = logging.getLogger("ioctimeline.threatfeed")


def load_feed(path: str) -> list[dict]:
    return json.loads(Path(path).read_text())


def sync_feed(store: Store, feed_path: str, seen: set[str]) -> int:
    """Write a `threat_intel` event for every indicator not yet seen this run. Returns count written."""
    indicators = load_feed(feed_path)
    written = 0
    for ioc in indicators:
        key = ioc["indicator"]
        if key in seen:
            continue
        seen.add(key)
        confidence = ioc.get("confidence", 0)
        threat_type = ioc.get("threat_type", "unknown")
        text = (
            f"{key} flagged as {threat_type} (confidence {confidence}) "
            f"— source: {ioc.get('source', 'feed')}, first seen {ioc.get('first_seen', 'n/a')}"
        )
        store.write(
            Event(
                entity=key,
                source="threat_intel",
                event_type="ip_reputation",
                text=text,
                payload=ioc,
            )
        )
        written += 1
    if written:
        logger.info("threat feed sync: wrote %d new indicator(s)", written)
    return written
