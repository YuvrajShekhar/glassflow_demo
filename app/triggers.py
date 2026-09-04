"""Trigger engine.

A trigger watches the store and, when its condition is met, writes a `finding` event back onto the
entity's timeline — the same "trigger fires -> finding written back" loop Tares uses, just with a
concrete security rule instead of Tares' generic condition DSL.

Rule implemented: velocity — N `login_failed` events for the same entity within a rolling window.
This is the same shape of detection as the bot-detection / credential-stuffing classification work
on the resume (rapid credential-stuffing attempts, repeated login failures -> classify + flag),
just re-expressed as: after every login_failed write, check the count, and if it crosses the
threshold, correlate against threat_intel automatically (an IP already on the feed makes the
finding higher-confidence) and write the finding.
"""
from __future__ import annotations

from .store import Event, Store

VELOCITY_THRESHOLD = 5      # failed logins...
VELOCITY_WINDOW_SECONDS = 60  # ...within this many seconds


def check_velocity(store: Store, entity: str) -> dict | None:
    """Call after writing a login_failed event. Returns the finding payload if the trigger fired."""
    count = store.count_recent(
        entity, source="auth_log", event_type="login_failed", window_seconds=VELOCITY_WINDOW_SECONDS
    )
    if count < VELOCITY_THRESHOLD:
        return None

    # Already flagged in this window? Don't re-fire.
    recent = store.read_timeline(entity, window_seconds=VELOCITY_WINDOW_SECONDS)
    if any(e["source"] == "finding" for e in recent):
        return None

    # Correlate: does threat-intel already know this entity? Read is the same read an agent gets.
    timeline = store.read_timeline(entity)
    known_bad = [e for e in timeline if e["source"] == "threat_intel"]
    confidence = "high" if known_bad else "medium"
    reason = (
        f"{count} failed logins from {entity} within {VELOCITY_WINDOW_SECONDS}s"
        + (f"; entity is already listed in threat-intel feed ({known_bad[0]['payload'].get('threat_type', 'n/a')})"
           if known_bad else "; not previously listed in threat-intel feed")
    )

    finding = {
        "entity": entity,
        "rule": "credential_stuffing_velocity",
        "confidence": confidence,
        "failed_login_count": count,
        "window_seconds": VELOCITY_WINDOW_SECONDS,
        "reason": reason,
    }

    store.write(
        Event(
            entity=entity,
            source="finding",
            event_type="velocity_alert",
            text=f"FINDING: possible credential stuffing from {entity} ({confidence} confidence) — {reason}",
            payload=finding,
        )
    )
    return finding
