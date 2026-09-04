"""Replay the credential-stuffing demo scenario and print the correlated result.

Usage (with the API running — `uvicorn app.main:app` — in another terminal):
    python demo/simulate.py
"""
from __future__ import annotations

import httpx

API_URL = "http://127.0.0.1:8000"


def main() -> None:
    resp = httpx.post(f"{API_URL}/demo/simulate", timeout=10)
    resp.raise_for_status()
    data = resp.json()
    attacker_ip = data["attacker_ip"]
    print(f"Simulated 6 failed logins from {attacker_ip} (already listed in the threat-intel feed).\n")

    resp = httpx.get(f"{API_URL}/entities/{attacker_ip}/timeline", timeout=10)
    resp.raise_for_status()
    events = resp.json()["events"]

    print("Correlated timeline:")
    for e in events:
        print(f"  [{e['event_time']}] ({e['source']:<12}) {e['text']}")

    fired = [e for e in events if e["source"] == "finding"]
    print(f"\n{len(fired)} finding(s) written back onto the timeline." if fired
          else "\nNo finding fired — check the velocity threshold.")


if __name__ == "__main__":
    main()
