"""
services/session_engine.py
──────────────────────────
Groups individual detection events into coherent attack sessions.

A session is ONGOING while attack events keep arriving.
After SESSION_GAP seconds of silence it is marked RESOLVED.

Session schema
──────────────
{
    session_id       : str          8-char hex ID
    attackers        : list[str]    IP addresses involved
    start_time       : float        unix timestamp
    end_time         : float        unix timestamp (updated each window)
    duration         : float        seconds
    peak_pps         : float
    peak_packets     : int
    total_packets    : int
    avg_probability  : float        rolling average ML probability
    event_count      : int
    severity         : str          LOW / MEDIUM / HIGH / CRITICAL
    attack_type      : str
    status           : str          ONGOING / RESOLVED
    last_update      : float        unix timestamp of last event
    mitigation_actions: list[str]
}
"""

import time
import uuid
from typing import Optional

from config import SESSION_GAP

# ── Storage ───────────────────────────────────────────────────────────────────
MAX_RESOLVED  = 200
_active:   dict[frozenset, dict] = {}   # frozenset(attackers) → session
_resolved: list[dict]            = []   # completed sessions


# ── Public API ────────────────────────────────────────────────────────────────

def update_sessions(event: dict) -> None:
    """
    Call once per detection window (from detector_engine).
    If the event is an attack, open or extend the matching session.
    Always check whether any active session has gone stale.
    """
    _close_stale()

    if event.get("decision") != "attack" or not event.get("attackers"):
        return

    key = frozenset(event["attackers"])
    now = time.time()

    if key in _active:
        _extend(key, event, now)
    else:
        _open(key, event, now)


def get_active_sessions() -> list[dict]:
    return list(_active.values())


def get_all_sessions() -> list[dict]:
    return _resolved + list(_active.values())


def get_session_by_id(session_id: str) -> Optional[dict]:
    for s in get_all_sessions():
        if s["session_id"] == session_id:
            return s
    return None


def add_mitigation(session_id: str, action: str) -> None:
    """Record a mitigation action against a session (called from mitigation)."""
    for s in list(_active.values()) + _resolved:
        if s["session_id"] == session_id:
            s["mitigation_actions"].append(action)
            return


# ── Internal helpers ──────────────────────────────────────────────────────────

def _open(key: frozenset, event: dict, now: float) -> None:
    _active[key] = {
        "session_id":        uuid.uuid4().hex[:8].upper(),
        "attackers":         list(event["attackers"]),
        "start_time":        now,
        "end_time":          now,
        "duration":          0.0,
        "peak_pps":          event.get("pps", 0),
        "peak_packets":      event.get("packets", 0),
        "total_packets":     event.get("packets", 0),
        "avg_probability":   event.get("attack_probability", 0.0),
        "event_count":       1,
        "severity":          event.get("severity", "LOW"),
        "attack_type":       event.get("attack_type", "unknown"),
        "status":            "ONGOING",
        "last_update":       now,
        "mitigation_actions": [],
    }


def _extend(key: frozenset, event: dict, now: float) -> None:
    s = _active[key]
    n = s["event_count"]

    s["end_time"]       = now
    s["duration"]       = now - s["start_time"]
    s["peak_pps"]       = max(s["peak_pps"],     event.get("pps", 0))
    s["peak_packets"]   = max(s["peak_packets"],  event.get("packets", 0))
    s["total_packets"] += event.get("packets", 0)
    s["avg_probability"] = (
        s["avg_probability"] * n + event.get("attack_probability", 0.0)
    ) / (n + 1)
    s["event_count"]    = n + 1
    s["severity"]       = event.get("severity",    s["severity"])
    s["attack_type"]    = event.get("attack_type", s["attack_type"])
    s["last_update"]    = now


def _close_stale() -> None:
    now   = time.time()
    stale = [k for k, s in _active.items()
             if now - s["last_update"] > SESSION_GAP]

    for key in stale:
        s = _active.pop(key)
        s["status"]   = "RESOLVED"
        s["duration"] = s["end_time"] - s["start_time"]
        _resolved.append(s)

    # Trim old resolved sessions
    while len(_resolved) > MAX_RESOLVED:
        _resolved.pop(0)