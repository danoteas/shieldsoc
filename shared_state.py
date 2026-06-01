"""
shared_state.py
───────────────
Single source of truth for all mutable runtime state.
"""

from collections import defaultdict
import threading

# ── IP attack scoring table ───────────────────────────────────────────────────
attack_table = defaultdict(lambda: {
    "score":     0,
    "blocked":   False,
    "last_seen": 0.0,
})

# ── Blocked IPs ───────────────────────────────────────────────────────────────
blocked_ips:    dict[str, float] = {}   # auto blocks: ip → unblock_timestamp
blocked_manual: set[str]         = set() # manual blocks: no expiry

# ── Configurable whitelist ────────────────────────────────────────────────────
# IPs here are NEVER captured, scored, or blocked.
# Editable at runtime via /api/whitelist endpoints.
# Always includes core system IPs that cannot be removed.
_PERMANENT_WHITELIST: frozenset[str] = frozenset({
    "127.0.0.1", "127.0.1.1", "localhost",
})

_whitelist_lock = threading.Lock()
_whitelist: set[str] = {
    "127.0.0.1", "127.0.1.1",
    "192.168.20.1",   # gateway
    "192.168.20.8",   # victim/server itself
    "10.0.0.1", "10.0.0.2", "172.16.0.1",
    "localhost",
}


def get_whitelist() -> list[str]:
    with _whitelist_lock:
        return sorted(_whitelist)


def add_to_whitelist(ip: str) -> bool:
    """Returns True if added, False if already present."""
    with _whitelist_lock:
        if ip in _whitelist:
            return False
        _whitelist.add(ip)
        return True


def remove_from_whitelist(ip: str) -> tuple[bool, str]:
    """
    Returns (success, reason).
    Permanent IPs (127.x, localhost) cannot be removed.
    """
    if ip in _PERMANENT_WHITELIST:
        return False, f"{ip} is a permanent system IP and cannot be removed"
    with _whitelist_lock:
        if ip not in _whitelist:
            return False, f"{ip} is not in whitelist"
        _whitelist.discard(ip)
        return True, "removed"


def is_whitelisted(ip: str) -> bool:
    with _whitelist_lock:
        return ip in _whitelist


# ── Helpers ───────────────────────────────────────────────────────────────────

def is_blocked(ip: str) -> bool:
    return ip in blocked_ips or ip in blocked_manual


def add_auto_block(ip: str, until: float) -> None:
    blocked_ips[ip]             = until
    attack_table[ip]["blocked"] = True


def remove_auto_block(ip: str) -> None:
    blocked_ips.pop(ip, None)
    attack_table[ip]["score"]   = 0
    attack_table[ip]["blocked"] = False


def add_manual_block(ip: str) -> None:
    blocked_manual.add(ip)
    attack_table[ip]["blocked"] = True


def remove_manual_block(ip: str) -> None:
    blocked_manual.discard(ip)
    if ip not in blocked_ips:
        attack_table[ip]["blocked"] = False


def all_blocked() -> list[str]:
    return list(set(list(blocked_ips.keys()) + list(blocked_manual)))


# ── ML threshold ──────────────────────────────────────────────────────────────
ml_threshold: float = 0.70