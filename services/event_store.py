"""
services/event_store.py  — v3
──────────────────────────────
Enterprise-grade event storage inspired by Wazuh / Elastic Security / Splunk.

Architecture:
  Hot tier  : last 500 events in memory ring buffer (instant access)
  Warm tier : SQLite with full-text index (last 90 days default)
  Cold tier : compressed JSONL archives per day (older than 90 days)
  Export    : CEF, JSON Lines, Syslog-ready format

Features:
  - No MAX_EVENTS limit in DB — store everything, rotate by time not count
  - Tiered retention: hot (memory) → warm (SQLite) → cold (compressed archive)
  - Real-time aggregation windows: 1h, 24h, 7d cached stats
  - Alert deduplication: same IP + same type within 60s = one alert
  - CEF export format (ArcSight/Splunk compatible)
  - Automatic daily archiving of old records
  - DB health monitoring
"""

import gzip
import json
import os
import sqlite3
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from config import EVENTS_FILE

# ── Paths ─────────────────────────────────────────────────────────────────────
_BASE_DIR   = os.path.dirname(os.path.abspath(EVENTS_FILE))
DB_PATH     = os.path.join(_BASE_DIR, "shieldsoc.db")
ARCHIVE_DIR = os.path.join(_BASE_DIR, "archive")
os.makedirs(ARCHIVE_DIR, exist_ok=True)

# ── Tuning ────────────────────────────────────────────────────────────────────
HOT_TIER_SIZE       = 500    # events kept in memory
WARM_TIER_DAYS      = 90     # days kept in SQLite
DEDUP_WINDOW_SEC    = 60     # same IP+type within this window = skip duplicate
STATS_CACHE_TTL     = 30     # seconds before aggregation cache expires

# ── Thread safety ─────────────────────────────────────────────────────────────
_DB_LOCK  = threading.Lock()
_MEM_LOCK = threading.Lock()

# ── Hot tier ──────────────────────────────────────────────────────────────────
_hot: list[dict] = []

# ── Deduplication state ───────────────────────────────────────────────────────
# { "ip|attack_type" → last_seen_timestamp }
_dedup_cache: dict[str, float] = {}

# ── Aggregation cache ─────────────────────────────────────────────────────────
_stats_cache: dict[str, Any] = {}
_stats_ts: float = 0.0

# ── WebSocket connections ─────────────────────────────────────────────────────
connections: list[Any] = []


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory  = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")   # write-ahead log = faster writes
    c.execute("PRAGMA synchronous=NORMAL") # balance speed vs durability
    c.execute("PRAGMA cache_size=-8000")   # 8MB page cache
    return c


def _init_db() -> None:
    with _DB_LOCK:
        c = _conn()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   INTEGER NOT NULL,
                packets     INTEGER  DEFAULT 0,
                unique_src  INTEGER  DEFAULT 0,
                entropy     REAL     DEFAULT 0,
                pps         REAL     DEFAULT 0,
                bps         REAL     DEFAULT 0,
                attack_prob REAL     DEFAULT 0,
                decision    TEXT     DEFAULT 'normal',
                attack_type TEXT     DEFAULT 'normal',
                severity    TEXT     DEFAULT 'LOW',
                attackers   TEXT     DEFAULT '',
                shap_json   TEXT     DEFAULT '[]',
                rule_fired  INTEGER  DEFAULT 0,
                raw_json    TEXT     NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_ts       ON events (timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_decision ON events (decision);
            CREATE INDEX IF NOT EXISTS idx_severity ON events (severity);
            CREATE INDEX IF NOT EXISTS idx_ts_dec   ON events (timestamp DESC, decision);

            CREATE TABLE IF NOT EXISTS daily_stats (
                date        TEXT PRIMARY KEY,
                total       INTEGER DEFAULT 0,
                attacks     INTEGER DEFAULT 0,
                peak_pps    REAL    DEFAULT 0,
                top_attacker TEXT   DEFAULT '',
                updated_at  INTEGER DEFAULT 0
            );
        """)
        c.commit()

        # Load hot tier from DB
        rows = c.execute(
            "SELECT raw_json FROM events ORDER BY id DESC LIMIT ?",
            (HOT_TIER_SIZE,)
        ).fetchall()
        c.close()

    for row in reversed(rows):
        try:
            _hot.append(json.loads(row["raw_json"]))
        except Exception:
            pass

    count = _get_total_count()
    if count > 0:
        print(f"✅ ShieldSOC DB: {count:,} events loaded | "
              f"Hot tier: {len(_hot)} | DB: {DB_PATH}")


def _get_total_count() -> int:
    with _DB_LOCK:
        try:
            c = _conn()
            n = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            c.close()
            return n
        except Exception:
            return 0


def _write_to_db(event: dict) -> None:
    """Background DB write — called from daemon thread."""
    raw = json.dumps(event)
    with _DB_LOCK:
        try:
            c = _conn()
            c.execute("""
                INSERT INTO events
                    (timestamp, packets, unique_src, entropy, pps, bps,
                     attack_prob, decision, attack_type, severity,
                     attackers, shap_json, rule_fired, raw_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event.get("timestamp", int(time.time())),
                event.get("packets", 0),
                event.get("unique_src", 0),
                event.get("entropy", 0.0),
                event.get("pps", 0.0),
                event.get("bps", 0.0),
                event.get("attack_probability", 0.0),
                event.get("decision", "normal"),
                event.get("attack_type", "normal"),
                event.get("severity", "LOW"),
                "|".join(event.get("attackers", [])),
                json.dumps(event.get("shap_explanation", [])),
                1 if event.get("rule_triggered") else 0,
                raw,
            ))
            c.commit()
            c.close()
        except Exception as e:
            print(f"⚠️  DB write error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# DEDUPLICATION  (like Elastic Security alert dedup)
# ═══════════════════════════════════════════════════════════════════════════════

def _is_duplicate(event: dict) -> bool:
    """
    Returns True if this is a near-duplicate alert.
    Same attackers + same attack_type within DEDUP_WINDOW_SEC → duplicate.
    Only applied to attack events to avoid suppressing normal windows.
    """
    if event.get("decision") != "attack":
        return False

    attackers = sorted(event.get("attackers", []))
    atype     = event.get("attack_type", "")
    key       = "|".join(attackers) + "§" + atype
    now       = time.time()

    last = _dedup_cache.get(key, 0)
    if now - last < DEDUP_WINDOW_SEC:
        return True

    _dedup_cache[key] = now
    # Evict stale dedup entries
    stale = [k for k, t in _dedup_cache.items() if now - t > DEDUP_WINDOW_SEC * 2]
    for k in stale:
        del _dedup_cache[k]
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def save_event(event: dict) -> None:
    """
    Save event through full pipeline:
    1. Hot tier (memory)
    2. Dedup check — skip DB write if duplicate attack
    3. SQLite (async background thread)
    4. JSONL (legacy compatibility)
    """
    # Hot tier
    with _MEM_LOCK:
        _hot.append(event)
        if len(_hot) > HOT_TIER_SIZE:
            _hot.pop(0)

    # Deduplicate attack alerts before persisting
    if not _is_duplicate(event):
        threading.Thread(
            target=_write_to_db, args=(event,), daemon=True
        ).start()

        # JSONL legacy
        try:
            with open(EVENTS_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass


def get_events() -> list[dict]:
    """Return hot tier (in-memory) events — fast path."""
    with _MEM_LOCK:
        return list(_hot)


def get_events_from_db(
    limit:    int         = 500,
    decision: str | None  = None,
    severity: str | None  = None,
    since:    int | None  = None,
    until:    int | None  = None,
    attacker: str | None  = None,
) -> list[dict]:
    """
    Query SQLite with filters.
    Equivalent to Elastic's query DSL but simpler.
    """
    clauses: list[str] = []
    params:  list      = []

    if decision:
        clauses.append("decision = ?");   params.append(decision)
    if severity:
        clauses.append("severity = ?");   params.append(severity)
    if since:
        clauses.append("timestamp >= ?"); params.append(since)
    if until:
        clauses.append("timestamp <= ?"); params.append(until)
    if attacker:
        clauses.append("attackers LIKE ?"); params.append(f"%{attacker}%")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)

    with _DB_LOCK:
        try:
            c    = _conn()
            rows = c.execute(
                f"SELECT raw_json FROM events {where} ORDER BY id DESC LIMIT ?",
                params,
            ).fetchall()
            c.close()
            return [json.loads(r["raw_json"]) for r in rows]
        except Exception as e:
            print(f"⚠️  DB read error: {e}")
            return []


# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATION  (like Elastic SIEM dashboards)
# ═══════════════════════════════════════════════════════════════════════════════

def get_aggregated_stats() -> dict:
    """
    Pre-aggregated stats for dashboard — cached for STATS_CACHE_TTL seconds.
    Covers 1h, 24h, 7d windows — like Wazuh's security events summary.
    """
    global _stats_cache, _stats_ts
    now = time.time()

    if now - _stats_ts < STATS_CACHE_TTL and _stats_cache:
        return _stats_cache

    windows = {
        "1h":  int(now) - 3600,
        "24h": int(now) - 86400,
        "7d":  int(now) - 604800,
    }

    result: dict[str, Any] = {}
    with _DB_LOCK:
        try:
            c = _conn()
            for label, since in windows.items():
                row = c.execute("""
                    SELECT
                        COUNT(*)                              AS total,
                        SUM(decision='attack')                AS attacks,
                        MAX(pps)                              AS peak_pps,
                        MAX(packets)                          AS peak_pkts,
                        AVG(attack_prob)                      AS avg_prob
                    FROM events
                    WHERE timestamp >= ?
                """, (since,)).fetchone()

                # Top attacker in window
                top = c.execute("""
                    SELECT attackers, COUNT(*) as cnt
                    FROM events
                    WHERE timestamp >= ? AND decision='attack' AND attackers != ''
                    GROUP BY attackers ORDER BY cnt DESC LIMIT 1
                """, (since,)).fetchone()

                # Attack type breakdown
                types = c.execute("""
                    SELECT attack_type, COUNT(*) as cnt
                    FROM events
                    WHERE timestamp >= ? AND decision='attack'
                    GROUP BY attack_type ORDER BY cnt DESC
                """, (since,)).fetchall()

                result[label] = {
                    "total":       row["total"] or 0,
                    "attacks":     row["attacks"] or 0,
                    "normal":      (row["total"] or 0) - (row["attacks"] or 0),
                    "peak_pps":    round(row["peak_pps"] or 0, 2),
                    "peak_pkts":   row["peak_pkts"] or 0,
                    "avg_prob":    round(row["avg_prob"] or 0, 3),
                    "top_attacker": (top["attackers"].split("|")[0]
                                     if top else "—"),
                    "attack_types": {r["attack_type"]: r["cnt"]
                                     for r in types},
                }
            c.close()
        except Exception as e:
            print(f"⚠️  Aggregation error: {e}")
            return {}

    _stats_cache = result
    _stats_ts    = now
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# RETENTION  (like Splunk's hot/warm/cold/frozen tiers)
# ═══════════════════════════════════════════════════════════════════════════════

def run_retention_policy() -> dict:
    """
    Tiered retention:
    - Warm tier (SQLite): keep last WARM_TIER_DAYS days
    - Cold tier: compress older records to daily .jsonl.gz archives
    - Returns stats on what was archived/deleted
    """
    now      = int(time.time())
    cutoff   = now - WARM_TIER_DAYS * 86400
    archived = 0
    deleted  = 0

    with _DB_LOCK:
        try:
            c = _conn()

            # Fetch records to archive (older than warm tier)
            old_rows = c.execute(
                "SELECT timestamp, raw_json FROM events WHERE timestamp < ? ORDER BY timestamp",
                (cutoff,)
            ).fetchall()

            if old_rows:
                # Group by date and write compressed archives
                by_date: dict[str, list] = defaultdict(list)
                for row in old_rows:
                    date = datetime.utcfromtimestamp(row["timestamp"]).strftime("%Y-%m-%d")
                    by_date[date].append(row["raw_json"])

                for date, records in by_date.items():
                    archive_path = os.path.join(ARCHIVE_DIR, f"{date}.jsonl.gz")
                    # Append to existing archive if it exists
                    mode = "ab" if os.path.exists(archive_path) else "wb"
                    with gzip.open(archive_path, mode) as gz:
                        for rec in records:
                            gz.write((rec + "\n").encode())
                    archived += len(records)

                # Delete archived records from warm tier
                c.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
                deleted = c.execute("SELECT changes()").fetchone()[0]
                c.commit()
                c.execute("VACUUM")  # reclaim space

            c.close()
        except Exception as e:
            print(f"⚠️  Retention error: {e}")

    print(f"✅ Retention: archived {archived} → cold, deleted {deleted} from warm tier")
    return {"archived": archived, "deleted": deleted, "cutoff_days": WARM_TIER_DAYS}


def get_db_stats() -> dict:
    """Full storage stats — shown on settings page."""
    with _DB_LOCK:
        try:
            c = _conn()
            total   = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            attacks = c.execute(
                "SELECT COUNT(*) FROM events WHERE decision='attack'"
            ).fetchone()[0]
            oldest  = c.execute("SELECT MIN(timestamp) FROM events").fetchone()[0]
            newest  = c.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
            c.close()

            db_kb  = os.path.getsize(DB_PATH) // 1024 if os.path.exists(DB_PATH) else 0
            arc_kb = sum(
                os.path.getsize(os.path.join(ARCHIVE_DIR, f))
                for f in os.listdir(ARCHIVE_DIR)
                if f.endswith(".jsonl.gz")
            ) // 1024 if os.path.exists(ARCHIVE_DIR) else 0

            archives = [f for f in os.listdir(ARCHIVE_DIR) if f.endswith(".jsonl.gz")]

            return {
                "total_events":   total,
                "attack_events":  attacks,
                "normal_events":  total - attacks,
                "hot_tier":       len(_hot),
                "warm_tier":      total,
                "cold_tier":      len(archives),
                "oldest_ts":      oldest,
                "newest_ts":      newest,
                "db_size_kb":     db_kb,
                "archive_size_kb": arc_kb,
                "warm_tier_days": WARM_TIER_DAYS,
                "dedup_window_s": DEDUP_WINDOW_SEC,
            }
        except Exception:
            return {}


def clear_old_events(days: int = 30) -> int:
    """Manually delete events older than N days (without archiving)."""
    cutoff = int(time.time()) - days * 86400
    with _DB_LOCK:
        try:
            c = _conn()
            c.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            deleted = c.execute("SELECT changes()").fetchone()[0]
            c.commit()
            c.close()
            return deleted
        except Exception:
            return 0


# ═══════════════════════════════════════════════════════════════════════════════
# CEF EXPORT  (ArcSight / Splunk compatible)
# ═══════════════════════════════════════════════════════════════════════════════

def export_cef(limit: int = 1000) -> str:
    """
    Export events in Common Event Format (CEF).
    Compatible with: Splunk, IBM QRadar, ArcSight, Elastic SIEM.

    Format:
    CEF:0|ShieldSOC|DDoS-Detector|1.0|<type>|<name>|<severity>|<extensions>
    """
    sev_map = {"CRITICAL": "10", "HIGH": "7", "MEDIUM": "5", "LOW": "3"}
    events  = get_events_from_db(limit=limit, decision="attack")
    lines   = []

    for e in events:
        ts      = e.get("timestamp", 0)
        atype   = e.get("attack_type", "UNKNOWN")
        sev     = e.get("severity", "LOW")
        attackers = e.get("attackers", [])
        prob    = e.get("attack_probability", 0)
        pps     = e.get("pps", 0)

        ext = (
            f"rt={ts * 1000} "
            f"src={attackers[0] if attackers else 'unknown'} "
            f"dst=192.168.20.8 "
            f"cs1={prob:.3f} cs1Label=MLProbability "
            f"cs2={pps:.1f} cs2Label=PacketsPerSec "
            f"cs3={atype} cs3Label=AttackType "
            f"cnt={len(attackers)}"
        )

        line = (
            f"CEF:0|ShieldSOC|DDoS-Detector|1.0|{atype}|"
            f"DDoS Attack Detected|{sev_map.get(sev, '5')}|{ext}"
        )
        lines.append(line)

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET
# ═══════════════════════════════════════════════════════════════════════════════

def register(ws: Any) -> None:
    if ws not in connections:
        connections.append(ws)


def unregister(ws: Any) -> None:
    if ws in connections:
        connections.remove(ws)


async def broadcast(event: dict) -> None:
    dead: list[Any] = []
    for ws in connections:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        unregister(ws)


# ═══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════════════════════════════════════════
_init_db()