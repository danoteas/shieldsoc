"""
main.py — v9
─────────────
Changes v3+v4:
1. Real IP geolocation via ip-api.com with local in-memory cache
2. Fallback to deterministic MD5 coords for private/local IPs
3. map_points is now async with proper count tracking
4. httpx used for async HTTP requests (pip install httpx)
"""

import asyncio
import csv
import hashlib
import io
import ipaddress
import threading
import time
from contextlib import asynccontextmanager

from services.telegram_alerts import (
    alert_login, alert_ip_blocked,
    alert_ip_unblocked, alert_startup, alert_test
)
from auth import (
    check_credentials, create_token, verify_token,
    require_auth, change_password, get_username, TOKEN_TTL_SEC
)

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, status
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdf_canvas

import shared_state as state
from detector.detector_engine import start_detector
from services.event_store import (
    get_events, get_events_from_db,
    get_db_stats, get_aggregated_stats,
    clear_old_events, run_retention_policy,
    export_cef, register, unregister
)
from services.mitigation import block_ip_manual, get_blocked, unblock_ip_manual
from services.session_engine import (
    get_active_sessions,
    get_all_sessions,
    get_session_by_id,
)

# ── Geo cache ─────────────────────────────────────────────────────────────────
# Stores geolocation results per IP — never expires (IPs don't move)
_geo_cache: dict[str, dict] = {}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False

def _fallback_coords(ip: str) -> dict:
    """Deterministic fake coords for private/unknown IPs."""
    h = hashlib.md5(ip.encode()).digest()
    return {
        "lat":     round((h[0] * 256 + h[1]) % 181 - 90, 4),
        "lon":     round((h[2] * 256 + h[3]) % 361 - 180, 4),
        "country": "Private Network",
        "city":    "",
        "isp":     "Local",
    }

async def _geolocate(ip: str) -> dict:
    """
    Lookup IP via ip-api.com (free tier: 45 req/min).
    Results cached in memory — same IP never queried twice.
    Private IPs get deterministic fake coords immediately.
    """
    if ip in _geo_cache:
        return _geo_cache[ip]

    if _is_private(ip):
        result = _fallback_coords(ip)
        _geo_cache[ip] = result
        return result

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,lat,lon,country,city,isp,query"}
            )
            data = r.json()
            if data.get("status") == "success":
                result = {
                    "lat":     data.get("lat", 0),
                    "lon":     data.get("lon", 0),
                    "country": data.get("country", "Unknown"),
                    "city":    data.get("city", ""),
                    "isp":     data.get("isp", ""),
                }
                _geo_cache[ip] = result
                return result
    except Exception:
        pass

    result = _fallback_coords(ip)
    _geo_cache[ip] = result
    return result


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_event_loop()
    t = threading.Thread(
        target=start_detector, args=(loop,), daemon=True, name="detector"
    )
    t.start()
    alert_startup()
    yield


app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Auth pages & endpoints ────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
def login_page():
    with open("templates/login.html") as f:
        return HTMLResponse(f.read())


@app.post("/api/auth/login")
async def api_login(request: Request):
    """Validate credentials, set JWT cookie."""
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")

    if not check_credentials(username, password):
        client_ip = request.client.host if request.client else "unknown"
        alert_login(username, client_ip, success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    token    = create_token(username)
    client_ip = request.client.host if request.client else "unknown"
    alert_login(username, client_ip, success=True)
    response = JSONResponse({"token": token, "username": username})
    response.set_cookie(
        key="shieldsoc_token",
        value=token,
        httponly=True,         # JS cannot read — XSS protection
        samesite="lax",
        max_age=TOKEN_TTL_SEC,
    )
    return response


@app.post("/api/auth/logout")
def api_logout():
    """Clear auth cookie."""
    response = JSONResponse({"status": "logged_out"})
    response.delete_cookie("shieldsoc_token")
    return response


@app.get("/api/auth/me")
def api_me(user: str = Depends(require_auth)):
    """Return current authenticated user info."""
    return {"username": user, "role": "analyst"}


@app.post("/api/auth/change-password")
async def api_change_password(
    request: Request,
    user: str = Depends(require_auth)
):
    body = await request.json()
    ok, msg = change_password(
        body.get("old_password", ""),
        body.get("new_password", "")
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "ok", "message": msg}


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = Depends(require_auth)):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/analytics", response_class=HTMLResponse)
def analytics_page(request: Request, user: str = Depends(require_auth)):
    return templates.TemplateResponse("analytics.html", {"request": request})

@app.get("/map", response_class=HTMLResponse)
def attack_map(request: Request, user: str = Depends(require_auth)):
    return templates.TemplateResponse("map.html", {"request": request})

@app.get("/history", response_class=HTMLResponse)
def history_page(request: Request, user: str = Depends(require_auth)):
    return templates.TemplateResponse("history.html", {"request": request})

@app.get("/intelligence", response_class=HTMLResponse)
def intelligence_page(request: Request, user: str = Depends(require_auth)):
    return templates.TemplateResponse("intelligence.html", {"request": request})

@app.get("/sessions", response_class=HTMLResponse)
def sessions_page(request: Request, user: str = Depends(require_auth)):
    return templates.TemplateResponse("sessions.html", {"request": request})

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: str = Depends(require_auth)):
    return templates.TemplateResponse("settings.html", {"request": request})




# ── Core data API ─────────────────────────────────────────────────────────────

@app.get("/api/events")
def api_events(user: str = Depends(require_auth)):
    return get_events()


@app.get("/api/traffic_series")
def traffic_series(user: str = Depends(require_auth)):
    data = get_events()[-100:]
    return {
        "timestamps": [e.get("timestamp", 0)          for e in data],
        "pps":        [e.get("pps", 0)                for e in data],
        "bps":        [e.get("bps", 0)                for e in data],
        "entropy":    [e.get("entropy", 0)             for e in data],
        "prob":       [e.get("attack_probability", 0)  for e in data],
        "packets":    [e.get("packets", 0)             for e in data],
    }


@app.get("/api/attack_distribution")
def attack_distribution(user: str = Depends(require_auth)):
    dist: dict[str, int] = {}
    for e in get_events():
        t = e.get("attack_type", "unknown")
        if t != "normal":
            dist[t] = dist.get(t, 0) + 1
    return dist


@app.get("/api/attacker_ranking")
def attacker_ranking(user: str = Depends(require_auth)):
    ranking: dict[str, int] = {}
    for e in get_events():
        for ip in e.get("attackers", []):
            ranking[ip] = ranking.get(ip, 0) + 1
    return sorted(ranking.items(), key=lambda x: x[1], reverse=True)[:10]


@app.get("/api/map_points")
async def map_points(user: str = Depends(require_auth)):
    """
    Real geolocation via ip-api.com with in-memory cache.
    Private IPs get deterministic fake coords (for local test network).
    Each attacker IP appears once with highest observed severity.
    """
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    # Aggregate: best severity + total count per IP
    ip_meta: dict[str, dict] = {}
    for e in get_events()[-200:]:
        for ip in e.get("attackers", []):
            sev = e.get("severity", "LOW")
            if ip not in ip_meta:
                ip_meta[ip] = {
                    "severity": sev,
                    "packets":  e.get("packets", 0),
                    "count":    1,
                }
            else:
                ip_meta[ip]["count"] += 1
                if severity_rank.get(sev, 0) > \
                   severity_rank.get(ip_meta[ip]["severity"], 0):
                    ip_meta[ip]["severity"] = sev
                    ip_meta[ip]["packets"]  = e.get("packets", 0)

    # Geolocate all unique IPs concurrently
    points = []
    if ip_meta:
        geo_results = await asyncio.gather(
            *[_geolocate(ip) for ip in ip_meta]
        )
        for ip, geo in zip(ip_meta.keys(), geo_results):
            meta = ip_meta[ip]
            points.append({
                "ip":       ip,
                "lat":      geo["lat"],
                "lon":      geo["lon"],
                "country":  geo["country"],
                "city":     geo["city"],
                "isp":      geo["isp"],
                "severity": meta["severity"],
                "packets":  meta["packets"],
                "count":    meta["count"],
            })

    return points


@app.get("/api/history")
def history_api(
    page: int = 1,
    size: int = 25,
    decision: str | None = None,
    severity: str | None = None,
):
    batch = get_events_from_db(limit=10000, decision=decision, severity=severity)
    total = len(batch)
    start = (page - 1) * size
    return {"total": total, "events": batch[start: start + size]}


@app.get("/api/db/stats")
def db_stats(user: str = Depends(require_auth)):
    return get_db_stats()


@app.post("/api/db/cleanup")
async def db_cleanup(request: Request):
    body = await request.json()
    days = int(body.get("days", 30))
    days = max(1, min(365, days))
    deleted = clear_old_events(days)
    return {"deleted": deleted, "days": days}


# ── Session API ───────────────────────────────────────────────────────────────

@app.get("/api/sessions")
def api_sessions(user: str = Depends(require_auth)):
    return get_all_sessions()

@app.get("/api/sessions/active")
def api_active_sessions(user: str = Depends(require_auth)):
    return get_active_sessions()

@app.get("/api/sessions/{session_id}/report")
def session_report(session_id: str):
    session = get_session_by_id(session_id)
    if not session:
        return {"error": "Session not found"}

    buf = io.BytesIO()
    c   = pdf_canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, h - 55, f"ATTACK REPORT — Session #{session['session_id']}")
    c.setFont("Helvetica", 9)
    c.setFillColorRGB(0.5, 0.5, 0.5)
    c.drawString(50, h - 72, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(50, h - 84, "ShieldSOC — DDoS Detection Platform")
    c.setFillColorRGB(0, 0, 0)
    c.line(50, h - 95, w - 50, h - 95)

    y = h - 120
    fields = [
        ("Attack Type",   session.get("attack_type", "—")),
        ("Severity",      session.get("severity",    "—")),
        ("Status",        session.get("status",      "—")),
        ("Start Time",    time.strftime(
                              "%Y-%m-%d %H:%M:%S",
                              time.localtime(session.get("start_time", 0)))),
        ("End Time",      time.strftime(
                              "%Y-%m-%d %H:%M:%S",
                              time.localtime(session.get("end_time", 0)))),
        ("Duration",      f"{round(session.get('duration', 0))} seconds"),
        ("Peak PPS",      str(round(session.get("peak_pps", 0), 2))),
        ("Total Packets", str(session.get("total_packets", 0))),
        ("Avg ML Prob",   str(round(session.get("avg_probability", 0), 3))),
        ("Event Count",   str(session.get("event_count", 0))),
        ("Attackers",     ", ".join(session.get("attackers", []))),
    ]

    for label, value in fields:
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, f"{label}:")
        c.setFont("Helvetica", 10)
        c.drawString(200, y, str(value))
        y -= 20

    y -= 10
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y, "Mitigation Actions")
    y -= 5
    c.line(50, y, w - 50, y)
    y -= 15
    c.setFont("Helvetica", 10)
    c.drawString(60, y, "• Automatic IP block via iptables")
    y -= 25

    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y, "Recommendations")
    y -= 5
    c.line(50, y, w - 50, y)
    y -= 15
    c.setFont("Helvetica", 10)
    for rec in [
        "Review firewall rules and tighten rate-limiting thresholds.",
        "Consider permanent block for repeat offender IPs.",
        "Enable SYN cookie protection on the host.",
        "Notify upstream provider if attack exceeded 1 Gbps.",
        "Schedule post-incident review within 24 hours.",
    ]:
        c.drawString(60, y, f"• {rec}")
        y -= 15

    c.save()
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                f'attachment; filename="report_{session_id}.pdf"'
        },
    )


# ── Export ────────────────────────────────────────────────────────────────────

@app.get("/api/events/export")
def export_events_csv(user: str = Depends(require_auth)):
    events = get_events()
    buf    = io.StringIO()
    if events:
        flat = []
        for e in events:
            row = dict(e)
            row["attackers"]        = "|".join(e.get("attackers", []))
            row["shap_explanation"] = str(e.get("shap_explanation", []))
            row.pop("scores", None)
            flat.append(row)
        writer = csv.DictWriter(buf, fieldnames=flat[0].keys())
        writer.writeheader()
        writer.writerows(flat)
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )


# ── Mitigation API ────────────────────────────────────────────────────────────

@app.post("/api/block/{ip}")
def api_block(ip: str, user: str = Depends(require_auth)):
    result = block_ip_manual(ip)
    if result.get("status") == "blocked":
        alert_ip_blocked(ip, duration=0, auto=False)
    return result

@app.post("/api/unblock/{ip}")
def api_unblock(ip: str, user: str = Depends(require_auth)):
    result = unblock_ip_manual(ip)
    alert_ip_unblocked(ip, by="manual")
    return result

@app.get("/api/blocked")
def api_blocked(user: str = Depends(require_auth)):
    return {"blocked": get_blocked()}


# ── Config API ────────────────────────────────────────────────────────────────

@app.get("/api/config/threshold")
def get_threshold(user: str = Depends(require_auth)):
    return {"threshold": state.ml_threshold}

@app.post("/api/config/threshold")
async def set_threshold(request: Request):
    body = await request.json()
    t    = float(body.get("threshold", 0.70))
    t    = max(0.50, min(0.95, t))
    state.ml_threshold = t
    return {"threshold": state.ml_threshold}



# ── Whitelist API ─────────────────────────────────────────────────────────────

@app.get("/api/whitelist")
def get_whitelist(user: str = Depends(require_auth)):
    return {"whitelist": state.get_whitelist()}

@app.post("/api/whitelist/{ip}")
def add_whitelist(ip: str, user: str = Depends(require_auth)):
    import re
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"status": "error", "message": "Invalid IP format"}
    added = state.add_to_whitelist(ip)
    if added:
        return {"status": "added", "ip": ip}
    return {"status": "already_exists", "ip": ip}

@app.delete("/api/whitelist/{ip}")
def remove_whitelist(ip: str, user: str = Depends(require_auth)):
    success, reason = state.remove_from_whitelist(ip)
    if success:
        return {"status": "removed", "ip": ip}
    return {"status": "error", "message": reason}


# ── Aggregated stats API ──────────────────────────────────────────────────────

@app.get("/api/stats/aggregated")
def aggregated_stats(user: str = Depends(require_auth)):
    """Pre-aggregated 1h/24h/7d stats — like Wazuh security summary."""
    return get_aggregated_stats()


# ── Export API ────────────────────────────────────────────────────────────────

@app.get("/api/events/export/cef")
def export_cef_endpoint(user: str = Depends(require_auth)):
    """Export attack events in CEF format (Splunk/QRadar compatible)."""
    cef = export_cef(limit=1000)
    return StreamingResponse(
        iter([cef]),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=shieldsoc_events.cef"}
    )


# ── Retention API ─────────────────────────────────────────────────────────────

@app.post("/api/db/retention")
def run_retention(user: str = Depends(require_auth)):
    """Manually trigger retention policy — archive old events to cold storage."""
    result = run_retention_policy()
    return result




@app.get("/api/telegram/status")
def telegram_status(user: str = Depends(require_auth)):
    from services.telegram_alerts import ENABLED, MIN_SEV, CHAT_ID
    return {
        "enabled":      ENABLED,
        "min_severity": MIN_SEV,
        "chat_id":      CHAT_ID[-4:].rjust(8, "*") if CHAT_ID else "",
    }

@app.post("/api/telegram/test")
def telegram_test(user: str = Depends(require_auth)):
    """Send test Telegram message to verify integration."""
    from services.telegram_alerts import alert_test, ENABLED
    if not ENABLED:
        return {"status": "disabled", "message": "Set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID in .env"}
    alert_test()
    return {"status": "sent"}


# ── Global search API ─────────────────────────────────────────────────────────

@app.get("/api/search")
def global_search(
    q: str,
    limit: int = 8,
    user: str = Depends(require_auth)
):
    """
    Search across events, blocked IPs, attack sessions.
    Returns unified results for global search bar.
    """
    from services.event_store import get_events_from_db
    import time

    q_lower = q.strip().lower()
    results = []

    # Search events by IP, attack type
    events = get_events_from_db(limit=200, decision="attack")
    seen   = set()
    for e in events:
        attackers = e.get("attackers", [])
        atype     = e.get("attack_type", "")
        ts        = e.get("timestamp", 0)
        sev       = e.get("severity", "LOW")

        for ip in attackers:
            if q_lower in ip.lower() or q_lower in atype.lower():
                key = f"{ip}_{atype}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "label":    ip,
                        "type":     atype,
                        "severity": sev,
                        "time":     time.strftime("%H:%M %d/%m", time.localtime(ts)),
                        "url":      f"/history?attacker={ip}",
                    })
        if len(results) >= limit:
            break

    # Search blocked IPs
    from shared_state import all_blocked
    for ip in all_blocked():
        if q_lower in ip.lower():
            results.append({
                "label":    ip,
                "type":     "BLOCKED IP",
                "severity": "HIGH",
                "time":     "active",
                "url":      "/",
            })

    return {"results": results[:limit], "query": q}



# ── AI Assistant API ──────────────────────────────────────────────────────────

@app.post("/api/ai/chat")
async def ai_chat(request: Request, user: str = Depends(require_auth)):
    """Real AI Security Assistant powered by DeepSeek."""
    import os as _os
    body = await request.json()
    question = body.get("message", "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="Empty message")

    api_key = _os.getenv("DEEPSEEK_API_KEY", "")
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="DEEPSEEK_API_KEY not set in .env file"
        )

    events  = get_events()
    attacks = [e for e in events if e.get("decision") == "attack"]

    ip_count = {}
    for e in attacks:
        for ip in e.get("attackers", []):
            ip_count[ip] = ip_count.get(ip, 0) + 1
    top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]

    type_dist = {}
    for e in attacks:
        t = e.get("attack_type", "unknown")
        type_dist[t] = type_dist.get(t, 0) + 1

    shap_events = [e for e in attacks if e.get("shap_explanation")]
    last_shap = shap_events[-1].get("shap_explanation", [])[:5] if shap_events else []

    blocked = get_blocked()

    recent_severities = {}
    for e in attacks[-50:]:
        sev = e.get("severity", "LOW")
        recent_severities[sev] = recent_severities.get(sev, 0) + 1

    system_prompt = """You are a professional cybersecurity AI assistant embedded in ShieldSOC — a real-time DDoS detection and mitigation platform.

PLATFORM: ShieldSOC v1.0 — Astana IT University, 2025
DETECTION ENGINE: XGBoost ML + 7 Snort-style rules + MITRE ATT&CK mapping
MITIGATION: Automated iptables blocking

LIVE PLATFORM DATA (right now):
- Total session events: {total}
- Attack events: {attacks}
- Currently blocked IPs: {blocked_n} — [{blocked_list}]
- ML threshold: {threshold}

TOP ATTACKERS:
{top_ips}

ATTACK DISTRIBUTION:
{type_dist}

SEVERITY BREAKDOWN (last 50 attacks):
{severities}

LATEST SHAP FEATURE CONTRIBUTIONS:
{shap}

Your role:
- Answer security questions using the live data above
- Provide specific, actionable recommendations
- Explain ML decisions using SHAP values when relevant
- Suggest mitigation strategies based on detected attack patterns
- Be concise (under 200 words) unless detailed analysis is requested
- Never make up data — use only what is provided above""".format(
        total=len(events),
        attacks=len(attacks),
        blocked_n=len(blocked),
        blocked_list=", ".join(blocked[:5]) if blocked else "none",
        threshold=state.ml_threshold,
        top_ips="\n".join(f"  {ip}: {n} events" for ip, n in top_ips) if top_ips else "  None",
        type_dist="\n".join(f"  {t}: {n}" for t, n in type_dist.items()) if type_dist else "  None",
        severities="\n".join(f"  {s}: {n}" for s, n in recent_severities.items()) if recent_severities else "  None",
        shap="\n".join(f"  {feat}: {val:+.4f}" for feat, val in last_shap) if last_shap else "  No SHAP data",
    )

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.deepseek.com/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "deepseek-chat",
                    "max_tokens": 512,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": question},
                    ],
                }
            )
            data = resp.json()
            if resp.status_code != 200:
                err = data.get("error", {}).get("message", "DeepSeek API error")
                raise HTTPException(status_code=502, detail=err)
            answer = data["choices"][0]["message"]["content"]
            return {"response": answer, "status": "ok"}
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="AI response timed out (30s)")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


# ── Network Snapshot API ──────────────────────────────────────────────────────
# Best practice: used by Cisco Stealthwatch, Darktrace, Vectra AI
# Captures point-in-time traffic baseline for before/after attack comparison

_snapshots = []

@app.post("/api/snapshot")
async def take_snapshot(request: Request, user: str = Depends(require_auth)):
    """Capture current network traffic snapshot with label (before/during/after)."""
    body = await request.json()
    label = (body.get("label") or "snapshot").strip()

    events  = get_events()
    recent  = events[-20:] if events else []
    attacks = [e for e in recent if e.get("decision") == "attack"]

    def avg(lst):
        return round(sum(lst) / len(lst), 3) if lst else 0

    ip_count = {}
    for e in attacks:
        for ip in e.get("attackers", []):
            ip_count[ip] = ip_count.get(ip, 0) + 1

    type_dist = {}
    for e in attacks:
        t = e.get("attack_type", "unknown")
        type_dist[t] = type_dist.get(t, 0) + 1

    snap = {
        "id":            int(time.time()),
        "label":         label,
        "timestamp":     time.time(),
        "time_str":      time.strftime("%Y-%m-%d %H:%M:%S"),
        "pps_avg":       avg([e.get("pps", 0) for e in recent]),
        "bps_avg":       avg([e.get("bps", 0) for e in recent]),
        "entropy_avg":   avg([e.get("entropy", 0) for e in recent]),
        "packet_avg":    avg([e.get("packets", 0) for e in recent]),
        "prob_avg":      avg([e.get("attack_probability", 0) for e in recent]),
        "attack_count":  len(attacks),
        "normal_count":  len(recent) - len(attacks),
        "top_attackers": sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5],
        "attack_types":  type_dist,
        "blocked_count": len(get_blocked()),
        "event_count":   len(recent),
    }

    _snapshots.append(snap)
    if len(_snapshots) > 20:
        _snapshots.pop(0)

    return {"status": "ok", "snapshot": snap}


@app.get("/api/snapshots")
def get_snapshots_api(user: str = Depends(require_auth)):
    return {"snapshots": _snapshots}


@app.delete("/api/snapshots")
def clear_snapshots(user: str = Depends(require_auth)):
    _snapshots.clear()
    return {"status": "cleared"}


@app.get("/api/snapshots/compare")
def compare_snapshots(
    id1: int,
    id2: int,
    user: str = Depends(require_auth)
):
    s1 = next((s for s in _snapshots if s["id"] == id1), None)
    s2 = next((s for s in _snapshots if s["id"] == id2), None)
    if not s1 or not s2:
        raise HTTPException(status_code=404, detail="Snapshot(s) not found")

    def delta(key):
        v1, v2 = s1.get(key, 0), s2.get(key, 0)
        diff = round(v2 - v1, 3)
        pct  = round(diff / v1 * 100, 1) if v1 else 0
        return {"before": v1, "after": v2, "delta": diff, "pct": pct}

    return {
        "before_label":  s1["label"],
        "after_label":   s2["label"],
        "before_time":   s1["time_str"],
        "after_time":    s2["time_str"],
        "pps":           delta("pps_avg"),
        "bps":           delta("bps_avg"),
        "entropy":       delta("entropy_avg"),
        "prob":          delta("prob_avg"),
        "attacks":       delta("attack_count"),
        "blocked":       delta("blocked_count"),
    }


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    register(ws)
    try:
        while True:
            await ws.receive_text()
    except Exception:
        pass
    finally:
        unregister(ws)