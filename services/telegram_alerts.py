"""
services/telegram_alerts.py
────────────────────────────
Telegram alert notifications for ShieldSOC.
Inspired by Zabbix/Grafana Telegram integration.

Triggers:
  - CRITICAL or HIGH attack detected
  - IP blocked (auto or manual)
  - IP unblocked
  - Admin login (new session)
  - Failed login attempt
  - Platform startup

Setup:
  1. Create bot via @BotFather → get TOKEN
  2. Get your CHAT_ID via @userinfobot
  3. Add to .env:
       TELEGRAM_TOKEN=your_bot_token
       TELEGRAM_CHAT_ID=your_chat_id
       TELEGRAM_MIN_SEVERITY=HIGH   # LOW|MEDIUM|HIGH|CRITICAL
"""

import asyncio
import os
import time
import threading
from datetime import datetime

import httpx
from dotenv import load_dotenv
load_dotenv(override=True)

# ── Config from environment ───────────────────────────────────────────────────
TOKEN       = os.environ.get("TELEGRAM_TOKEN", "")
CHAT_ID     = os.environ.get("TELEGRAM_CHAT_ID", "")
MIN_SEV     = os.environ.get("TELEGRAM_MIN_SEVERITY", "HIGH")
ENABLED     = bool(TOKEN and CHAT_ID)

SEV_RANK    = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
API_URL     = f"https://api.telegram.org/bot{TOKEN}/sendMessage"

# ── Rate limiting — max 1 alert per 30s per alert type ───────────────────────
_last_sent: dict[str, float] = {}
RATE_LIMIT_SEC = 30


def _should_send(key: str) -> bool:
    now  = time.time()
    last = _last_sent.get(key, 0)
    if now - last < RATE_LIMIT_SEC:
        return False
    _last_sent[key] = now
    return True


# ── Send message ──────────────────────────────────────────────────────────────

async def _send(text: str) -> bool:
    if not ENABLED:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(API_URL, json={
                "chat_id":    CHAT_ID,
                "text":       text,
                "parse_mode": "HTML",
            })
            return r.status_code == 200
    except Exception as e:
        print(f"⚠️  Telegram error: {e}")
        return False


def send_sync(text: str) -> None:
    """Fire-and-forget from sync context."""
    if not ENABLED:
        return
    threading.Thread(
        target=lambda: asyncio.run(_send(text)),
        daemon=True
    ).start()


# ── Alert formatters ──────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def alert_attack(event: dict) -> None:
    """Send attack detection alert."""
    sev = event.get("severity", "LOW")
    if SEV_RANK.get(sev, 0) < SEV_RANK.get(MIN_SEV, 3):
        return

    attackers = event.get("attackers", [])
    if not attackers:
        return

    key = f"attack_{'_'.join(sorted(attackers))}"
    if not _should_send(key):
        return

    sev_emoji = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"
    }.get(sev, "⚪")

    prob  = event.get("attack_probability", 0)
    atype = event.get("attack_type", "UNKNOWN")
    pps   = event.get("pps", 0)
    pkts  = event.get("packets", 0)
    rule  = "✅ Rule" if event.get("rule_triggered") else "🤖 ML"

    ips = "\n".join(f"  <code>{ip}</code>" for ip in attackers)

    text = (
        f"{sev_emoji} <b>ShieldSOC — {sev} ATTACK</b>\n"
        f"─────────────────────\n"
        f"🕐 Time: <b>{_ts()}</b>\n"
        f"🎯 Type: <b>{atype}</b>\n"
        f"📊 Probability: <b>{prob:.1%}</b>\n"
        f"📦 Packets: <b>{pkts}</b> | PPS: <b>{pps:.0f}</b>\n"
        f"🔍 Detected by: {rule}\n"
        f"🌐 Attackers:\n{ips}\n"
        f"─────────────────────\n"
        f"<i>ShieldSOC · Astana IT University</i>"
    )
    send_sync(text)


def alert_ip_blocked(ip: str, duration: int, auto: bool = True) -> None:
    """Send IP block notification."""
    key = f"block_{ip}"
    if not _should_send(key):
        return

    mode = "🤖 Auto-block" if auto else "👤 Manual block"
    dur  = f"{duration}s" if duration > 0 else "permanent"

    text = (
        f"🧱 <b>ShieldSOC — IP Blocked</b>\n"
        f"─────────────────────\n"
        f"🕐 Time: <b>{_ts()}</b>\n"
        f"🚫 IP: <code>{ip}</code>\n"
        f"⏱ Duration: <b>{dur}</b>\n"
        f"📌 Method: {mode}\n"
        f"─────────────────────\n"
        f"<i>iptables DROP rule applied</i>"
    )
    send_sync(text)


def alert_ip_unblocked(ip: str, by: str = "auto") -> None:
    """Send IP unblock notification."""
    text = (
        f"✅ <b>ShieldSOC — IP Unblocked</b>\n"
        f"─────────────────────\n"
        f"🕐 Time: <b>{_ts()}</b>\n"
        f"🔓 IP: <code>{ip}</code>\n"
        f"📌 Reason: <b>{by}</b>\n"
    )
    send_sync(text)


def alert_login(username: str, ip: str, success: bool) -> None:
    """Send login notification — both success and failure."""
    if success:
        key = f"login_ok_{ip}"
        if not _should_send(key):
            return
        text = (
            f"🔐 <b>ShieldSOC — Admin Login</b>\n"
            f"─────────────────────\n"
            f"🕐 Time: <b>{_ts()}</b>\n"
            f"👤 User: <b>{username}</b>\n"
            f"🌐 From IP: <code>{ip}</code>\n"
            f"✅ Status: <b>Authenticated</b>\n"
        )
    else:
        key = f"login_fail_{ip}"
        if not _should_send(key):
            return
        text = (
            f"⚠️ <b>ShieldSOC — Failed Login</b>\n"
            f"─────────────────────\n"
            f"🕐 Time: <b>{_ts()}</b>\n"
            f"👤 User tried: <b>{username}</b>\n"
            f"🌐 From IP: <code>{ip}</code>\n"
            f"❌ Status: <b>Access Denied</b>\n"
        )
    send_sync(text)


def alert_startup() -> None:
    """Send platform startup notification."""
    text = (
        f"🚀 <b>ShieldSOC Started</b>\n"
        f"─────────────────────\n"
        f"🕐 Time: <b>{_ts()}</b>\n"
        f"🛡 Platform: <b>Online</b>\n"
        f"📡 Monitoring: <b>eth0</b>\n"
        f"🔒 Auth: <b>JWT enabled</b>\n"
        f"─────────────────────\n"
        f"<i>All systems operational</i>"
    )
    send_sync(text)


def alert_test() -> None:
    """Send test message to verify configuration."""
    text = (
        f"✅ <b>ShieldSOC — Test Alert</b>\n"
        f"─────────────────────\n"
        f"🕐 Time: <b>{_ts()}</b>\n"
        f"Telegram integration is working correctly.\n"
        f"Min severity: <b>{MIN_SEV}</b>\n"
        f"Rate limit: <b>{RATE_LIMIT_SEC}s</b>\n"
    )
    # Bypass rate limit for test
    asyncio.run(_send(text))


if ENABLED:
    print(f"✅ Telegram alerts: chat_id={CHAT_ID} | min_severity={MIN_SEV}")
else:
    print("ℹ️  Telegram alerts: disabled (set TELEGRAM_TOKEN + TELEGRAM_CHAT_ID in .env)")