"""
detector/detector_engine.py  — v8
──────────────────────────────────
Changes v6+v7:
1. Rule-based detection layer (Snort-style) alongside ML
   Rules fire independently — attack declared even if ML prob is low
   Each rule has a name, condition, score bonus, and forced attack type
2. Buffer size cap — max 50,000 entries to prevent memory growth
3. rule_triggered field added to event for dashboard transparency
4. Cleaner detection pipeline: rules → ML → combined decision
"""

import asyncio
import math
import subprocess
import threading
import time
import socket

import joblib
import numpy as np
import pandas as pd
import shap
from collections import Counter

import shared_state as state
from config import (
    ATTACK_SCORE_THRESHOLD,
    BASE_BLOCK_TIME,
    MIN_PACKETS,
    MODEL_PATH,
    SCORE_DECAY,
    STALE_IP_TIMEOUT,
    WINDOW_SIZE,
)
from services.event_store import broadcast, save_event
from services.telegram_alerts import alert_attack, alert_ip_blocked
from services.session_engine import update_sessions

# ── Settings ──────────────────────────────────────────────────────────────────
INTERFACE   = "eth0"
VICTIM_IP   = "192.168.20.8"
BUFFER_CAP  = 50_000   # max packets in buffer — prevents memory growth

PLATFORM_FEATURES = [
    "pps", "packets", "entropy", "unique", "burst_index",
    "packets_ma", "entropy_ma", "entropy_delta",
    "unique_ratio", "packets_ratio"
]

# ── Rule-based detection layer ────────────────────────────────────────────────
# Each rule: (name, condition_fn, score_bonus, forced_attack_type)
# condition_fn receives: (pps, bps, entropy, unique_src, packets, burst_index, dominant_ratio)
# Returns True if rule fires
#
# These rules fire REGARDLESS of ML probability.
# If any rule fires → decision forced to "attack" + score_bonus applied to all IPs in window.

RULES = [
    (
        "SYN_FLOOD_HIGH_PPS",
        lambda pps, bps, ent, uniq, pkts, burst, dom: pps > 8000 and ent < 1.0,
        8,
        "SYN_FLOOD",
    ),
    (
        "UDP_FLOOD_HIGH_BPS",
        lambda pps, bps, ent, uniq, pkts, burst, dom: bps > 1_000_000 and uniq < 5,
        8,
        "UDP_FLOOD",
    ),
    (
        "SINGLE_SOURCE_FLOOD",
        # One IP sending >80% of all packets + high volume
        lambda pps, bps, ent, uniq, pkts, burst, dom: dom > 0.80 and pkts > 200,
        6,
        "VOLUMETRIC",
    ),
    (
        "BURST_SPIKE",
        # Sudden packet burst >6x the moving average
        lambda pps, bps, ent, uniq, pkts, burst, dom: burst > 6.0 and pkts > 100,
        5,
        "VOLUMETRIC",
    ),
    (
        "DISTRIBUTED_AMPLIFICATION",
        # Many unique sources + high entropy + high volume
        lambda pps, bps, ent, uniq, pkts, burst, dom: uniq > 50 and ent > 4.0 and pkts > 300,
        7,
        "AMPLIFICATION",
    ),
    (
        "SLOWLORIS",
        # Low PPS but sustained packet count — connection exhaustion
        lambda pps, bps, ent, uniq, pkts, burst, dom: pps < 150 and pkts > 150 and uniq < 10,
        4,
        "SLOWLORIS",
    ),
    (
        "PORT_SCAN_PROBE",
        # Many unique sources, moderate entropy, low-medium packet count
        # Typical nmap/masscan pattern
        lambda pps, bps, ent, uniq, pkts, burst, dom: uniq > 20 and pkts < 200 and ent > 2.5,
        5,
        "PORT_SCAN",
    ),
]


# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────
# Maps attack_type → (technique_id, technique_name, tactic)
# Reference: https://attack.mitre.org/
MITRE_MAP = {
    "SYN_FLOOD":     ("T1498.001", "Network Flooding: Direct Network Flood",  "Impact"),
    "UDP_FLOOD":     ("T1498.001", "Network Flooding: Direct Network Flood",  "Impact"),
    "VOLUMETRIC":    ("T1498",     "Network Denial of Service",               "Impact"),
    "AMPLIFICATION": ("T1498.002", "Network Flooding: Reflection Amplification", "Impact"),
    "SLOWLORIS":     ("T1499.001", "Endpoint Denial of Service: OS Exhaustion Flood", "Impact"),
    "DISTRIBUTED":   ("T1498",     "Network Denial of Service",               "Impact"),
    "PORT_SCAN":     ("T1046",     "Network Service Discovery",               "Discovery"),
    "ML_DETECTED":   ("T1498",     "Network Denial of Service",               "Impact"),
    "normal":        ("",          "",                                        ""),
}

def get_mitre(attack_type: str) -> dict:
    """Return MITRE ATT&CK info for a given attack type."""
    tid, name, tactic = MITRE_MAP.get(attack_type, ("", "", ""))
    return {"id": tid, "name": name, "tactic": tactic}


def apply_rules(
    pps: float,
    bps: float,
    entropy: float,
    unique_src: int,
    packets: int,
    burst_index: float,
    dominant_ratio: float,
) -> tuple[bool, str, int]:
    """
    Evaluate all rules against current window.
    Returns (fired, attack_type, score_bonus).
    If multiple rules fire, highest score_bonus wins.
    """
    fired_rules = []
    for name, condition, bonus, atype in RULES:
        try:
            if condition(pps, bps, entropy, unique_src, packets, burst_index, dominant_ratio):
                fired_rules.append((name, bonus, atype))
        except Exception:
            pass

    if not fired_rules:
        return False, "", 0

    # Pick rule with highest score bonus
    fired_rules.sort(key=lambda x: x[1], reverse=True)
    best_name, best_bonus, best_type = fired_rules[0]
    print(f"  🚨 RULE FIRED: {best_name} (bonus +{best_bonus}, type={best_type})")
    if len(fired_rules) > 1:
        others = ", ".join(r[0] for r in fired_rules[1:])
        print(f"     Also matched: {others}")
    return True, best_type, best_bonus


# ── Whitelist ─────────────────────────────────────────────────────────────────
# Whitelist is now managed by shared_state — editable at runtime via UI.
# Add machine's own hostname IP on startup.
def _register_local_ips() -> None:
    try:
        local = socket.gethostbyname(socket.gethostname())
        state.add_to_whitelist(local)
    except Exception:
        pass

_register_local_ips()

# ── Model load ────────────────────────────────────────────────────────────────
_model = joblib.load(MODEL_PATH)

if hasattr(_model, "feature_names_in_"):
    mf = list(_model.feature_names_in_)
    if set(mf) == set(PLATFORM_FEATURES):
        print(f"✅ Признаки модели OK: {PLATFORM_FEATURES}")
    else:
        print(f"⚠️  Несовпадение признаков!")
        print(f"   Модель: {mf}")
        print(f"   Платформа: {PLATFORM_FEATURES}")

try:
    _explainer = shap.TreeExplainer(_model)
    SHAP_OK = True
    print("✅ SHAP загружен")
except Exception as e:
    _explainer = None
    SHAP_OK = False
    print(f"⚠️  SHAP: {e}")

# ── Rolling window history ────────────────────────────────────────────────────
_pkt_history: list[float] = []
_ent_history: list[float] = []

# ── Thread-safe buffer — non-whitelist IPs only ───────────────────────────────
_lock:   threading.Lock = threading.Lock()
_buffer: list[str]      = []


# ── Helpers ───────────────────────────────────────────────────────────────────

def calc_entropy(counter: Counter, total: int) -> float:
    if total == 0:
        return 0.0
    h = 0.0
    for v in counter.values():
        p = v / total
        if p > 0:
            h -= p * math.log2(p)
    return h


def get_iface_counters() -> tuple[int, int]:
    """
    Returns (rx_packets, rx_bytes).
    /proc/net/dev: parts[1]=RX_bytes, parts[2]=RX_packets
    """
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if INTERFACE in line:
                    parts = line.split()
                    return int(parts[2]), int(parts[1])
    except Exception:
        pass
    return 0, 0


def calc_severity(packets: int, proba: float,
                  score: int, has_attackers: bool,
                  rule_fired: bool) -> str:
    # Rule fired → always at least HIGH regardless of ML
    if rule_fired and has_attackers:
        if proba > 0.85 or score > 12 or packets > 500:
            return "CRITICAL"
        return "HIGH"
    if not has_attackers:
        if proba > 0.8 and packets > 150:
            return "MEDIUM"
        return "LOW"
    if proba > 0.85 or score > 12 or packets > 500:
        return "CRITICAL"
    if proba > 0.65 or score > 8  or packets > 300:
        return "HIGH"
    if proba > 0.45 or score > 5  or packets > 150:
        return "MEDIUM"
    return "LOW"


def classify_attack_type_ml(pps, bps, entropy, unique, packets) -> str:
    """ML-based attack type — used when no rule fires."""
    if pps > 5000 and entropy < 1.5:
        return "SYN_FLOOD"
    if bps > 500_000 and unique < 5:
        return "UDP_FLOOD"
    if unique > 100 and entropy > 3.5:
        return "AMPLIFICATION"
    if pps < 100 and packets > 200:
        return "SLOWLORIS"
    if unique > 10 and entropy > 2.0:
        return "DISTRIBUTED"
    if packets > 300:
        return "VOLUMETRIC"
    return "ML_DETECTED"


def shap_explain(features: pd.DataFrame) -> list[list]:
    if not SHAP_OK or _explainer is None:
        return []
    try:
        sv = _explainer.shap_values(features)
        if isinstance(sv, list) and len(sv) == 2:
            vals = np.array(sv[1][0])
        elif isinstance(sv, np.ndarray) and sv.ndim == 3:
            vals = sv[0, :, 1]
        elif isinstance(sv, np.ndarray) and sv.ndim == 2:
            vals = sv[0]
        else:
            vals = np.array(sv).flatten()[:len(PLATFORM_FEATURES)]

        paired = sorted(
            zip(PLATFORM_FEATURES, [round(float(v), 4) for v in vals]),
            key=lambda x: abs(x[1]),
            reverse=True,
        )
        return [list(p) for p in paired[:5]]
    except Exception as e:
        print(f"⚠️  SHAP explain error: {e}")
        return []


def run_ipt(args: list[str]) -> bool:
    try:
        r = subprocess.run(
            ["sudo", "-n", "iptables"] + args,
            capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0:
            if "password" in r.stderr.lower() or "sudo" in r.stderr.lower():
                print("❌ sudo: добавь danoteas ALL=(ALL) NOPASSWD: /sbin/iptables")
            return False
        return True
    except subprocess.TimeoutExpired:
        print("⚠️  iptables timeout")
        return False
    except FileNotFoundError:
        print("⚠️  iptables не найден")
        return False
    except Exception as e:
        print(f"⚠️  iptables error: {e}")
        return False


def block_ip(ip: str, duration: int) -> None:
    alert_ip_blocked(ip, duration=duration, auto=True)
    if state.is_whitelisted(ip):
        return
    print(f"🔥 БЛОКИРОВКА {ip} на {duration}с")
    if run_ipt(["-A", "INPUT", "-s", ip, "-j", "DROP"]):
        state.add_auto_block(ip, time.time() + duration)
        print(f"   ✅ {ip} заблокирован")
    else:
        print(f"   ⚠️  Блокировка не выполнена — проверь sudoers")


def unblock_expired() -> None:
    now = time.time()
    for ip, t in list(state.blocked_ips.items()):
        if now > t:
            print(f"✅ РАЗБЛОКИРОВКА {ip}")
            run_ipt(["-D", "INPUT", "-s", ip, "-j", "DROP"])
            state.remove_auto_block(ip)


def decay_cleanup() -> None:
    now, stale = time.time(), []
    for ip, d in state.attack_table.items():
        d["score"] = max(0, d["score"] - SCORE_DECAY)
        if now - d["last_seen"] > STALE_IP_TIMEOUT and not d["blocked"]:
            stale.append(ip)
    for ip in stale:
        del state.attack_table[ip]


# ── Capture thread ────────────────────────────────────────────────────────────

def capture_thread() -> None:
    import pyshark
    global _buffer
    print(f"📡 Захват на {INTERFACE}")

    while True:
        try:
            cap = pyshark.LiveCapture(
                interface=INTERFACE,
                bpf_filter="ip",
                use_json=True,
                include_raw=False,
            )
            for pkt in cap.sniff_continuously():
                try:
                    if hasattr(pkt, "ip"):
                        src = pkt.ip.src
                        if not state.is_whitelisted(src):
                            with _lock:
                                # Buffer cap — prevent unbounded memory growth
                                if len(_buffer) < BUFFER_CAP:
                                    _buffer.append(src)
                except Exception:
                    pass
        except Exception as e:
            print(f"⚠️  Ошибка захвата: {e} — retry 3s")
            time.sleep(3)


# ── Main detection loop ───────────────────────────────────────────────────────

def detection_loop(loop: asyncio.AbstractEventLoop) -> None:

    print("=" * 62)
    print("🚀  ShieldSOC Detector v7")
    print(f"    Interface  : {INTERFACE}")
    print(f"    Whitelist  : {state.get_whitelist()}")
    print(f"    Features   : {PLATFORM_FEATURES}")
    print(f"    Window     : {WINDOW_SIZE}s | MinPkts: {MIN_PACKETS}")
    print(f"    Rules      : {len(RULES)} active")
    print(f"    Buffer cap : {BUFFER_CAP:,} packets")
    print("=" * 62)

    print("🔑 Проверяю sudoers...")
    if run_ipt(["-L", "INPUT", "-n", "--line-numbers"]):
        print("   ✅ iptables работает без пароля")
    else:
        print("   ⚠️  Блокировка недоступна — настрой sudoers")

    t = threading.Thread(target=capture_thread, daemon=True, name="capture")
    t.start()

    print("⏳ Инициализация захвата (2с)...")
    time.sleep(2)
    print("✅ Детектор активен!\n")

    prev_pkts          = 1
    prev_ent           = 0.0
    prev_rxp, prev_rxb = get_iface_counters()
    prev_t             = time.time()
    wnum               = 0

    while True:
        time.sleep(WINDOW_SIZE)
        wnum += 1

        with _lock:
            buf     = list(_buffer)
            _buffer.clear()

        rxp, rxb = get_iface_counters()
        now  = time.time()
        dt   = max(now - prev_t, 0.001)
        pps  = (rxp - prev_rxp) / dt
        bps  = (rxb - prev_rxb) / dt
        prev_rxp, prev_rxb = rxp, rxb
        prev_t = now

        unblock_expired()
        decay_cleanup()

        packets    = len(buf)
        counter    = Counter(buf)
        unique_src = len(counter)

        top = counter.most_common(5)
        print(f"[W{wnum}] {packets} пак (non-WL) | "
              f"Топ: {top} | PPS:{pps:.0f} BPS:{bps:.0f}")

        decision      = "normal"
        atype         = "normal"
        severity      = "LOW"
        attackers:    list[str]  = []
        shap_exp:     list[list] = []
        proba         = 0.0
        entropy       = 0.0
        rule_fired    = False
        rule_name     = ""

        if packets >= MIN_PACKETS:
            entropy = calc_entropy(counter, packets)

            _pkt_history.append(packets)
            _ent_history.append(entropy)
            if len(_pkt_history) > 6:
                _pkt_history.pop(0)
                _ent_history.pop(0)

            pma = sum(_pkt_history) / len(_pkt_history)
            ema = sum(_ent_history) / len(_ent_history)

            burst_index    = packets / (pma + 1)
            dominant_ratio = counter.most_common(1)[0][1] / packets if counter else 0.0

            fd = {
                "pps":           pps,
                "packets":       float(packets),
                "entropy":       entropy,
                "unique":        float(unique_src),
                "burst_index":   burst_index,
                "packets_ma":    pma,
                "entropy_ma":    ema,
                "entropy_delta": entropy - prev_ent,
                "unique_ratio":  unique_src / (packets + 1),
                "packets_ratio": packets / max(prev_pkts, 1),
            }

            feats = pd.DataFrame([fd])[PLATFORM_FEATURES]
            proba = float(_model.predict_proba(feats)[0][1])
            shap_exp = shap_explain(feats)

            # ── Rule-based layer ──────────────────────────────────────────────
            rule_fired, rule_atype, rule_bonus = apply_rules(
                pps, bps, entropy, unique_src,
                packets, burst_index, dominant_ratio
            )

            max_score = max(
                (state.attack_table[ip]["score"] for ip in counter),
                default=0,
            )
            severity = calc_severity(
                packets, proba, max_score,
                has_attackers=bool(counter),
                rule_fired=rule_fired,
            )

            # ── ML scoring ────────────────────────────────────────────────────
            for ip, cnt in counter.items():
                dom = cnt / packets
                if dom > 0.4 and proba > 0.6 and pps > 50:
                    state.attack_table[ip]["score"] += 3
                if unique_src > 5 and entropy > 1.5 and proba > 0.6:
                    state.attack_table[ip]["score"] += 2
                if packets > 100 and proba > 0.6:
                    state.attack_table[ip]["score"] += 2
                if proba > state.ml_threshold:
                    state.attack_table[ip]["score"] += 2
                # Rule bonus — applied to all IPs in this window
                if rule_fired:
                    state.attack_table[ip]["score"] += rule_bonus

            # ── Attack type resolution ────────────────────────────────────────
            # Rule type takes priority over ML type classification
            high = [
                ip for ip in counter
                if state.attack_table[ip]["score"] >= ATTACK_SCORE_THRESHOLD
            ]
            if rule_fired:
                atype = rule_atype
            elif proba > state.ml_threshold or high:
                atype = classify_attack_type_ml(
                    pps, bps, entropy, unique_src, packets
                )

            # ── Mitigation ────────────────────────────────────────────────────
            for ip in counter:
                state.attack_table[ip]["last_seen"] = time.time()
                # Rule fired → immediate attack regardless of score threshold
                score_hit = state.attack_table[ip]["score"] >= ATTACK_SCORE_THRESHOLD
                if score_hit or rule_fired:
                    attackers.append(ip)
                    decision = "attack"
                    if not state.is_blocked(ip):
                        dur = BASE_BLOCK_TIME + \
                              state.attack_table[ip]["score"] * 10
                        block_ip(ip, dur)

            prev_pkts = packets
            prev_ent  = entropy

        else:
            unique_src = len(counter)

        print(f"  → {decision} | prob={proba:.3f} | "
              f"pkts={packets} | sev={severity} | "
              f"rule={'✅' if rule_fired else '—'} | att={attackers}")

        event = {
            "timestamp":          int(time.time()),
            "packets":            packets,
            "unique_src":         unique_src,
            "entropy":            round(entropy, 3),
            "pps":                round(pps, 2),
            "bps":                round(bps, 2),
            "attack_probability": round(proba, 3),
            "decision":           decision,
            "attack_type":        atype,
            "severity":           severity,
            "attackers":          attackers,
            "shap_explanation":   shap_exp,
            "rule_triggered":     rule_fired,
            "mitre":              get_mitre(atype),
            "scores": {
                ip: d["score"] for ip, d in state.attack_table.items()
            },
        }

        save_event(event)
        if decision == "attack":
            alert_attack(event)
        update_sessions(event)
        asyncio.run_coroutine_threadsafe(broadcast(event), loop)


def start_detector(loop: asyncio.AbstractEventLoop) -> None:
    detection_loop(loop)