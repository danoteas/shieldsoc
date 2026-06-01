"use strict"

// ── Design tokens ─────────────────────────────────────────────────────────────
const C = {
    cyan:    "#00d4ff",
    red:     "#ff3d57",
    amber:   "#ffab00",
    green:   "#00e676",
    purple:  "#b388ff",
    grid:    "rgba(26,48,80,0.7)",
    textSec: "#7a9cc0",
}

Chart.defaults.color       = C.textSec
Chart.defaults.borderColor = C.grid
Chart.defaults.font.family = "'Inter', sans-serif"
Chart.defaults.font.size   = 11

// ── State ─────────────────────────────────────────────────────────────────────
let probChart   = null
let packetChart = null

const MAX_POINTS = 40
const chartData  = { labels: [], prob: [], packets: [] }
const allEvents  = []

// ── Sound alert — uses global window.playAlert from base.html ────────────────
// AudioContext is managed globally to work across all tabs

// ── Severity helpers ──────────────────────────────────────────────────────────
const SEV_COLOR = {
    CRITICAL: "#ff3d57",
    HIGH:     "#ff8f00",
    MEDIUM:   "#ffd600",
    LOW:      "#00d4ff",
}
function sevColor(s) { return SEV_COLOR[s] || "#7a9cc0" }
function sevBadge(s) { return `<span class="badge-sev ${s}">${s}</span>` }
function decBadge(d) {
    return `<span class="badge-decision ${d}">${d.toUpperCase()}</span>`
}

// ── Alert banner ──────────────────────────────────────────────────────────────
let _alertTimer = null
function showAlert(msg, severity = "HIGH") {
    const el = document.getElementById("alertBanner")
    if (!el) return
    el.innerHTML = `🚨 ${msg}`
    el.style.display = "block"
    clearTimeout(_alertTimer)
    _alertTimer = setTimeout(() => { el.style.display = "none" }, 12000)
    playAlert(severity === "CRITICAL" ? "critical" : "normal")
}

// ── Charts init ───────────────────────────────────────────────────────────────
function initCharts() {
    const baseOpts = {
        animation: false, responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
            x: { ticks: { maxTicksLimit: 8, color: C.textSec }, grid: { color: C.grid } },
            y: { ticks: { color: C.textSec }, grid: { color: C.grid } },
        },
    }

    probChart = new Chart(document.getElementById("probChart"), {
        type: "line",
        data: {
            labels: chartData.labels,
            datasets: [{
                data: chartData.prob,
                borderColor: C.red,
                backgroundColor: "rgba(255,61,87,0.08)",
                fill: true, tension: 0.4, pointRadius: 2,
            }],
        },
        options: {
            ...baseOpts,
            scales: {
                ...baseOpts.scales,
                y: { ...baseOpts.scales.y, min: 0, max: 1 },
            },
        },
    })

    packetChart = new Chart(document.getElementById("packetChart"), {
        type: "line",
        data: {
            labels: chartData.labels,
            datasets: [{
                data: chartData.packets,
                borderColor: C.cyan,
                backgroundColor: "rgba(0,212,255,0.06)",
                fill: true, tension: 0.4, pointRadius: 2,
            }],
        },
        options: baseOpts,
    })
}

// ── Push to charts ────────────────────────────────────────────────────────────
function pushToCharts(event) {
    const label = new Date(event.timestamp * 1000).toLocaleTimeString()
    chartData.labels.push(label)
    chartData.prob.push(event.attack_probability)
    // Use pps (interface-level) not packets (buffer-only, often 0 for whitelisted traffic)
    chartData.packets.push(event.pps || 0)
    if (chartData.labels.length > MAX_POINTS) {
        chartData.labels.shift()
        chartData.prob.shift()
        chartData.packets.shift()
    }
    probChart.update("none")
    packetChart.update("none")
}

// ── Metric cards ──────────────────────────────────────────────────────────────
function updateCards() {
    document.getElementById("totalEvents").innerText  = allEvents.length
    document.getElementById("activeAttacks").innerText =
        allEvents.filter(e => e.decision === "attack").length

    const avgPps = allEvents.length
        ? (allEvents.reduce((s, e) => s + (e.pps || 0), 0) / allEvents.length).toFixed(2)
        : "0.00"
    document.getElementById("avgPps").innerText = avgPps

    const recent   = allEvents.slice(-20)
    let sev        = "LOW"
    const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for (const s of sevOrder) {
        if (recent.some(e => e.severity === s)) { sev = s; break }
    }
    const sevEl = document.getElementById("maxSeverity")
    sevEl.innerText   = sev
    sevEl.style.color = sevColor(sev)

    if (allEvents.filter(e => e.decision === "attack").length > 0) {
        const card = document.querySelector(".metric-card.accent-red")
        if (card) card.style.boxShadow = "0 0 16px rgba(255,61,87,0.4)"
    }
}

// ── Event table row ───────────────────────────────────────────────────────────
function prependTableRow(e) {
    const tbody = document.getElementById("eventsTable")
    const isAtk = e.decision === "attack"
    const row   = document.createElement("tr")
    if (isAtk) row.style.background = "rgba(255,61,87,0.06)"

    // MITRE shown inline under attack_type, not as separate column
    const mitreTag = e.mitre && e.mitre.id
        ? `<br><a href="https://attack.mitre.org/techniques/${e.mitre.id.replace('.','/')}/"
              target="_blank"
              style="font-family:var(--font-mono);font-size:9px;color:var(--purple);
                     text-decoration:none;opacity:0.8;" title="${e.mitre.name}">${e.mitre.id}</a>`
        : ""

    row.innerHTML = `
        <td style="font-family:var(--font-mono);font-size:12px;color:var(--text-secondary);">
            ${new Date(e.timestamp * 1000).toLocaleTimeString()}</td>
        <td style="font-family:var(--font-mono);">${e.packets}</td>
        <td style="font-family:var(--font-mono);">${e.pps}</td>
        <td style="font-family:var(--font-mono);">${e.entropy}</td>
        <td style="font-family:var(--font-mono);color:${e.attack_probability > 0.7 ? C.red : C.textSec};">
            ${e.attack_probability}</td>
        <td>${sevBadge(e.severity)}</td>
        <td>${decBadge(e.decision)}</td>
        <td style="font-size:11px;color:var(--text-secondary);">${e.attack_type}${mitreTag}</td>
        ${isAtk ? `<td><button class="ai-explain-btn"
            onclick="event.stopPropagation();window.aiExplain && aiExplain('${e.attack_type}','${(e.attackers||[])[0]||"?"}','${e.attack_probability.toFixed(3)}','${e.shap_explanation&&e.shap_explanation.length?e.shap_explanation[0][0]+"("+( e.shap_explanation[0][1]>0?"+":"")+e.shap_explanation[0][1].toFixed(3)+")":"—"}')">✦ Explain</button></td>` : "<td></td>"}
    `
    tbody.insertBefore(row, tbody.firstChild)
    while (tbody.rows.length > 20) tbody.deleteRow(tbody.rows.length - 1)

    if (isAtk && e.severity === "CRITICAL") {
        showAlert(
            `CRITICAL attack! Type: ${e.attack_type} · ` +
            `Attackers: ${(e.attackers || []).join(", ") || "unknown"} · ` +
            `Probability: ${(e.attack_probability * 100).toFixed(0)}%`,
            "CRITICAL"
        )
    } else if (isAtk) {
        showAlert(
            `Attack detected: ${e.attack_type} · ${e.severity} · ` +
            `IP: ${(e.attackers || []).join(", ")}`,
            e.severity
        )
    }
}

// ── Top attackers ─────────────────────────────────────────────────────────────
function updateAttackers() {
    const counts = {}
    allEvents.forEach(e => {
        ;(e.attackers || []).forEach(ip => {
            counts[ip] = (counts[ip] || 0) + 1
        })
    })

    const ul      = document.getElementById("attackersList")
    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8)

    ul.innerHTML = entries.length
        ? entries.map(([ip, n]) => `
            <li style="display:flex;justify-content:space-between;
                        align-items:center;margin-bottom:8px;">
                <code>${ip}</code>
                <span style="background:rgba(255,61,87,.15);color:#ff3d57;
                             font-family:var(--font-mono);font-size:11px;
                             padding:2px 7px;border-radius:4px;">${n}</span>
            </li>`).join("")
        : `<li style="color:var(--text-dim);font-size:12px;">No attackers</li>`
}

// ── Blocked IPs list ──────────────────────────────────────────────────────────
async function updateBlocked() {
    try {
        const res  = await fetch("/api/blocked")
        const data = await res.json()
        const ul   = document.getElementById("blockedList")
        const list = data.blocked || []

        ul.innerHTML = list.length
            ? list.map(ip => `
                <li style="display:flex;justify-content:space-between;
                            align-items:center;margin-bottom:6px;">
                    <code>${ip}</code>
                    <button class="btn-soc danger"
                            onclick="quickUnblock('${ip}')">Unblock</button>
                </li>`).join("")
            : `<li style="color:var(--text-dim);font-size:12px;">* No blocked IPs</li>`
    } catch (_) {}
}

async function quickUnblock(ip) {
    await fetch(`/api/unblock/${ip}`, { method: "POST" })
    updateBlocked()
    updateAttackers()
    setManualStatus(`✅ ${ip} unblocked`, "var(--green)")
}

// ── Manual block UI ───────────────────────────────────────────────────────────
function setManualStatus(msg, color = "var(--text-secondary)") {
    const el = document.getElementById("manualBlockStatus")
    if (!el) return
    el.innerText   = msg
    el.style.color = color
    setTimeout(() => { el.innerText = "" }, 4000)
}

async function manualBlock() {
    const inp = document.getElementById("manualIpInput")
    const ip  = (inp?.value || "").trim()
    if (!ip) {
        setManualStatus("⚠ Enter an IP address", "var(--amber)")
        return
    }
    // Basic IP format check
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
        setManualStatus("⚠ Invalid IP format", "var(--amber)")
        return
    }
    try {
        const res  = await fetch(`/api/block/${ip}`, { method: "POST" })
        const data = await res.json()
        if (data.status === "blocked") {
            setManualStatus(`🔒 ${ip} blocked`, "var(--red)")
        } else if (data.status === "already_blocked") {
            setManualStatus(`ℹ ${ip} already blocked`, "var(--amber)")
        }
        inp.value = ""
        updateBlocked()
    } catch (e) {
        setManualStatus("❌ Request failed", "var(--red)")
    }
}

async function manualUnblock() {
    const inp = document.getElementById("manualIpInput")
    const ip  = (inp?.value || "").trim()
    if (!ip) {
        setManualStatus("⚠ Enter an IP address", "var(--amber)")
        return
    }
    try {
        await fetch(`/api/unblock/${ip}`, { method: "POST" })
        setManualStatus(`✅ ${ip} unblocked`, "var(--green)")
        inp.value = ""
        updateBlocked()
        updateAttackers()
    } catch (e) {
        setManualStatus("❌ Request failed", "var(--red)")
    }
}

// ── Sensitivity slider ────────────────────────────────────────────────────────
async function initSlider() {
    try {
        const res = await fetch("/api/config/threshold")
        const d   = await res.json()
        const s   = document.getElementById("thresholdSlider")
        if (s) {
            s.value = d.threshold
            const valEl = document.getElementById("thresholdVal")
            if (valEl) valEl.innerText = parseFloat(d.threshold).toFixed(2)
        }
    } catch (_) {}
}

async function onSliderChange(val) {
    const valEl = document.getElementById("thresholdVal")
    if (valEl) valEl.innerText = parseFloat(val).toFixed(2)
    await fetch("/api/config/threshold", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threshold: parseFloat(val) }),
    })
}

// ── Initial load ──────────────────────────────────────────────────────────────
async function initialLoad() {
    try {
        const res    = await fetch("/api/events")
        const events = await res.json()
        events.forEach(e => {
            allEvents.push(e)
            pushToCharts(e)
        })
        events.slice(-20).reverse().forEach(prependTableRow)
        updateCards()
        updateAttackers()
    } catch (_) {}
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
function connectWS() {
    const proto  = location.protocol === "https:" ? "wss" : "ws"
    const ws     = new WebSocket(`${proto}://${location.host}/ws`)
    const status = document.getElementById("wsStatus")

    ws.onopen = () => {
        if (status) { status.innerText = "● Live"; status.style.color = C.green }
    }

    ws.onmessage = (msg) => {
        try {
            const event = JSON.parse(msg.data)
            allEvents.push(event)
            if (allEvents.length > 1000) allEvents.shift()

            pushToCharts(event)
            prependTableRow(event)
            updateCards()

            if (event.decision === "attack") {
                updateAttackers()
                updateBlocked()
            }
        } catch (e) {
            console.error("WS parse error:", e)
        }
    }

    ws.onclose = () => {
        if (status) {
            status.innerText   = "● Reconnecting…"
            status.style.color = C.amber
        }
        setTimeout(connectWS, 3000)
    }

    ws.onerror = () => ws.close()
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
    initCharts()
    await initialLoad()
    connectWS()
    initSlider()

    setInterval(() => {
        updateBlocked()
        updateAttackers()
    }, 5000)

    updateBlocked()
})