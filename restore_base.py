#!/usr/bin/env python3
"""
Restores missing features to base.html WITHOUT replacing the file.
Run from: ~/ddos-venv/diploma/ddos_platform/
"""
import re, sys

path = "templates/base.html"
try:
    with open(path) as f:
        content = f.read()
    print(f"Loaded {len(content)} chars")
except FileNotFoundError:
    print(f"ERROR: {path} not found. Run from ddos_platform directory.")
    sys.exit(1)

changes = 0

# ── 1. Bootstrap Icons CDN ────────────────────────────────────────────
if "bootstrap-icons" not in content:
    content = content.replace(
        '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">',
        '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">\n    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">',
        1
    )
    changes += 1
    print("OK Bootstrap Icons CDN added")
else:
    print("-- Bootstrap Icons already present")

# ── 2. Sidebar toggle CSS ─────────────────────────────────────────────
if "sidebar-toggle" not in content:
    toggle_css = """
        /* ── Sidebar collapsible toggle ──────────────────────────── */
        :root { --transition: .22s ease; }
        .sidebar { transition: width var(--transition); overflow: visible; }
        .sidebar.collapsed { width: 54px; }
        .sidebar.collapsed .brand-name,
        .sidebar.collapsed .brand-sub,
        .sidebar.collapsed .sidebar-section,
        .sidebar.collapsed .sidebar-footer,
        .sidebar.collapsed .nav-label,
        .sidebar.collapsed .logout-label,
        .sidebar.collapsed .live-dot { display: none; }
        .sidebar.collapsed a { justify-content: center; padding: 9px 0; }
        .sidebar.collapsed .nav-icon,
        .sidebar.collapsed i.nav-icon { font-size: 17px; width: auto; }
        .main { transition: margin-left var(--transition); }
        body.sidebar-collapsed .main { margin-left: 54px; }
        body.sidebar-collapsed .topbar { left: 54px; }
        body.sidebar-collapsed #alertBanner { left: calc(54px + 18px); }

        .sidebar-toggle {
            position: absolute;
            top: 14px;
            right: -13px;
            width: 26px; height: 26px;
            background: var(--bg-surface);
            border: 1px solid var(--border-bright);
            border-radius: 50%;
            cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            font-size: 13px;
            color: var(--text-secondary);
            z-index: 201;
            box-shadow: 0 0 0 2px var(--bg-sidebar);
            transition: background .15s, color .15s, box-shadow .15s;
            user-select: none;
        }
        .sidebar-toggle:hover { background: var(--bg-surface-2); color: var(--cyan); }
        i.nav-icon { font-size:15px; flex-shrink:0; width:20px; text-align:center; line-height:1; display:inline-flex; align-items:center; justify-content:center; }
"""
    content = content.replace("    </style>", toggle_css + "    </style>", 1)
    changes += 1
    print("OK Sidebar toggle CSS added")
else:
    print("-- Sidebar toggle CSS already present")

# ── 3. Sidebar toggle HTML button (inside .sidebar div) ──────────────
if 'class="sidebar-toggle"' not in content:
    content = content.replace(
        '<div class="sidebar-brand">',
        '<button class="sidebar-toggle" id="sidebarToggle" onclick="toggleSidebar()" title="Toggle sidebar">‹</button>\n<div class="sidebar-brand">',
        1
    )
    changes += 1
    print("OK Sidebar toggle button added")
else:
    print("-- Sidebar toggle button already present")

# ── 4. Replace emoji nav icons with Bootstrap Icons ───────────────────
icon_map = {
    '<span class="nav-icon">📊</span>': '<i class="bi bi-speedometer2 nav-icon"></i>',
    '<span class="nav-icon">📈</span>': '<i class="bi bi-graph-up nav-icon"></i>',
    '<span class="nav-icon">🌍</span>': '<i class="bi bi-globe nav-icon"></i>',
    '<span class="nav-icon">📚</span>': '<i class="bi bi-clock-history nav-icon"></i>',
    '<span class="nav-icon">🔐</span>': '<i class="bi bi-shield-exclamation nav-icon"></i>',
    '<span class="nav-icon">🧠</span>': '<i class="bi bi-cpu nav-icon"></i>',
}
for old, new in icon_map.items():
    if old in content:
        content = content.replace(old, new)
        changes += 1
print(f"OK Nav icons replaced ({changes} total changes so far)")

# ── 5. Brand icon emoji → BI icon ────────────────────────────────────
if '🛡' in content and 'bi-shield-fill-check' not in content:
    content = content.replace(
        '<div class="brand-icon">🛡</div>',
        '<div class="brand-icon"><i class="bi bi-shield-fill-check" style="color:#fff;font-size:15px;"></i></div>'
    )
    changes += 1
    print("OK Brand icon replaced")

# ── 6. Add nav-label spans for i18n (if missing) ─────────────────────
# The sidebar links need <span class="nav-label">Text</span> for i18n
label_map = [
    (' Dashboard\n', ' <span class="nav-label" data-i18n="nav.dashboard">Dashboard</span>\n'),
    (' Traffic Analytics\n', ' <span class="nav-label" data-i18n="nav.analytics">Traffic Analytics</span>\n'),
    (' Attack Map\n', ' <span class="nav-label" data-i18n="nav.map">Attack Map</span>\n'),
    (' Event History\n', ' <span class="nav-label" data-i18n="nav.history">Event History</span>\n'),
    (' Attack Sessions\n', ' <span class="nav-label" data-i18n="nav.sessions">Attack Sessions</span>\n'),
    (' Intelligence\n', ' <span class="nav-label" data-i18n="nav.intelligence">Intelligence</span>\n'),
]
for old, new in label_map:
    if old in content and 'nav-label' not in content.split(old)[0][-200:]:
        content = content.replace(old, new, 1)
        changes += 1

# ── 7. toggleSidebar JS function ─────────────────────────────────────
if "toggleSidebar" not in content:
    sidebar_js = """
// ═══════════════════════════════════════════════════════════════════════
// SIDEBAR TOGGLE
// ═══════════════════════════════════════════════════════════════════════
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar')
    const btn     = document.getElementById('sidebarToggle')
    const isCollapsed = sidebar.classList.toggle('collapsed')
    document.body.classList.toggle('sidebar-collapsed', isCollapsed)
    localStorage.setItem('shieldsoc_sidebar', isCollapsed ? 'collapsed' : 'open')
    if (btn) btn.textContent = isCollapsed ? '›' : '‹'
}

// Restore sidebar state on load
;(function() {
    const saved = localStorage.getItem('shieldsoc_sidebar')
    if (saved === 'collapsed') {
        document.querySelector('.sidebar')?.classList.add('collapsed')
        document.body.classList.add('sidebar-collapsed')
        const btn = document.getElementById('sidebarToggle')
        if (btn) btn.textContent = '›'
    }
})()

"""
    # Insert before the THEME TOGGLE section
    content = content.replace(
        "// ═══════════════════════════════════════════════════════════════════════\n// THEME TOGGLE",
        sidebar_js + "// ═══════════════════════════════════════════════════════════════════════\n// THEME TOGGLE"
    )
    changes += 1
    print("OK toggleSidebar() JS added")
else:
    print("-- toggleSidebar already present")

with open(path, "w") as f:
    f.write(content)

print(f"\n✅ Done — {changes} changes applied. base.html: {len(content)} chars")
