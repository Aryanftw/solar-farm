"""
Solar Farm OT Security Watchman — Streamlit Dashboard
Professional industrial SOC dashboard with navy/charcoal design system.

Pages:
  1. Overview
  2. Device Inventory
  3. Alerts
  4. Timeline
  5. Model & Sensor Health
  6. Validation
"""

import json
import os
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")
REFRESH_INTERVAL_S = 15

# ── Design System ────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Solar Farm — OT Security Watchman",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject custom CSS — navy/charcoal/muted-green palette
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    --color-bg:           #0d1117;
    --color-surface:      #161b22;
    --color-surface2:     #1c2333;
    --color-border:       #30363d;
    --color-navy:         #1a2742;
    --color-navy-light:   #243352;
    --color-green:        #3fb950;
    --color-green-muted:  #238636;
    --color-amber:        #d29922;
    --color-red:          #da3633;
    --color-blue:         #388bfd;
    --color-text:         #e6edf3;
    --color-text-muted:   #8b949e;
    --color-text-dim:     #6e7681;
}

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: var(--color-bg) !important;
    color: var(--color-text) !important;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: var(--color-navy) !important;
    border-right: 1px solid var(--color-border);
}
section[data-testid="stSidebar"] .stRadio label {
    color: var(--color-text) !important;
    font-size: 0.9rem;
}

/* Main content area */
.main .block-container {
    padding-top: 1rem;
    background-color: var(--color-bg);
    max-width: 1400px;
}

/* Page header */
.page-header {
    background: linear-gradient(135deg, var(--color-navy) 0%, var(--color-navy-light) 100%);
    border: 1px solid var(--color-border);
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
}
.page-header h1 {
    margin: 0;
    font-size: 1.4rem;
    font-weight: 600;
    color: var(--color-text);
}
.page-header .subtitle {
    color: var(--color-text-muted);
    font-size: 0.85rem;
    margin-top: 0.1rem;
}

/* Stat cards */
.stat-card {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    text-align: center;
}
.stat-card .stat-value {
    font-size: 2rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    color: var(--color-text);
    line-height: 1.2;
}
.stat-card .stat-label {
    font-size: 0.78rem;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-top: 0.25rem;
}
.stat-card.green .stat-value  { color: var(--color-green); }
.stat-card.amber .stat-value  { color: var(--color-amber); }
.stat-card.red .stat-value    { color: var(--color-red); }
.stat-card.blue .stat-value   { color: var(--color-blue); }

/* Severity badges */
.badge {
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 4px;
    font-size: 0.73rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
.badge-critical { background: #3b0a0a; color: #ff7b7b; border: 1px solid #da3633; }
.badge-high     { background: #2d1b00; color: #f9b93a; border: 1px solid #d29922; }
.badge-medium   { background: #0c1b2e; color: #7ec8ff; border: 1px solid #388bfd; }
.badge-low      { background: #0f2a18; color: #7de88a; border: 1px solid #3fb950; }

/* Status indicator */
.status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
}
.status-online  { background: var(--color-green); box-shadow: 0 0 6px var(--color-green); }
.status-offline { background: var(--color-red); }
.status-unknown { background: var(--color-text-dim); }
.status-warning { background: var(--color-amber); }

/* Section headers */
.section-header {
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 1.25rem 0 0.75rem;
    padding-bottom: 0.4rem;
    border-bottom: 1px solid var(--color-border);
}

/* Alert row */
.alert-row {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-left: 3px solid var(--color-border);
    border-radius: 6px;
    padding: 0.75rem 1rem;
    margin-bottom: 0.5rem;
    font-size: 0.87rem;
}
.alert-row.critical { border-left-color: var(--color-red); }
.alert-row.high     { border-left-color: var(--color-amber); }
.alert-row.medium   { border-left-color: var(--color-blue); }
.alert-row.low      { border-left-color: var(--color-green); }

/* Monospace values */
.mono { font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; }

/* Warning banner */
.lab-warning {
    background: #1c1000;
    border: 1px solid var(--color-amber);
    border-radius: 6px;
    padding: 0.6rem 1rem;
    font-size: 0.82rem;
    color: var(--color-amber);
    margin-bottom: 1rem;
}

/* Streamlit overrides */
.stDataFrame { background: var(--color-surface) !important; }
div[data-testid="metric-container"] {
    background: var(--color-surface) !important;
    border: 1px solid var(--color-border) !important;
    border-radius: 8px !important;
    padding: 0.75rem !important;
}
div[data-testid="metric-container"] label { color: var(--color-text-muted) !important; }
.stButton > button {
    background: var(--color-navy-light) !important;
    border: 1px solid var(--color-border) !important;
    color: var(--color-text) !important;
    border-radius: 6px !important;
}
.stButton > button:hover {
    background: var(--color-navy) !important;
    border-color: var(--color-blue) !important;
}
</style>
""",
    unsafe_allow_html=True,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLORS = {
    "critical": "#da3633",
    "high": "#d29922",
    "medium": "#388bfd",
    "low": "#3fb950",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def api(path: str, default=None, timeout: int = 5):
    """Call API endpoint, return JSON or default on failure."""
    try:
        r = requests.get(f"{API_URL}{path}", timeout=timeout)
        if r.ok:
            return r.json()
    except Exception as e:
        pass
    return default


def severity_badge(sev: str) -> str:
    cls = f"badge-{sev}"
    return f'<span class="badge {cls}">{sev}</span>'


def status_dot(online: bool, unknown: bool = False) -> str:
    if unknown:
        cls = "status-unknown"
    elif online:
        cls = "status-online"
    else:
        cls = "status-offline"
    return f'<span class="status-dot {cls}"></span>'


def utc_age(ts_str: str) -> str:
    """Return human-readable age of a UTC timestamp."""
    try:
        ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        diff = datetime.now(timezone.utc) - ts
        s = int(diff.total_seconds())
        if s < 60:
            return f"{s}s ago"
        elif s < 3600:
            return f"{s//60}m ago"
        elif s < 86400:
            return f"{s//3600}h ago"
        return f"{s//86400}d ago"
    except Exception:
        return ts_str


def plotly_dark_layout() -> dict:
    return {
        "plot_bgcolor": "#161b22",
        "paper_bgcolor": "#161b22",
        "font": {"color": "#e6edf3", "family": "Inter"},
        "xaxis": {"gridcolor": "#30363d", "linecolor": "#30363d"},
        "yaxis": {"gridcolor": "#30363d", "linecolor": "#30363d"},
        "margin": {"l": 40, "r": 20, "t": 30, "b": 40},
    }


# ── Navigation ────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown(
        """
        <div style="padding:1rem 0 0.5rem;">
          <div style="font-size:1.15rem;font-weight:700;color:#e6edf3;">🛡️ OT Security</div>
          <div style="font-size:0.78rem;color:#8b949e;">Solar Farm Watchman</div>
          <div style="margin-top:0.5rem;font-size:0.72rem;color:#3fb950;">● Lab simulation only</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.divider()

    page = st.radio(
        "Navigation",
        ["Overview", "Device Inventory", "Alerts", "Timeline", "Model & Sensor", "Validation"],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown(
        f'<div style="font-size:0.72rem;color:#6e7681;">API: {API_URL}<br>'
        f'Refreshed: {datetime.now(timezone.utc).strftime("%H:%M:%S")} UTC</div>',
        unsafe_allow_html=True,
    )
    if st.button("🔄 Refresh"):
        st.rerun()


# ── Page 1: Overview ──────────────────────────────────────────────────────────

if page == "Overview":
    st.markdown(
        '<div class="page-header">'
        '<div>🏭</div>'
        '<div><h1>Plant & Security Overview</h1>'
        '<div class="subtitle">Real-time status of the simulated solar farm OT network</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="lab-warning">⚠️ This is an isolated simulation. All data originates from the local Docker lab. '
        'Not connected to any real industrial plant or network.</div>',
        unsafe_allow_html=True,
    )

    overview = api("/overview", {})
    devices = overview.get("devices", {})
    alerts_data = overview.get("alerts", {})
    sensor = overview.get("sensor", {})
    protocols = overview.get("protocols", {})
    by_sev = alerts_data.get("by_severity", {})

    # ── Top stats
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(
            f'<div class="stat-card blue"><div class="stat-value">{devices.get("total", 0)}</div>'
            f'<div class="stat-label">Devices Seen</div></div>',
            unsafe_allow_html=True,
        )
    with col2:
        known = devices.get("authorised", 0)
        st.markdown(
            f'<div class="stat-card green"><div class="stat-value">{known}</div>'
            f'<div class="stat-label">Authorised</div></div>',
            unsafe_allow_html=True,
        )
    with col3:
        unknown = devices.get("unknown", 0)
        cls = "red" if unknown > 0 else ""
        st.markdown(
            f'<div class="stat-card {cls}"><div class="stat-value">{unknown}</div>'
            f'<div class="stat-label">Unknown Devices</div></div>',
            unsafe_allow_html=True,
        )
    with col4:
        crit = by_sev.get("critical", 0)
        cls = "red" if crit > 0 else ""
        st.markdown(
            f'<div class="stat-card {cls}"><div class="stat-value">{crit}</div>'
            f'<div class="stat-label">Critical Alerts</div></div>',
            unsafe_allow_html=True,
        )
    with col5:
        high = by_sev.get("high", 0)
        cls = "amber" if high > 0 else ""
        st.markdown(
            f'<div class="stat-card {cls}"><div class="stat-value">{high}</div>'
            f'<div class="stat-label">High Alerts</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div style="margin-top:1rem;"></div>', unsafe_allow_html=True)

    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown('<div class="section-header">Recent Alerts</div>', unsafe_allow_html=True)
        recent = alerts_data.get("recent", [])
        if recent:
            for a in recent[:8]:
                sev = a.get("severity", "low")
                rule = a.get("rule_name", "")
                ts = utc_age(a.get("timestamp_utc", ""))
                src = a.get("src_ip", "?")
                explanation = a.get("explanation", "")[:120]
                st.markdown(
                    f'<div class="alert-row {sev}">'
                    f'{severity_badge(sev)} <strong class="mono">{rule}</strong> '
                    f'<span style="color:#8b949e;font-size:0.8rem;">— {ts} — src: {src}</span>'
                    f'<div style="color:#c9d1d9;font-size:0.82rem;margin-top:0.3rem;">{explanation}…</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("No alerts yet. Run a scenario to generate alerts.")

    with col_right:
        st.markdown('<div class="section-header">Alert Severity Distribution</div>', unsafe_allow_html=True)
        if by_sev:
            sev_df = pd.DataFrame(
                [(k, v) for k, v in sorted(by_sev.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))],
                columns=["Severity", "Count"],
            )
            fig = px.bar(
                sev_df, x="Severity", y="Count",
                color="Severity",
                color_discrete_map=SEVERITY_COLORS,
                text="Count",
            )
            fig.update_layout(**plotly_dark_layout(), showlegend=False, height=220)
            fig.update_traces(textposition="outside")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alert data yet.")

        st.markdown('<div class="section-header">Sensor Status</div>', unsafe_allow_html=True)
        if sensor and sensor.get("status") != "no_data":
            running = sensor.get("sensor_running", 0)
            observed = sensor.get("traffic_observed", 0)
            mode = sensor.get("capture_mode", "unknown")
            packets = sensor.get("packets_seen", 0)
            last_proto = sensor.get("last_protocol_seen", "N/A")
            last_health_ts = utc_age(sensor.get("timestamp_utc", ""))

            st.markdown(
                f'<div class="stat-card" style="text-align:left;padding:0.75rem;">'
                f'{status_dot(bool(running))} <strong>Sensor Process:</strong> {"Running" if running else "Stopped"}<br>'
                f'{status_dot(bool(observed))} <strong>Traffic Observed:</strong> {"Yes" if observed else "No"}<br>'
                f'<span style="color:#8b949e;font-size:0.82rem;">Mode: <span class="mono">{mode}</span> | '
                f'Packets: <span class="mono">{packets}</span> | '
                f'Last: <span class="mono">{last_proto}</span><br>'
                f'Updated: {last_health_ts}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="stat-card"><span class="status-dot status-unknown"></span>'
                'No sensor health data yet.</div>',
                unsafe_allow_html=True,
            )

        st.markdown('<div class="section-header">Protocol Traffic</div>', unsafe_allow_html=True)
        if protocols:
            for proto, count in protocols.items():
                st.markdown(
                    f'<div class="mono" style="color:#8b949e;">{proto}: '
                    f'<span style="color:#e6edf3;">{count:,} events</span></div>',
                    unsafe_allow_html=True,
                )


# ── Page 2: Device Inventory ──────────────────────────────────────────────────

elif page == "Device Inventory":
    st.markdown(
        '<div class="page-header">'
        '<div>📡</div>'
        '<div><h1>Device Inventory</h1>'
        '<div class="subtitle">Passively discovered devices — built from observed network traffic</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    inv = api("/inventory", {"devices": [], "count": 0})
    devices = inv.get("devices", [])

    col_search, col_filter = st.columns([3, 1])
    with col_search:
        search = st.text_input("🔍 Search by IP, role, or hostname", placeholder="e.g. 172.20.0 or inverter")
    with col_filter:
        show_unknown_only = st.checkbox("Show unknown only")

    if search:
        devices = [
            d for d in devices
            if search.lower() in (d.get("ip", "") + d.get("role", "") + (d.get("hostname") or "")).lower()
        ]
    if show_unknown_only:
        devices = [d for d in devices if not d.get("authorised")]

    if devices:
        rows = []
        for d in devices:
            auth = d.get("authorised", 0)
            rows.append({
                "Auth": "✅" if auth else "❌ UNKNOWN",
                "IP": d.get("ip", ""),
                "Hostname": d.get("hostname") or "—",
                "Role": d.get("role", "unknown"),
                "Protocols": d.get("protocols", "[]"),
                "First Seen (UTC)": d.get("first_seen_utc", ""),
                "Last Seen (UTC)": d.get("last_seen_utc", ""),
                "Source": d.get("source", ""),
            })
        df = pd.DataFrame(rows)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Auth": st.column_config.TextColumn(width="small"),
                "IP": st.column_config.TextColumn(width="medium"),
                "First Seen (UTC)": st.column_config.TextColumn(width="medium"),
                "Last Seen (UTC)": st.column_config.TextColumn(width="medium"),
            },
        )
        st.markdown(
            f'<div style="color:#6e7681;font-size:0.78rem;">Showing {len(devices)} device(s). '
            f'Inventory built from passive traffic observation only — no active scanning.</div>',
            unsafe_allow_html=True,
        )
    else:
        st.info("No devices observed yet. Start the lab and wait for traffic to flow.")


# ── Page 3: Alerts ────────────────────────────────────────────────────────────

elif page == "Alerts":
    st.markdown(
        '<div class="page-header">'
        '<div>🚨</div>'
        '<div><h1>Alert Log</h1>'
        '<div class="subtitle">All security alerts with evidence and plain-English explanations</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        sev_filter = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
    with col_f2:
        scenario_filter = st.text_input("Scenario ID", placeholder="e.g. S1")
    with col_f3:
        status_filter = st.selectbox("Status", ["All", "open", "closed"])

    params = {}
    if sev_filter != "All":
        params["severity"] = sev_filter
    if scenario_filter:
        params["scenario_id"] = scenario_filter
    if status_filter != "All":
        params["status"] = status_filter
    params["limit"] = 200

    try:
        r = requests.get(f"{API_URL}/alerts", params=params, timeout=5)
        alerts_resp = r.json() if r.ok else {"alerts": [], "total": 0}
    except Exception:
        alerts_resp = {"alerts": [], "total": 0}

    alerts = alerts_resp.get("alerts", [])
    total = alerts_resp.get("total", 0)
    st.markdown(f'<div class="section-header">Alerts ({total} total, showing {len(alerts)})</div>', unsafe_allow_html=True)

    if alerts:
        for a in alerts:
            sev = a.get("severity", "low")
            with st.expander(
                f"{a.get('rule_name','?')} — {a.get('src_ip','?')} → {a.get('dst_ip','?')} | {sev.upper()} | {a.get('timestamp_utc','')}",
                expanded=False,
            ):
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.markdown(f"**Alert ID:** `{a.get('alert_id','')}`")
                    st.markdown(f"**Rule:** `{a.get('rule_id','')}` — {a.get('rule_name','')}")
                    st.markdown(f"**Severity:** {severity_badge(sev)}", unsafe_allow_html=True)
                    st.markdown(f"**Protocol:** `{a.get('protocol','')}`")
                    st.markdown(f"**Timestamp:** `{a.get('timestamp_utc','')}`")
                    if a.get("scenario_id"):
                        st.markdown(f"**Scenario:** `{a.get('scenario_id')}`")
                with col2:
                    st.markdown(f"**Source:** `{a.get('src_ip','?')}`")
                    st.markdown(f"**Destination:** `{a.get('dst_ip','?')}:{a.get('dst_port','?')}`")
                    st.markdown(f"**Status:** `{a.get('status','open')}`")
                    if a.get("anomaly_score") is not None:
                        st.markdown(f"**Anomaly Score:** `{a['anomaly_score']:.4f}`")

                st.markdown("**Explanation:**")
                st.info(a.get("explanation", "No explanation available"))
                if a.get("recommended_action"):
                    st.markdown("**Recommended Action:**")
                    st.warning(a.get("recommended_action"))

                evidence = a.get("evidence_json")
                if evidence:
                    try:
                        ev = json.loads(evidence)
                        st.markdown("**Evidence:**")
                        st.json(ev)
                    except Exception:
                        st.code(evidence)
    else:
        st.info("No alerts match the current filters.")


# ── Page 4: Timeline ──────────────────────────────────────────────────────────

elif page == "Timeline":
    st.markdown(
        '<div class="page-header">'
        '<div>📈</div>'
        '<div><h1>Event Timeline</h1>'
        '<div class="subtitle">Normal SCADA polling and attack event overlay</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    hours = st.slider("Time window (hours back)", 1, 24, 2)
    tl = api(f"/timeline?hours={hours}", {"events": [], "alerts": []})
    events = tl.get("events", [])
    alerts = tl.get("alerts", [])

    if events or alerts:
        event_df = pd.DataFrame(events) if events else pd.DataFrame(columns=["timestamp_utc", "protocol", "src_ip"])
        alert_df = pd.DataFrame(alerts) if alerts else pd.DataFrame(columns=["timestamp_utc", "severity", "rule_name"])

        fig = go.Figure()

        # Plot events by protocol
        if not event_df.empty and "timestamp_utc" in event_df.columns:
            for proto in event_df["protocol"].unique() if "protocol" in event_df.columns else []:
                sub = event_df[event_df["protocol"] == proto]
                fig.add_trace(go.Scatter(
                    x=sub["timestamp_utc"],
                    y=[proto] * len(sub),
                    mode="markers",
                    name=f"{proto} traffic",
                    marker=dict(size=5, color="#388bfd", opacity=0.5),
                ))

        # Plot alerts
        if not alert_df.empty and "timestamp_utc" in alert_df.columns:
            for sev in ["critical", "high", "medium", "low"]:
                sub = alert_df[alert_df.get("severity", pd.Series()) == sev] if "severity" in alert_df.columns else pd.DataFrame()
                if not sub.empty:
                    fig.add_trace(go.Scatter(
                        x=sub["timestamp_utc"],
                        y=[f"⚠ {sev.upper()}"] * len(sub),
                        mode="markers",
                        name=f"{sev} alert",
                        marker=dict(size=10, color=SEVERITY_COLORS.get(sev, "#fff"), symbol="triangle-up"),
                        text=sub.get("rule_name", ""),
                    ))

        fig.update_layout(
            **plotly_dark_layout(),
            height=380,
            title="Events & Alerts Timeline",
            xaxis_title="Time (UTC)",
            yaxis_title="Category",
        )
        st.plotly_chart(fig, use_container_width=True)

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f'<div class="section-header">Events ({len(events)})</div>', unsafe_allow_html=True)
            if events:
                st.dataframe(pd.DataFrame(events).sort_values("timestamp_utc", ascending=False).head(50), use_container_width=True, hide_index=True)
        with col2:
            st.markdown(f'<div class="section-header">Alerts ({len(alerts)})</div>', unsafe_allow_html=True)
            if alerts:
                st.dataframe(pd.DataFrame(alerts).sort_values("timestamp_utc", ascending=False), use_container_width=True, hide_index=True)
    else:
        st.info("No events or alerts in the selected window. Start the lab and run scenarios.")


# ── Page 5: Model & Sensor Health ────────────────────────────────────────────

elif page == "Model & Sensor":
    st.markdown(
        '<div class="page-header">'
        '<div>🧠</div>'
        '<div><h1>Model & Sensor Health</h1>'
        '<div class="subtitle">Anomaly model status, baseline, and capture health</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="lab-warning">⚠️ The ML model is trained on the synthetic lab baseline only. '
        'It has NOT been validated against real solar farm traffic and must not be used in production.</div>',
        unsafe_allow_html=True,
    )

    col_model, col_sensor = st.columns(2)

    with col_model:
        st.markdown('<div class="section-header">Anomaly Model (IsolationForest)</div>', unsafe_allow_html=True)
        model_status = api("/model/status", {})
        if model_status.get("loaded"):
            st.success("✅ Model loaded and ready")
            st.markdown(f"**Version:** `{model_status.get('version','?')}`")
            st.markdown(f"**Trained at:** `{model_status.get('trained_at_utc','?')}`")
            st.markdown(f"**Training samples:** `{model_status.get('n_samples','?')}`")
            st.markdown(f"**Contamination:** `{model_status.get('contamination','?')}`")
            feats = model_status.get("feature_names", [])
            if feats:
                st.markdown("**Features:**")
                for f in feats:
                    st.markdown(f"  - `{f}`")
        else:
            st.warning("⚠️ Model not yet trained")
            st.markdown(model_status.get("message", "Run 'make baseline' then 'make up' to trigger training."))

        st.markdown('<div class="section-header">Baseline Windows</div>', unsafe_allow_html=True)
        bw = api("/baseline/windows?limit=50", {"windows": []})
        windows = bw.get("windows", [])
        st.markdown(f"**Normal baseline windows stored:** `{len(windows)}`")
        if windows:
            wdf = pd.DataFrame(windows)
            st.dataframe(wdf[["window_start_utc", "src_ip", "total_requests", "write_count", "labelled"]].head(10), use_container_width=True, hide_index=True)

    with col_sensor:
        st.markdown('<div class="section-header">Sensor Health</div>', unsafe_allow_html=True)
        sensor = api("/sensor/health", {})
        if sensor and sensor.get("sensor_running") is not None:
            running = sensor.get("sensor_running", 0)
            observed = sensor.get("traffic_observed", 0)
            mode = sensor.get("capture_mode", "unknown")
            packets = sensor.get("packets_seen", 0)
            last_ts = utc_age(sensor.get("timestamp_utc", ""))

            if running and observed:
                st.success("✅ Sensor running — traffic observed")
            elif running:
                st.warning("⚠️ Sensor process running but no traffic observed yet")
            else:
                st.error("❌ Sensor not running")

            st.markdown(f"**Capture mode:** `{mode}`")
            st.markdown(f"**Packets seen:** `{packets:,}`")
            st.markdown(f"**Last protocol:** `{sensor.get('last_protocol_seen','N/A')}`")
            st.markdown(f"**Last update:** `{last_ts}`")

            if mode == "pcap_replay":
                st.info("📼 **PCAP replay mode** — Sensor is replaying a capture file. This is expected on Windows/macOS. Live capture requires Linux/WSL2.")
            elif mode == "live":
                st.success("📡 **Live capture mode** — Sensor is observing actual network traffic.")
        else:
            st.warning("No sensor health data received yet. The sensor container may not have started.")


# ── Page 6: Validation ────────────────────────────────────────────────────────

elif page == "Validation":
    st.markdown(
        '<div class="page-header">'
        '<div>📊</div>'
        '<div><h1>Validation & B.2 Metrics</h1>'
        '<div class="subtitle">Scenario-by-scenario detection outcomes — calculated from actual test runs</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="lab-warning">⚠️ All percentages are calculated from actual trial results, not hard-coded. '
        'Run <code>make evaluate</code> to populate results.</div>',
        unsafe_allow_html=True,
    )

    summary = api("/trials/summary", {})

    if not isinstance(summary, dict) or summary.get("total_trials", 0) == 0:
        st.info("No trial results yet. Run 'make evaluate' to populate validation data.")
        if isinstance(summary, dict) and summary.get("message"):
            st.caption(summary["message"])
        st.stop()
    else:
        total = summary["total_trials"]
        detected = summary.get("detected", summary.get("true_positives", 0))
        det_rate = summary.get("detection_rate_pct")
        det_rate = 0.0 if det_rate is None else det_rate
        fp_rate = summary.get("false_alarm_rate_pct")
        fp_rate = 0.0 if fp_rate is None else fp_rate
        frac_label = summary.get("detection_rate_fraction", f"{detected}/{total}")
        lat_median = summary.get("alert_latency_median_s")
        lat_p95 = summary.get("alert_latency_p95_s")
        lat_worst = summary.get("alert_latency_worst_s")

        col1, col2, col3 = st.columns(3)
        with col1:
            color = "green" if det_rate >= 95 else "amber" if det_rate >= 80 else "red"
            st.markdown(
                f'<div class="stat-card {color}"><div class="stat-value">{det_rate}%</div>'
                f'<div class="stat-label">Detection Rate ({frac_label})</div>'
                f'<div style="color:#8b949e;font-size:0.75rem;">Target: ≥95%</div></div>',
                unsafe_allow_html=True,
            )
        with col2:
            color = "green" if fp_rate < 5 else "amber" if fp_rate < 10 else "red"
            st.markdown(
                f'<div class="stat-card {color}"><div class="stat-value">{fp_rate}%</div>'
                f'<div class="stat-label">False Alarm Rate</div>'
                f'<div style="color:#8b949e;font-size:0.75rem;">Target: <5%</div></div>',
                unsafe_allow_html=True,
            )
        with col3:
            lat_disp = f"{lat_p95:.1f}s" if lat_p95 is not None else "N/A"
            color = "green" if lat_p95 is not None and lat_p95 < 900 else "amber"
            st.markdown(
                f'<div class="stat-card {color}"><div class="stat-value">{lat_disp}</div>'
                f'<div class="stat-label">Alert Latency p95</div>'
                f'<div style="color:#8b949e;font-size:0.75rem;">Target: <15min</div></div>',
                unsafe_allow_html=True,
            )

        st.markdown('<div class="section-header">Latency Details</div>', unsafe_allow_html=True)
        lcol1, lcol2, lcol3 = st.columns(3)
        with lcol1:
            st.metric("Median Latency", f"{lat_median:.1f}s" if lat_median else "N/A")
        with lcol2:
            st.metric("p95 Latency", f"{lat_p95:.1f}s" if lat_p95 else "N/A")
        with lcol3:
            st.metric("Worst Latency", f"{lat_worst:.1f}s" if lat_worst else "N/A")

        st.caption(summary.get("status_note", summary.get("note", "")))

        st.markdown('<div class="section-header">By Scenario</div>', unsafe_allow_html=True)
        by_scenario = summary.get("by_scenario", {})
        if by_scenario:
            scenario_rows = []
            for sid, data in sorted(by_scenario.items()):
                d = data.get("detected", 0)
                t = data.get("total", 0)
                rate = round(d / t * 100, 1) if t > 0 else 0
                scenario_rows.append({
                    "Scenario": sid,
                    "Detected": d,
                    "Total Trials": t,
                    "Rate": f"{rate}%",
                    "Result": "✅ PASS" if rate >= 95 else "❌ FAIL",
                })
            st.dataframe(pd.DataFrame(scenario_rows), use_container_width=True, hide_index=True)
