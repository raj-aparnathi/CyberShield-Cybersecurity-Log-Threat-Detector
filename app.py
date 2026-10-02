"""
app.py — CyberShield Streamlit Web Interface

Features:
    1. 📂  Log File Upload & Parsing
    2. 🔐  Brute-Force Detection
    3. 🚨  Suspicious Request Detection
    4. 📊  Threat Dashboard with charts
    5. ⚠️  Risk Classification (LOW / MEDIUM / HIGH)
    6. 🗄️  Threat History (MySQL) + CSV Report Download

Run with:
    streamlit run app.py
"""

import os
import sys
import io
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
import streamlit as st

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so relative imports work with Streamlit
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.log_parser import parse_log_file, parse_log_text
from analyzer.threat_detector import detect_all_threats
from analyzer.risk_analyzer import enrich_threats_with_risk
from database.db_manager import DBManager
from utils.logger import get_logger

logger = get_logger(__name__)

# Use a non-interactive backend so matplotlib doesn't try to open windows
matplotlib.use("Agg")

# ---------------------------------------------------------------------------
# Streamlit Page Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberShield — Threat Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS for a premium dark cybersecurity look
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* ---- Global ---- */
    .stApp {
        background: linear-gradient(135deg, #0a0e17 0%, #111827 50%, #0f172a 100%);
    }

    /* ---- Sidebar ---- */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #111827 0%, #1e293b 100%);
        border-right: 1px solid rgba(56,189,248,0.15);
    }

    /* ---- Metric cards ---- */
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, rgba(30,41,59,0.85), rgba(15,23,42,0.95));
        border: 1px solid rgba(56,189,248,0.2);
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 4px 24px rgba(0,0,0,0.4), inset 0 1px 0 rgba(56,189,248,0.1);
    }
    div[data-testid="stMetric"] label {
        color: #94a3b8 !important;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.08em;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-weight: 700;
        font-size: 2rem;
    }

    /* ---- Headings ---- */
    h1, h2, h3 {
        color: #e2e8f0 !important;
    }
    h1 {
        background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800 !important;
    }

    /* ---- Dataframes ---- */
    .stDataFrame {
        border: 1px solid rgba(56,189,248,0.15);
        border-radius: 8px;
        overflow: hidden;
    }

    /* ---- Buttons ---- */
    .stButton > button {
        background: linear-gradient(135deg, #1e3a5f, #1e293b);
        color: #38bdf8;
        border: 1px solid rgba(56,189,248,0.3);
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #38bdf8, #818cf8);
        color: #0f172a;
        border-color: #38bdf8;
        box-shadow: 0 0 20px rgba(56,189,248,0.4);
    }

    /* ---- File uploader ---- */
    section[data-testid="stFileUploader"] {
        border: 2px dashed rgba(56,189,248,0.3);
        border-radius: 12px;
        padding: 12px;
    }

    /* ---- Alert boxes ---- */
    .threat-alert {
        background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(220,38,38,0.08));
        border-left: 4px solid #ef4444;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 8px 0;
        color: #fca5a5;
    }
    .success-box {
        background: linear-gradient(135deg, rgba(34,197,94,0.15), rgba(22,163,74,0.08));
        border-left: 4px solid #22c55e;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 8px 0;
        color: #86efac;
    }
    .info-box {
        background: linear-gradient(135deg, rgba(56,189,248,0.12), rgba(59,130,246,0.08));
        border-left: 4px solid #38bdf8;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 8px 0;
        color: #93c5fd;
    }

    /* ---- Tabs ---- */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        background: rgba(30,41,59,0.6);
        border-radius: 8px 8px 0 0;
        border: 1px solid rgba(56,189,248,0.15);
        color: #94a3b8;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background: rgba(56,189,248,0.15) !important;
        color: #38bdf8 !important;
        border-bottom: 2px solid #38bdf8;
    }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("## 🛡️ CyberShield")
    st.caption("Cybersecurity Log Threat Detector")

    st.markdown("---")

    st.markdown("### 📂 Upload Log File")
    uploaded_file = st.file_uploader(
        "Choose a `.log` file",
        type=["log", "txt"],
        help="Upload a server log file in the format:  TIMESTAMP | IP | EVENT | STATUS"
    )

    use_sample = st.checkbox("Use sample log file", value=True)

    st.markdown("---")

    st.markdown("### 🗄️ MySQL Settings")
    db_host = st.text_input("Host", value="localhost")
    db_user = st.text_input("User", value="root")
    db_password = st.text_input("Password", type="password", value="")
    db_name = st.text_input("Database", value="cybershield")

    save_to_db = st.checkbox("Save threats to MySQL", value=False)

    st.markdown("---")
    st.markdown(
        "<div style='text-align:center; color:#475569; font-size:0.75rem;'>"
        "Built with ❤️ using Python & Streamlit"
        "</div>",
        unsafe_allow_html=True
    )


# ═══════════════════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("# 🛡️ CyberShield")
st.markdown(
    "<p style='color:#94a3b8; font-size:1.1rem; margin-top:-10px;'>"
    "Real-time cybersecurity log analysis &amp; threat detection dashboard"
    "</p>",
    unsafe_allow_html=True,
)

# ═══════════════════════════════════════════════════════════════════════════
# STEP 1 — PARSE LOGS
# ═══════════════════════════════════════════════════════════════════════════
logs = []

if uploaded_file is not None:
    raw_text = uploaded_file.read().decode("utf-8")
    logs = parse_log_text(raw_text)
    st.markdown(
        f'<div class="success-box">✅ Uploaded file parsed — '
        f'<strong>{len(logs)}</strong> log entries extracted.</div>',
        unsafe_allow_html=True,
    )
elif use_sample:
    sample_path = os.path.join(PROJECT_ROOT, "data", "sample_server.log")
    logs = parse_log_file(sample_path)
    st.markdown(
        f'<div class="info-box">ℹ️ Using sample log file — '
        f'<strong>{len(logs)}</strong> entries loaded.</div>',
        unsafe_allow_html=True,
    )
else:
    st.info("👆 Upload a log file or enable the sample log to begin analysis.")
    st.stop()

# Build a DataFrame of all log entries
df_logs = pd.DataFrame(logs)

# ═══════════════════════════════════════════════════════════════════════════
# STEP 2 — DETECT THREATS & ASSIGN RISK
# ═══════════════════════════════════════════════════════════════════════════
threats = detect_all_threats(logs)
threats = enrich_threats_with_risk(threats)

# ═══════════════════════════════════════════════════════════════════════════
# STEP 3 — KEY METRICS (top of dashboard)
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("---")

total_logs = len(logs)
failed_logins = sum(1 for l in logs if l["event"] == "LOGIN_FAILED")
suspicious_ips = len({t["ip"] for t in threats})
total_threats = len(threats)

col1, col2, col3, col4 = st.columns(4)
col1.metric("📋 Total Log Entries", total_logs)
col2.metric("🔐 Failed Logins", failed_logins)
col3.metric("🌐 Suspicious IPs", suspicious_ips)
col4.metric("🚨 Threats Detected", total_threats)

# ═══════════════════════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════════════════════
tab_dashboard, tab_logs, tab_threats, tab_history, tab_report = st.tabs([
    "📊 Dashboard",
    "📜 Parsed Logs",
    "🚨 Threat Details",
    "🗄️ Threat History",
    "📥 Download Report",
])

# ── TAB 1: Dashboard (charts) ────────────────────────────────────────────
with tab_dashboard:
    if threats:
        chart_col1, chart_col2 = st.columns(2)

        # --- Threat Type Distribution ---
        with chart_col1:
            st.markdown("#### Threat Type Distribution")
            threat_types = pd.Series([t["threat"] for t in threats]).value_counts()

            fig1, ax1 = plt.subplots(figsize=(5, 3.5))
            fig1.patch.set_facecolor("#0f172a")
            ax1.set_facecolor("#0f172a")

            colors_bar = ["#ef4444", "#f59e0b", "#38bdf8", "#a78bfa", "#34d399"]
            bars = ax1.barh(
                threat_types.index,
                threat_types.values,
                color=colors_bar[:len(threat_types)],
                edgecolor="none",
                height=0.5,
            )
            # Add value labels
            for bar in bars:
                width = bar.get_width()
                ax1.text(
                    width + 0.1, bar.get_y() + bar.get_height() / 2,
                    f"{int(width)}", va="center", color="#e2e8f0",
                    fontweight="bold", fontsize=11,
                )

            ax1.set_xlabel("Count", color="#94a3b8", fontsize=10)
            ax1.tick_params(colors="#94a3b8")
            ax1.spines["top"].set_visible(False)
            ax1.spines["right"].set_visible(False)
            ax1.spines["bottom"].set_color("#334155")
            ax1.spines["left"].set_color("#334155")
            plt.tight_layout()
            st.pyplot(fig1)

        # --- Risk Distribution Pie ---
        with chart_col2:
            st.markdown("#### Risk Level Distribution")
            risk_counts = pd.Series([t["risk"] for t in threats]).value_counts()

            fig2, ax2 = plt.subplots(figsize=(5, 3.5))
            fig2.patch.set_facecolor("#0f172a")
            ax2.set_facecolor("#0f172a")

            risk_colors = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#22c55e"}
            pie_colors = [risk_colors.get(r, "#64748b") for r in risk_counts.index]

            wedges, texts, autotexts = ax2.pie(
                risk_counts.values,
                labels=risk_counts.index,
                autopct="%1.0f%%",
                colors=pie_colors,
                startangle=140,
                textprops={"color": "#e2e8f0", "fontweight": "bold"},
                wedgeprops={"edgecolor": "#0f172a", "linewidth": 2},
            )
            for t in autotexts:
                t.set_color("#0f172a")
                t.set_fontsize(11)
            plt.tight_layout()
            st.pyplot(fig2)

        # --- Event Frequency Bar Chart ---
        st.markdown("#### 📈 Event Frequency Overview")
        event_counts = df_logs["event"].value_counts()

        fig3, ax3 = plt.subplots(figsize=(10, 3.5))
        fig3.patch.set_facecolor("#0f172a")
        ax3.set_facecolor("#0f172a")

        bar_colors = []
        for evt in event_counts.index:
            if evt == "LOGIN_FAILED":
                bar_colors.append("#ef4444")
            elif evt in ("UNAUTHORIZED_ACCESS", "FORBIDDEN_REQUEST"):
                bar_colors.append("#f59e0b")
            else:
                bar_colors.append("#22c55e")

        bars3 = ax3.bar(
            event_counts.index, event_counts.values,
            color=bar_colors, edgecolor="none", width=0.5,
        )
        for bar in bars3:
            height = bar.get_height()
            ax3.text(
                bar.get_x() + bar.get_width() / 2, height + 0.2,
                f"{int(height)}", ha="center", color="#e2e8f0",
                fontweight="bold", fontsize=11,
            )

        ax3.set_ylabel("Count", color="#94a3b8")
        ax3.tick_params(colors="#94a3b8", axis="both")
        ax3.spines["top"].set_visible(False)
        ax3.spines["right"].set_visible(False)
        ax3.spines["bottom"].set_color("#334155")
        ax3.spines["left"].set_color("#334155")
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()
        st.pyplot(fig3)

    else:
        st.markdown(
            '<div class="success-box">✅ No threats detected — all clear!</div>',
            unsafe_allow_html=True,
        )

# ── TAB 2: Parsed Logs ───────────────────────────────────────────────────
with tab_logs:
    st.markdown("#### 📜 All Parsed Log Entries")
    st.dataframe(df_logs, use_container_width=True, height=400)

# ── TAB 3: Threat Details ────────────────────────────────────────────────
with tab_threats:
    if threats:
        for i, t in enumerate(threats, 1):
            risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(t["risk"], "⚪")
            alert_html = f"""
            <div class="threat-alert">
                <strong>{risk_emoji} Threat #{i} — {t['threat']}</strong><br>
                <table style="color:#e2e8f0; margin-top:8px;">
                    <tr><td style="padding-right:16px;"><strong>IP Address:</strong></td>
                        <td><code>{t['ip']}</code></td></tr>
                    <tr><td><strong>Occurrences:</strong></td>
                        <td>{t['count']}</td></tr>
                    <tr><td><strong>Risk Level:</strong></td>
                        <td><span style="font-weight:700;">{t['risk']}</span></td></tr>
                </table>
            </div>
            """
            st.markdown(alert_html, unsafe_allow_html=True)

        # Summary table
        st.markdown("#### 📋 Threat Summary Table")
        df_threats = pd.DataFrame([
            {
                "Threat": t["threat"],
                "IP": t["ip"],
                "Occurrences": t["count"],
                "Risk": t["risk"],
            }
            for t in threats
        ])
        st.dataframe(df_threats, use_container_width=True)
    else:
        st.success("No threats detected.")

# ── TAB 4: Threat History (MySQL) ────────────────────────────────────────
with tab_history:
    st.markdown("#### 🗄️ Threat History (MySQL Database)")

    if save_to_db and threats:
        db = DBManager(config={
            "host": db_host,
            "user": db_user,
            "password": db_password,
            "database": db_name,
        })

        if db.connect():
            db.create_table()
            db.insert_threats(threats)
            st.markdown(
                '<div class="success-box">✅ Threats saved to MySQL database.</div>',
                unsafe_allow_html=True,
            )

            history = db.get_all_threats()
            db.close()

            if history:
                df_history = pd.DataFrame(history)
                st.dataframe(df_history, use_container_width=True, height=400)
            else:
                st.info("No historical records found.")
        else:
            st.error(
                "❌ Could not connect to MySQL. Please check your credentials "
                "in the sidebar and ensure the database exists."
            )
            st.markdown(
                '<div class="info-box">'
                '<strong>💡 Setup Tip:</strong> Run the following in MySQL:<br>'
                '<code>CREATE DATABASE IF NOT EXISTS cybershield;</code>'
                '</div>',
                unsafe_allow_html=True,
            )
    elif not save_to_db:
        st.info("Enable **'Save threats to MySQL'** in the sidebar to store and view history.")
    else:
        st.info("No threats to save.")

# ── TAB 5: Download Report ───────────────────────────────────────────────
with tab_report:
    st.markdown("#### 📥 Download Threat Report (CSV)")

    if threats:
        df_report = pd.DataFrame([
            {
                "Timestamp": t["events"][0] if t.get("events") else "",
                "IP Address": t["ip"],
                "Threat Type": t["threat"],
                "Occurrences": t["count"],
                "Risk Level": t["risk"],
            }
            for t in threats
        ])

        st.dataframe(df_report, use_container_width=True)

        # Save to reports/ folder
        reports_dir = os.path.join(PROJECT_ROOT, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        report_path = os.path.join(reports_dir, "reports.csv")
        df_report.to_csv(report_path, index=False)

        # Offer download button
        csv_buffer = io.StringIO()
        df_report.to_csv(csv_buffer, index=False)

        st.download_button(
            label="⬇️  Download Report as CSV",
            data=csv_buffer.getvalue(),
            file_name="cybershield_threat_report.csv",
            mime="text/csv",
        )

        st.markdown(
            f'<div class="success-box">'
            f'📁 Report also saved locally at: <code>{report_path}</code>'
            f'</div>',
            unsafe_allow_html=True,
        )
    else:
        st.info("No threats to report.")

# ═══════════════════════════════════════════════════════════════════════════
# FOOTER
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown(
    "<div style='text-align:center; color:#475569; font-size:0.8rem; padding:16px;'>"
    "🛡️ <strong>CyberShield</strong> — Cybersecurity Log Threat Detector  •  "
    "Powered by Python, Streamlit, Pandas &amp; MySQL"
    "</div>",
    unsafe_allow_html=True,
)
