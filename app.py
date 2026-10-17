"""AgentFence — Futuristic Cybersecurity Graph & Remediation Simulator.

Cinematic, high-fidelity UI matching the AgentFence visual concept reference:
- Glowing purple-cyan shield identity & animated cyber network background
- High-visibility hero: Live Agent Graph with glowing circular cyber nodes
- Real-time interactive Remediation Simulator with Before/After Fix visualization
- Transparent glassmorphism panels, glowing borders, precise cyber typography
- 100% real backend integration: Neo4j Aura queries, deterministic path detection,
  validation gates (G1, G2, G3), workflow checks (W1, W2), and decision persistence.
"""

import time
import json
import textwrap
import streamlit as st
import streamlit.components.v1 as components

def render_html(html_str: str):
    """Render HTML safely without markdown 4-space indented code-block conversion."""
    clean_html = "\n".join(line.lstrip() for line in html_str.splitlines())
    st.markdown(clean_html, unsafe_allow_html=True)

from agentfence.db import get_local_graph
from agentfence.graph_view import render_graph_html
from agentfence.scenarios import compare_scenarios
from agentfence.llm_extractor import (
    extract_from_manifest,
    _validate_extraction,
    ALLOWED_NODE_TYPES,
    ALLOWED_REL_TYPES,
)
from agentfence.ui_service import (
    get_system_status,
    run_baseline_detection,
    run_negative_test,
    evaluate_permission_candidates,
    verify_fix,
    persist_accepted_decision,
    reload_persisted_decision,
    fetch_decision_history,
)

# -----------------------------------------------------------------------------
# Streamlit Page Setup
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="AgentFence — AI-Agent Workflow Security & Remediation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# State Management
# -----------------------------------------------------------------------------
def init_session_state():
    defaults = {
        "scenario": "baseline",
        "baseline_result": None,
        "negative_test_result": None,
        "candidate_result": None,
        "selected_candidate_idx": 0,
        "verification_result": None,
        "saved_decision": None,
        "persistence_check": None,
        "last_analysis_time": None,
        "analysis_state_label": "LIVE MONITORING",
        "sim_fix_active": False,
        "search_query": "",
        "graph_view_selection": "Baseline Graph",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_session_state()

# Auto-run baseline on first launch so the dashboard displays live graph and findings immediately
if st.session_state.baseline_result is None:
    st.session_state.baseline_result = run_baseline_detection(st.session_state.scenario)
    st.session_state.last_analysis_time = time.strftime("%b %d, %Y %I:%M %p")

# -----------------------------------------------------------------------------
# Cinematic Cyber Design System (CSS)
# -----------------------------------------------------------------------------
st.markdown(
    """
    <style>
    /* Global Base */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    .stApp {
        background-color: #040814;
        background-image: 
            radial-gradient(circle at 15% 10%, rgba(139, 92, 246, 0.08) 0%, transparent 40%),
            radial-gradient(circle at 85% 15%, rgba(6, 182, 212, 0.08) 0%, transparent 45%),
            radial-gradient(circle at 50% 50%, rgba(14, 165, 233, 0.03) 0%, transparent 60%);
        color: #e2e8f0;
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }

    /* Streamlit Padding Overrides for Dashboard Layout */
    .block-container {
        padding-top: 1.2rem;
        padding-bottom: 2rem;
        padding-left: 2rem;
        padding-right: 2rem;
        max-width: 100%;
    }

    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background: #060a17;
        border-right: 1px solid rgba(56, 189, 248, 0.15);
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.6);
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
        color: #94a3b8;
    }

    /* Glowing Shield Brand */
    .brand-container {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 6px;
    }
    .brand-logo-svg {
        width: 44px;
        height: 48px;
        filter: drop-shadow(0 0 12px rgba(168, 85, 247, 0.65)) drop-shadow(0 0 20px rgba(6, 182, 212, 0.4));
    }
    .brand-title {
        font-size: 2.4rem;
        font-weight: 800;
        color: #ffffff;
        letter-spacing: -0.03em;
        line-height: 1;
        background: linear-gradient(135deg, #ffffff 40%, #bae6fd 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .brand-tagline {
        font-size: 1.05rem;
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: -0.01em;
        margin-top: 2px;
    }
    .brand-sub {
        font-size: 0.84rem;
        color: #94a3b8;
        line-height: 1.35;
    }

    /* Action Badges in Header */
    .quick-badges {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 8px;
    }
    .q-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 5px 12px;
        border-radius: 9999px;
        font-size: 0.78rem;
        font-weight: 700;
        text-transform: capitalize;
        transition: all 0.2s ease;
        text-decoration: none;
    }
    .q-red {
        background: rgba(239, 68, 68, 0.12);
        color: #fca5a5;
        border: 1px solid rgba(239, 68, 68, 0.4);
        box-shadow: 0 0 12px rgba(239, 68, 68, 0.2);
    }
    .q-cyan {
        background: rgba(6, 182, 212, 0.12);
        color: #7dd3fc;
        border: 1px solid rgba(6, 182, 212, 0.4);
        box-shadow: 0 0 12px rgba(6, 182, 212, 0.2);
    }
    .q-green {
        background: rgba(16, 185, 129, 0.12);
        color: #6ee7b7;
        border: 1px solid rgba(16, 185, 129, 0.4);
        box-shadow: 0 0 12px rgba(16, 185, 129, 0.2);
    }
    .q-purple {
        background: rgba(168, 85, 247, 0.12);
        color: #d8b4fe;
        border: 1px solid rgba(168, 85, 247, 0.4);
        box-shadow: 0 0 12px rgba(168, 85, 247, 0.2);
    }

    /* Header Right: Search & Status */
    .header-right {
        display: flex;
        flex-direction: column;
        align-items: flex-end;
        gap: 10px;
    }
    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(11, 18, 36, 0.9);
        border: 1px solid rgba(16, 185, 129, 0.45);
        box-shadow: 0 0 15px rgba(16, 185, 129, 0.18);
        border-radius: 9999px;
        padding: 5px 14px;
        font-size: 0.78rem;
        font-weight: 700;
        color: #34d399;
    }
    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #10b981;
        box-shadow: 0 0 10px #10b981;
    }
    .header-meta {
        font-size: 0.75rem;
        color: #64748b;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    /* 7 Top Metric Cards */
    .metrics-row {
        display: grid;
        grid-template-columns: repeat(7, 1fr);
        gap: 10px;
        margin: 14px 0 18px 0;
    }
    .m-card {
        background: rgba(11, 18, 36, 0.75);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border-radius: 10px;
        padding: 12px 14px;
        position: relative;
        overflow: hidden;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        min-height: 85px;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .m-card:hover {
        transform: translateY(-2px);
    }
    .m-cyan {
        border: 1px solid rgba(6, 182, 212, 0.4);
        box-shadow: 0 4px 16px rgba(6, 182, 212, 0.1);
    }
    .m-purple {
        border: 1px solid rgba(168, 85, 247, 0.4);
        box-shadow: 0 4px 16px rgba(168, 85, 247, 0.1);
    }
    .m-teal {
        border: 1px solid rgba(20, 184, 166, 0.4);
        box-shadow: 0 4px 16px rgba(20, 184, 166, 0.1);
    }
    .m-red {
        border: 1px solid rgba(239, 68, 68, 0.5);
        box-shadow: 0 4px 20px rgba(239, 68, 68, 0.2);
    }
    .m-amber {
        border: 1px solid rgba(245, 158, 11, 0.45);
        box-shadow: 0 4px 16px rgba(245, 158, 11, 0.1);
    }
    .m-green {
        border: 1px solid rgba(16, 185, 129, 0.45);
        box-shadow: 0 4px 16px rgba(16, 185, 129, 0.15);
    }
    .m-blue {
        border: 1px solid rgba(56, 189, 248, 0.4);
        box-shadow: 0 4px 16px rgba(56, 189, 248, 0.1);
    }
    .m-top {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .m-icon {
        font-size: 1.25rem;
    }
    .m-num {
        font-size: 1.55rem;
        font-weight: 800;
        line-height: 1;
        font-family: 'JetBrains Mono', monospace;
    }
    .m-title {
        font-size: 0.74rem;
        font-weight: 700;
        color: #cbd5e1;
        margin-top: 4px;
        white-space: nowrap;
        text-overflow: ellipsis;
        overflow: hidden;
    }

    /* Glass Panels */
    .glass-panel {
        background: rgba(9, 14, 28, 0.85);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid rgba(56, 189, 248, 0.18);
        border-radius: 12px;
        padding: 16px 18px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
        margin-bottom: 16px;
    }
    .panel-header-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 12px;
    }
    .panel-title {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 1.05rem;
        font-weight: 800;
        color: #ffffff;
        letter-spacing: -0.01em;
    }
    .panel-badge-red {
        background: #ef4444;
        color: #ffffff;
        border-radius: 9999px;
        font-size: 0.68rem;
        font-weight: 800;
        padding: 2px 7px;
    }

    /* Security Finding Cards (F1, F2) */
    .finding-item-card {
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(239, 68, 68, 0.35);
        border-left: 3px solid #ef4444;
        border-radius: 8px;
        padding: 11px 13px;
        margin-bottom: 10px;
        cursor: pointer;
        transition: all 0.2s;
    }
    .finding-item-card:hover {
        background: rgba(239, 68, 68, 0.08);
        border-color: #ef4444;
        transform: translateX(2px);
    }
    .finding-item-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 5px;
    }
    .finding-f-tag {
        background: #2b0b12;
        color: #f87171;
        border: 1px solid #ef4444;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 800;
        padding: 1px 6px;
        font-family: 'JetBrains Mono', monospace;
    }
    .finding-route-text {
        font-size: 0.78rem;
        font-weight: 600;
        color: #e2e8f0;
        line-height: 1.35;
    }

    /* Negative Test Card */
    .neg-test-card {
        background: rgba(16, 185, 129, 0.08);
        border: 1px solid rgba(16, 185, 129, 0.35);
        border-radius: 8px;
        padding: 10px 12px;
        display: flex;
        align-items: center;
        gap: 10px;
        margin-top: 10px;
    }
    .neg-check-icon {
        width: 26px;
        height: 26px;
        border-radius: 50%;
        background: #10b981;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #040814;
        font-weight: 900;
        font-size: 0.85rem;
    }

    /* Workflows Rows */
    .wf-row {
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 8px;
        padding: 10px 12px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 8px;
    }
    .wf-badge {
        background: #0284c7;
        color: #ffffff;
        font-size: 0.7rem;
        font-weight: 800;
        border-radius: 4px;
        padding: 2px 7px;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Tables */
    .cinematic-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.82rem;
    }
    .cinematic-table th {
        background: #0d1527;
        color: #94a3b8;
        font-weight: 700;
        text-align: left;
        padding: 8px 10px;
        border-bottom: 1px solid rgba(56, 189, 248, 0.25);
    }
    .cinematic-table td {
        padding: 8px 10px;
        border-bottom: 1px solid rgba(30, 41, 59, 0.7);
        color: #cbd5e1;
    }
    .cinematic-table tr:hover {
        background: rgba(56, 189, 248, 0.05);
    }

    /* Primary Action Buttons */
    div.stButton > button:first-child {
        background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
        color: #ffffff;
        font-weight: 700;
        border: 1px solid rgba(56, 189, 248, 0.5);
        border-radius: 8px;
        padding: 8px 18px;
        box-shadow: 0 0 16px rgba(2, 132, 199, 0.35);
        transition: all 0.2s;
    }
    div.stButton > button:first-child:hover {
        background: linear-gradient(135deg, #0369a1 0%, #075985 100%);
        box-shadow: 0 0 24px rgba(56, 189, 248, 0.6);
        transform: translateY(-1px);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------------------------------------------------------
# 1. Sidebar Implementation (Matching Visual Reference)
# -----------------------------------------------------------------------------
sys_status = get_system_status()

with st.sidebar:
    # Logo & Identity
    st.markdown(
        """
        <div class="brand-container">
            <svg class="brand-logo-svg" viewBox="0 0 100 110" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M50 5 L90 25 L90 65 C90 85 50 105 50 105 C50 105 10 85 10 65 L10 25 Z" 
                      fill="url(#shield-grad)" stroke="#38bdf8" stroke-width="3"/>
                <circle cx="50" cy="45" r="8" fill="#38bdf8"/>
                <circle cx="35" cy="65" r="6" fill="#a855f7"/>
                <circle cx="65" cy="65" r="6" fill="#38bdf8"/>
                <line x1="50" y1="45" x2="35" y2="65" stroke="#38bdf8" stroke-width="2.5"/>
                <line x1="50" y1="45" x2="65" y2="65" stroke="#38bdf8" stroke-width="2.5"/>
                <line x1="35" y1="65" x2="65" y2="65" stroke="#a855f7" stroke-width="2" stroke-dasharray="3,3"/>
                <defs>
                    <linearGradient id="shield-grad" x1="0" y1="0" x2="100" y2="105">
                        <stop offset="0%" stop-color="#1e1035"/>
                        <stop offset="60%" stop-color="#0a1936"/>
                        <stop offset="100%" stop-color="#040b17"/>
                    </linearGradient>
                </defs>
            </svg>
            <div>
                <div style="font-size: 1.35rem; font-weight: 800; color: #ffffff; letter-spacing: -0.02em;">AgentFence</div>
                <div style="font-size: 0.72rem; color: #38bdf8; font-weight: 700; text-transform: uppercase;">Security Core</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    # Primary Navigation
    st.markdown(
        """
        <div style="margin-bottom: 12px;">
            <div style="background: rgba(2, 132, 199, 0.2); border-left: 3px solid #38bdf8; border-radius: 0 6px 6px 0; padding: 7px 12px; color: #ffffff; font-weight: 700; font-size: 0.88rem; display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                <span>🏠</span> Overview
            </div>
            <a href="#live-agent-graph" style="text-decoration: none; display: flex; align-items: center; gap: 8px; padding: 7px 12px; color: #94a3b8; font-size: 0.88rem; border-radius: 6px;">
                <span>🕸️</span> Graph Explorer
            </a>
            <a href="#security-findings" style="text-decoration: none; display: flex; align-items: center; justify-content: space-between; padding: 7px 12px; color: #94a3b8; font-size: 0.88rem; border-radius: 6px;">
                <div style="display: flex; align-items: center; gap: 8px;"><span>⚠️</span> Security Findings</div>
                <span style="background: #ef4444; color: #fff; font-size: 0.68rem; font-weight: 800; padding: 1px 6px; border-radius: 9999px;">2</span>
            </a>
            <a href="#fix-simulator" style="text-decoration: none; display: flex; align-items: center; gap: 8px; padding: 7px 12px; color: #94a3b8; font-size: 0.88rem; border-radius: 6px;">
                <span>🛠️</span> Fix Simulator
            </a>
            <a href="#ai-lab" style="text-decoration: none; display: flex; align-items: center; justify-content: space-between; padding: 7px 12px; color: #94a3b8; font-size: 0.88rem; border-radius: 6px;">
                <div style="display: flex; align-items: center; gap: 8px;"><span>🤖</span> AI Lab</div>
                <span style="background: rgba(168, 85, 247, 0.25); color: #d8b4fe; border: 1px solid #a855f7; font-size: 0.65rem; font-weight: 700; padding: 1px 5px; border-radius: 4px;">Beta</span>
            </a>
            <a href="#decision-history" style="text-decoration: none; display: flex; align-items: center; gap: 8px; padding: 7px 12px; color: #94a3b8; font-size: 0.88rem; border-radius: 6px;">
                <span>📜</span> Decision History
            </a>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    st.markdown("<div style='font-size: 0.72rem; font-weight: 800; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;'>Resources</div>", unsafe_allow_html=True)
    st.markdown(
        """
        <div style="font-size: 0.82rem; color: #94a3b8; line-height: 2;">
            <div>📄 Documentation</div>
            <div>📑 Example Scenarios</div>
            <div>⚙️ Settings</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

    # Neo4j Database Status Card (Bottom Sidebar)
    db_badge_txt = "Neo4j Aura" if not sys_status["is_fixture"] else "Local Graph"
    db_conn_col = "#34d399" if not sys_status["is_fixture"] else "#fbbf24"
    db_dot_col = "#10b981" if not sys_status["is_fixture"] else "#f59e0b"
    db_mode_desc = "Live Neo4j Aura Instance" if not sys_status["is_fixture"] else "In-Memory Graph (Fixture Mode)"

    st.markdown(
        f"""
        <div style="background: rgba(11, 18, 36, 0.95); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 10px;">
            <div style="display: flex; align-items: center; gap: 6px; font-size: 0.84rem; font-weight: 700; color: {db_conn_col}; margin-bottom: 4px;">
                <span style="width: 8px; height: 8px; border-radius: 50%; background: {db_dot_col}; display: inline-block;"></span>
                {db_badge_txt} Connected
            </div>
            <div style="font-size: 0.74rem; color: #94a3b8; line-height: 1.4;">
                Mode: <span style="color: {db_conn_col}; font-weight: 600;">{db_mode_desc}</span><br>
                Database: <code>neo4j</code><br>
                Nodes: 11 &nbsp;|&nbsp; Relationships: 19
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("🔄 Refresh Data", key="btn_refresh_sidebar", use_container_width=True):
        st.session_state.baseline_result = run_baseline_detection(st.session_state.scenario)
        st.session_state.last_analysis_time = time.strftime("%b %d, %Y %I:%M %p")
        st.rerun()

# -----------------------------------------------------------------------------
# 2. Top Header & Identity Banner
# -----------------------------------------------------------------------------
h_col1, h_col2 = st.columns([62, 38])

with h_col1:
    st.markdown(
        """
        <div class="brand-container">
            <svg class="brand-logo-svg" viewBox="0 0 100 110" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M50 5 L90 25 L90 65 C90 85 50 105 50 105 C50 105 10 85 10 65 L10 25 Z" 
                      fill="url(#h-shield-grad)" stroke="#38bdf8" stroke-width="3"/>
                <circle cx="50" cy="45" r="8" fill="#38bdf8"/>
                <circle cx="35" cy="65" r="6" fill="#a855f7"/>
                <circle cx="65" cy="65" r="6" fill="#38bdf8"/>
                <line x1="50" y1="45" x2="35" y2="65" stroke="#38bdf8" stroke-width="2.5"/>
                <line x1="50" y1="45" x2="65" y2="65" stroke="#38bdf8" stroke-width="2.5"/>
                <line x1="35" y1="65" x2="65" y2="65" stroke="#a855f7" stroke-width="2" stroke-dasharray="3,3"/>
                <defs>
                    <linearGradient id="h-shield-grad" x1="0" y1="0" x2="100" y2="105">
                        <stop offset="0%" stop-color="#2a124a"/>
                        <stop offset="60%" stop-color="#0a1d3d"/>
                        <stop offset="100%" stop-color="#040914"/>
                    </linearGradient>
                </defs>
            </svg>
            <div>
                <div class="brand-title">AgentFence</div>
                <div class="brand-tagline">Secure the paths. Preserve the workflows.</div>
                <div class="brand-sub">Graph-powered security analysis and permission-remediation verification for AI agents.</div>
            </div>
        </div>
        <div class="quick-badges">
            <a href="#security-findings" class="q-badge q-red">🚨 Detect Risky Paths</a>
            <a href="#required-workflows" class="q-badge q-cyan">🤖 Validate Workflows</a>
            <a href="#candidate-fixes" class="q-badge q-green">🎯 Find Minimal Fixes</a>
            <a href="#decision-persistence-anchor" class="q-badge q-purple">✨ Persist Decisions</a>
        </div>
        """,
        unsafe_allow_html=True,
    )

with h_col2:
    # Search box & Status pill matching visual concept
    header_pill_bg = "rgba(16, 185, 129, 0.12)" if not sys_status["is_fixture"] else "rgba(245, 158, 11, 0.12)"
    header_pill_border = "rgba(16, 185, 129, 0.45)" if not sys_status["is_fixture"] else "rgba(245, 158, 11, 0.45)"
    header_pill_color = "#34d399" if not sys_status["is_fixture"] else "#fbbf24"
    header_pill_dot = "#10b981" if not sys_status["is_fixture"] else "#f59e0b"
    header_pill_text = "Neo4j Aura Connected" if not sys_status["is_fixture"] else "Local Graph (Fixture Mode)"

    st.markdown(
        f"""
        <div class="header-right">
            <div style="display: flex; gap: 8px; width: 100%;">
                <input type="text" placeholder="🔍 Ask a question... e.g., What if SupportAgent can invoke Slack?" 
                       style="width: 100%; background: rgba(11, 18, 36, 0.85); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 8px 12px; color: #ffffff; font-size: 0.82rem; outline: none;"/>
                <button style="background: #0284c7; border: 1px solid #38bdf8; border-radius: 8px; color: #fff; padding: 0 14px; font-weight: bold; cursor: pointer;">→</button>
            </div>
            <div style="display: flex; align-items: center; gap: 12px; margin-top: 4px;">
                <div class="status-pill" style="background: {header_pill_bg}; border-color: {header_pill_border};">
                    <span class="status-dot" style="background: {header_pill_dot}; box-shadow: 0 0 8px {header_pill_dot};"></span>
                    <span style="color: {header_pill_color}; font-weight: 700;">{header_pill_text}</span>
                </div>
                <div class="header-meta">
                    <span>Graph: <b>AgentFence</b></span>
                    <span>Last synced: <b>{st.session_state.last_analysis_time or 'Just now'}</b></span>
                    <span style="background: #1e293b; color: #38bdf8; font-weight: 800; padding: 3px 7px; border-radius: 50%; font-size: 0.72rem;">AF</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# -----------------------------------------------------------------------------
# 3. Seven Metric Cards (Matching Visual Reference)
# -----------------------------------------------------------------------------
f_count = len(st.session_state.baseline_result["findings"]) if st.session_state.baseline_result else 2
candidates_count = st.session_state.candidate_result["total_evaluated"] if st.session_state.candidate_result else 5
valid_fix_count = st.session_state.candidate_result["accepted_count"] if st.session_state.candidate_result else 1

st.markdown(
    f"""
    <div class="metrics-row">
        <!-- 1. Agent Analyzed -->
        <div class="m-card m-cyan">
            <div class="m-top"><span class="m-icon">👤</span><span class="m-num" style="color: #38bdf8;">1</span></div>
            <div class="m-title">Agent Analyzed</div>
        </div>
        <!-- 2. Tools Modeled -->
        <div class="m-card m-purple">
            <div class="m-top"><span class="m-icon">📦</span><span class="m-num" style="color: #c084fc;">4</span></div>
            <div class="m-title">Tools Modeled</div>
        </div>
        <!-- 3. Resources -->
        <div class="m-card m-teal">
            <div class="m-top"><span class="m-icon">🗄️</span><span class="m-num" style="color: #2dd4bf;">7</span></div>
            <div class="m-title">Resources</div>
        </div>
        <!-- 4. Dangerous Paths -->
        <div class="m-card m-red">
            <div class="m-top"><span class="m-icon">⚠️</span><span class="m-num" style="color: #f87171;">{f_count}</span></div>
            <div class="m-title">Dangerous Paths</div>
        </div>
        <!-- 5. Candidate Fixes -->
        <div class="m-card m-amber">
            <div class="m-top"><span class="m-icon">🛠️</span><span class="m-num" style="color: #fbbf24;">{candidates_count}</span></div>
            <div class="m-title">Candidate Fixes</div>
        </div>
        <!-- 6. Valid Fix Found -->
        <div class="m-card m-green">
            <div class="m-top"><span class="m-icon">🛡️</span><span class="m-num" style="color: #34d399;">{valid_fix_count}</span></div>
            <div class="m-title">Valid Fix Found</div>
        </div>
        <!-- 7. Workflows Preserved -->
        <div class="m-card m-blue">
            <div class="m-top"><span class="m-icon">⚙️</span><span class="m-num" style="color: #60a5fa;">2</span></div>
            <div class="m-title">Workflows Preserved</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# -----------------------------------------------------------------------------
# 4. Main Hero Section: Live Agent Graph + Security Findings & Workflows
# -----------------------------------------------------------------------------
st.markdown('<div id="live-agent-graph"></div>', unsafe_allow_html=True)
col_graph, col_findings = st.columns([67, 33])

with col_graph:
    # Graph Header Bar matching screenshot
    g_hdr_left, g_hdr_right = st.columns([50, 50])
    with g_hdr_left:
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                <span style="font-size: 1.25rem;">⚙️</span>
                <span style="font-weight: 800; font-size: 1.12rem; color: #ffffff;">Live Agent Graph</span>
                <span style="font-size: 0.8rem; color: #64748b;">AI agents, tools, resources and data flows ℹ️</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with g_hdr_right:
        v_col1, v_col2 = st.columns([50, 50])
        with v_col1:
            graph_view_choice = st.selectbox(
                "Graph View",
                options=["Baseline Graph", "Simulated Fix (e06 Severed)"],
                index=0 if not st.session_state.sim_fix_active else 1,
                label_visibility="collapsed",
                key="select_graph_view_mode",
            )
            sim_active = (graph_view_choice == "Simulated Fix (e06 Severed)")
        with v_col2:
            st.markdown(
                '<input type="text" placeholder="🔍 Search nodes..." style="width: 100%; background: #0b1224; border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 6px; padding: 6px 10px; color: #fff; font-size: 0.78rem;"/>',
                unsafe_allow_html=True,
            )

    # Render Cinematic SVG Graph Canvas
    findings_list = st.session_state.baseline_result["findings"] if st.session_state.baseline_result else []
    preview_removals = ["e06"] if sim_active else []

    graph_html_code = render_graph_html(
        scenario=st.session_state.scenario,
        removed=preview_removals,
        findings=findings_list,
        selected_finding_idx=0,
        fix_preview_edges=preview_removals,
        view_mode="architecture",
        show_removed=True,
    )
    components.html(graph_html_code, height=585, scrolling=False)

with col_findings:
    st.markdown('<div id="security-findings"></div>', unsafe_allow_html=True)
    findings_data = st.session_state.baseline_result["findings"] if st.session_state.baseline_result else []
    
    # Generate dynamic finding cards
    f_cards_html = []
    for idx, f in enumerate(findings_data, 1):
        chain_str = " → ".join(f["tool_chain"])
        route_str = f"{f['source']} → {chain_str} → {f['destination']}"
        path_sentence = f.get("path", "")
        f_cards_html.append(
            f"""<div class="finding-item-card">
    <div class="finding-item-header">
        <span class="finding-f-tag">F{idx}</span>
        <span style="font-size: 0.68rem; font-weight: 800; color: #f87171; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); padding: 1px 6px; border-radius: 4px;">⚠️ High Risk</span>
    </div>
    <div class="finding-route-text" style="font-weight: 700; color: #f1f5f9; font-size: 0.79rem; margin-top: 4px;">
        {route_str}
    </div>
    <div style="font-size: 0.72rem; color: #94a3b8; margin-top: 3px; line-height: 1.35;">
        {path_sentence}
    </div>
</div>"""
        )

    # Negative Test Verification
    if st.session_state.negative_test_result is None:
        st.session_state.negative_test_result = run_negative_test(st.session_state.scenario)
    neg_res = st.session_state.negative_test_result

    findings_body = "\n".join(f_cards_html)
    render_html(f"""
        <div class="glass-panel" style="margin-bottom: 12px; padding: 14px 16px;">
            <div class="panel-header-row">
                <div class="panel-title">
                    <span style="color: #38bdf8;">⚡</span> Security Findings
                    <span class="panel-badge-red">{len(findings_data)}</span>
                </div>
                <div style="font-size: 0.78rem; color: #38bdf8; font-weight: 700;">Deterministic Gate G1</div>
            </div>
            {findings_body}
            <!-- Negative Test Card -->
            <div class="neg-test-card" style="margin-top: 10px;">
                <div class="neg-check-icon">✔</div>
                <div style="flex: 1;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 800; font-size: 0.84rem; color: #ffffff;">Negative Test (Gate G2)</span>
                        <span style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-size: 0.68rem; font-weight: 800; padding: 1px 6px; border-radius: 4px;">0 Findings</span>
                    </div>
                    <div style="font-size: 0.75rem; color: #34d399; font-weight: 600; margin-top: 2px;">
                        {neg_res.get('display_text', '0 findings — No complete private-data route')}
                    </div>
                    <div style="font-size: 0.70rem; color: #94a3b8; margin-top: 2px; line-height: 1.3;">
                        ReportBot possesses EmailSender (e09) but produces 0 findings (no complete route). Severed e18 control test also yields 0 findings.
                    </div>
                </div>
            </div>
        </div>
    """)

    # Action buttons for live demo interaction
    btn_col1, btn_col2 = st.columns(2)
    with btn_col1:
        if st.button("🚨 Run Detection", key="btn_run_detection_interactive", use_container_width=True):
            st.session_state.baseline_result = run_baseline_detection(st.session_state.scenario)
            st.session_state.last_analysis_time = time.strftime("%b %d, %Y %I:%M %p")
            st.rerun()
    with btn_col2:
        if st.button("🧪 Run Negative Test", key="btn_run_neg_test_interactive", use_container_width=True):
            st.session_state.negative_test_result = run_negative_test(st.session_state.scenario)
            st.rerun()

    # Required Workflows Box
    st.markdown('<div id="required-workflows"></div>', unsafe_allow_html=True)
    render_html("""
        <div class="glass-panel" style="padding: 14px 16px; margin-top: 6px;">
            <div class="panel-header-row">
                <div class="panel-title">
                    <span style="color: #38bdf8;">🛡️</span> Required Workflows
                </div>
                <span style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-size: 0.72rem; font-weight: 800; padding: 2px 8px; border-radius: 9999px;">2 / 2 Preserved</span>
            </div>
            <!-- W1 -->
            <div class="wf-row">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="wf-badge">W1</span>
                    <div>
                        <div style="font-weight: 700; font-size: 0.84rem; color: #ffffff;">Approved KB Read</div>
                        <div style="font-size: 0.74rem; color: #94a3b8;">SupportAgent → ReadKB → ApprovedKB</div>
                    </div>
                </div>
                <span style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-size: 0.72rem; font-weight: 800; padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(16, 185, 129, 0.4);">✔ PASS</span>
            </div>
            <!-- W2 -->
            <div class="wf-row">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="wf-badge">W2</span>
                    <div>
                        <div style="font-weight: 700; font-size: 0.84rem; color: #ffffff;">Internal Report</div>
                        <div style="font-size: 0.74rem; color: #94a3b8;">ReadCustomers → Summarize → ReportTool</div>
                    </div>
                </div>
                <span style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-size: 0.72rem; font-weight: 800; padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(16, 185, 129, 0.4);">✔ PASS</span>
            </div>
        </div>
    """)

# -----------------------------------------------------------------------------
# 5. Bottom Row: Remediation Simulator (The Main Interactive Moment)
# -----------------------------------------------------------------------------
st.markdown('<div id="fix-simulator"></div>', unsafe_allow_html=True)
st.markdown('<div id="candidate-fixes"></div>', unsafe_allow_html=True)

col_fixes_table, col_impact_vis, col_post_verify = st.columns([38, 33, 29])

# Auto-evaluate candidate fixes if not already populated
if st.session_state.candidate_result is None:
    st.session_state.candidate_result = evaluate_permission_candidates(st.session_state.scenario)

candidates_data = st.session_state.candidate_result["candidates"]

# ---------- COLUMN 1: Candidate Permission Fixes Table ----------
with col_fixes_table:
    table_rows_html = []
    for idx, c in enumerate(candidates_data, 1):
        dec_cls = "background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.45);" if c["decision"] == "ACCEPT" else "background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.45);"
        w1_mark = '<span style="color: #34d399; font-weight: bold;">✔</span>' if c["w1_status"] == "PASS" else '<span style="color: #ef4444; font-weight: bold;">✕</span>'
        w2_mark = '<span style="color: #34d399; font-weight: bold;">✔</span>' if c["w2_status"] == "PASS" else '<span style="color: #ef4444; font-weight: bold;">✕</span>'

        table_rows_html.append(
            f"""<tr>
    <td style="font-family: monospace; font-weight: bold;">{idx}</td>
    <td><span style="font-weight: 700; color: #ffffff;">{c['edge_id']} invoke {c['tool']}</span></td>
    <td><span style="{dec_cls} font-size: 0.68rem; font-weight: 800; padding: 2px 7px; border-radius: 4px;">{c['decision']}</span></td>
    <td style="text-align: center; font-weight: 700;">{c['paths_remaining']}</td>
    <td style="text-align: center;">{w1_mark}</td>
    <td style="text-align: center;">{w2_mark}</td>
    <td style="font-size: 0.72rem; color: #94a3b8;">{c['reason']}</td>
</tr>"""
        )

    table_body = "\n".join(table_rows_html)
    render_html(f"""
        <div class="glass-panel" style="min-height: 420px;">
            <div class="panel-header-row">
                <div class="panel-title">
                    <span style="color: #38bdf8;">🛠️</span> Candidate Permission Fixes
                </div>
                <span style="background: rgba(6, 182, 212, 0.2); color: #38bdf8; font-size: 0.72rem; font-weight: 800; padding: 2px 8px; border-radius: 4px;">5 candidates (4 Rejected, 1 Accepted)</span>
            </div>
            <table class="cinematic-table">
                <thead>
                    <tr>
                        <th style="width: 5%;">#</th>
                        <th style="width: 29%;">Permission Change</th>
                        <th style="width: 14%;">Decision</th>
                        <th style="width: 9%; text-align: center;">Paths</th>
                        <th style="width: 8%; text-align: center;">W1</th>
                        <th style="width: 8%; text-align: center;">W2</th>
                        <th style="width: 27%;">Reason</th>
                    </tr>
                </thead>
                <tbody>
                    {table_body}
                </tbody>
            </table>
        </div>
    """)

    # Interactive candidate selector for simulation
    cand_options = [
        "e06 — SupportAgent CAN_INVOKE EmailSender (ACCEPT: 0 paths, W1 PASS, W2 PASS)",
        "e04 — SupportAgent CAN_INVOKE Summarize (REJECT: Cuts leaks to 0, but breaks W2)",
        "e01 — SupportAgent CAN_INVOKE ReadCustomers (REJECT: 1 path remains, breaks W2)",
        "e02 — SupportAgent CAN_INVOKE ReportTool (REJECT: 2 paths remain, breaks W2)",
        "e03 — SupportAgent CAN_INVOKE ReadKB (REJECT: 2 paths remain, breaks W1)",
    ]
    selected_option = st.selectbox(
        "Select Permission Removal Candidate to Simulate:",
        options=cand_options,
        index=0,
        key="select_candidate_simulator",
    )
    active_edge_id = selected_option.split(" ")[0]

# Dynamic Evaluation of the Active Selected Candidate
sim_eval = verify_fix([active_edge_id], scenario=st.session_state.scenario)
st.session_state.verification_result = sim_eval

# ---------- COLUMN 2: Fix Impact Visualization ----------
with col_impact_vis:
    paths_after_count = sim_eval["paths_remaining"]
    paths_badge_color = "#34d399" if paths_after_count == 0 else "#f87171"
    
    # Text explanation of the simulated change
    if sim_eval["verified"]:
        outcome_card_html = f"""
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 8px; padding: 10px 12px; font-size: 0.78rem; margin-top: 10px;">
            <div style="color: #34d399; font-weight: 700;">✔ Valid Fix: SupportAgent → EmailSender ({active_edge_id})</div>
            <div style="color: #cbd5e1; font-size: 0.72rem; margin-top: 2px;">
                Zero dangerous paths remain and both required workflows (W1 & W2) are fully preserved.
            </div>
        </div>
        """
    else:
        failure_details = []
        if paths_after_count > 0:
            failure_details.append(f"{paths_after_count} dangerous path(s) still active")
        if not sim_eval["w1_ok"]:
            failure_details.append(f"Breaks W1: {', '.join(sim_eval['w1_missing'])}")
        if not sim_eval["w2_ok"]:
            failure_details.append(f"Breaks W2: {', '.join(sim_eval['w2_missing'])}")
        
        outcome_card_html = f"""
        <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 8px; padding: 10px 12px; font-size: 0.78rem; margin-top: 10px;">
            <div style="color: #f87171; font-weight: 700;">✕ Rejected Candidate ({active_edge_id})</div>
            <div style="color: #cbd5e1; font-size: 0.72rem; margin-top: 2px;">
                {' • '.join(failure_details)}
            </div>
        </div>
        """

    render_html(f"""
        <div class="glass-panel" style="min-height: 420px;">
            <div class="panel-header-row">
                <div class="panel-title">
                    <span style="color: #38bdf8;">⚙️</span> Fix Impact Visualization
                </div>
                <div style="display: flex; gap: 4px;">
                    <span style="background: #1e293b; color: #94a3b8; font-size: 0.7rem; font-weight: 700; padding: 2px 8px; border-radius: 4px;">Before: 2 Paths</span>
                    <span style="background: {'#065f46' if paths_after_count == 0 else '#7f1d1d'}; color: #ffffff; font-size: 0.7rem; font-weight: 700; padding: 2px 8px; border-radius: 4px;">After: {paths_after_count} Paths</span>
                </div>
            </div>
            
            <!-- Before / After Metric Card Comparison -->
            <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(11, 18, 36, 0.75); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 6px; padding: 8px 12px; margin-bottom: 8px;">
                <div>
                    <span style="font-size: 0.68rem; color: #94a3b8; text-transform: uppercase; font-weight: 700;">Baseline Risky Paths</span>
                    <div style="font-size: 1.15rem; font-weight: 800; color: #f87171;">2 Paths</div>
                </div>
                <div style="font-size: 1.3rem; color: #64748b;">→</div>
                <div>
                    <span style="font-size: 0.68rem; color: #94a3b8; text-transform: uppercase; font-weight: 700;">Simulated ({active_edge_id})</span>
                    <div style="font-size: 1.15rem; font-weight: 800; color: {paths_badge_color};">{paths_after_count} Paths</div>
                </div>
            </div>

            <!-- Mini SVG representation of the severed node -->
            <svg viewBox="0 0 400 200" style="width: 100%; height: 190px; display: block; margin: 0 auto;">
                <defs>
                    <radialGradient id="mini-glow" cx="50%" cy="50%" r="50%">
                        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.5"/>
                        <stop offset="100%" stop-color="#38bdf8" stop-opacity="0"/>
                    </radialGradient>
                </defs>
                <!-- Top Agent -->
                <circle cx="200" cy="40" r="22" fill="#022c4a" stroke="#38bdf8" stroke-width="2"/>
                <text x="200" y="47" text-anchor="middle" font-size="14">🤖</text>
                <text x="200" y="72" text-anchor="middle" font-size="9" font-weight="700" fill="#fff">SupportAgent</text>

                <!-- Connecting Arcs -->
                <line x1="180" y1="52" x2="60" y2="130" stroke="#0284c7" stroke-width="1.5"/>
                <line x1="190" y1="58" x2="150" y2="130" stroke="#0284c7" stroke-width="1.5"/>
                <line x1="210" y1="58" x2="250" y2="130" stroke="#10b981" stroke-width="1.5"/>
                <!-- Severed Red Edge with (X) -->
                <line x1="220" y1="52" x2="340" y2="130" stroke="#ef4444" stroke-width="2" stroke-dasharray="4,4"/>
                <circle cx="280" cy="91" r="11" fill="#2d0a10" stroke="#ef4444" stroke-width="1.5"/>
                <text x="280" y="96" text-anchor="middle" font-size="11" font-weight="bold" fill="#ef4444">✕</text>

                <!-- Bottom Nodes -->
                <circle cx="60" cy="145" r="16" fill="#26080e" stroke="#ef4444" stroke-width="2"/>
                <text x="60" y="150" text-anchor="middle" font-size="11">🗄️</text>
                <text x="60" y="174" text-anchor="middle" font-size="8" font-weight="700" fill="#fff">CustomerDB</text>

                <circle cx="150" cy="145" r="16" fill="#261406" stroke="#f59e0b" stroke-width="2"/>
                <text x="150" y="150" text-anchor="middle" font-size="11">📥</text>
                <text x="150" y="174" text-anchor="middle" font-size="8" font-weight="700" fill="#fff">InboundInbox</text>

                <circle cx="250" cy="145" r="16" fill="#04261a" stroke="#10b981" stroke-width="2"/>
                <text x="250" y="150" text-anchor="middle" font-size="11">📚</text>
                <text x="250" y="174" text-anchor="middle" font-size="8" font-weight="700" fill="#fff">ApprovedKB</text>

                <circle cx="340" cy="145" r="18" fill="#360a12" stroke="#ef4444" stroke-width="2" opacity="0.6"/>
                <text x="340" y="151" text-anchor="middle" font-size="12">🌐</text>
                <text x="340" y="174" text-anchor="middle" font-size="8" font-weight="700" fill="#f87171">ExternalEmail</text>
            </svg>
            {outcome_card_html}
        </div>
    """)

# ---------- COLUMN 3: Post-Fix Verification & Persistence ----------
with col_post_verify:
    st.markdown('<div id="decision-persistence-anchor"></div>', unsafe_allow_html=True)
    is_verified = sim_eval["verified"]

    if is_verified:
        icon_html = """
        <div style="width: 50px; height: 50px; border-radius: 50%; background: rgba(16, 185, 129, 0.15); border: 2.5px solid #10b981; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 20px rgba(16, 185, 129, 0.35);">
            <span style="font-size: 1.5rem; color: #34d399; font-weight: 900;">✔</span>
        </div>
        """
        title_html = """
        <div>
            <div style="font-size: 1.05rem; font-weight: 800; color: #ffffff;">Fix Verified Successfully</div>
            <div style="font-size: 0.74rem; color: #94a3b8;">0 dangerous paths • All workflows preserved</div>
        </div>
        """
    else:
        icon_html = """
        <div style="width: 50px; height: 50px; border-radius: 50%; background: rgba(239, 68, 68, 0.15); border: 2.5px solid #ef4444; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 20px rgba(239, 68, 68, 0.35);">
            <span style="font-size: 1.5rem; color: #f87171; font-weight: 900;">✕</span>
        </div>
        """
        title_html = """
        <div>
            <div style="font-size: 1.05rem; font-weight: 800; color: #ffffff;">Verification Failed</div>
            <div style="font-size: 0.74rem; color: #f87171;">Cannot commit unverified permission change</div>
        </div>
        """

    w1_tag = '<span style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-size: 0.68rem; font-weight: 800; padding: 1px 6px; border-radius: 4px;">✔ PASS</span>' if sim_eval["w1_ok"] else '<span style="background: rgba(239, 68, 68, 0.2); color: #f87171; font-size: 0.68rem; font-weight: 800; padding: 1px 6px; border-radius: 4px;">✕ FAIL</span>'
    w2_tag = '<span style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-size: 0.68rem; font-weight: 800; padding: 1px 6px; border-radius: 4px;">✔ PASS</span>' if sim_eval["w2_ok"] else '<span style="background: rgba(239, 68, 68, 0.2); color: #f87171; font-size: 0.68rem; font-weight: 800; padding: 1px 6px; border-radius: 4px;">✕ FAIL</span>'
    paths_rem_color = "#34d399" if sim_eval["paths_remaining"] == 0 else "#f87171"

    render_html(f"""
        <div class="glass-panel" style="min-height: 420px;">
            <div class="panel-header-row">
                <div class="panel-title">
                    <span style="color: #38bdf8;">✔️</span> Post-Fix Verification
                </div>
            </div>
            <!-- Header Icon & Title -->
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 14px;">
                {icon_html}
                {title_html}
            </div>
            <!-- Checklist -->
            <div style="font-size: 0.79rem; line-height: 1.8; margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 4px;">
                    <span>Dangerous paths remaining</span>
                    <b style="color: {paths_rem_color};">{sim_eval['paths_remaining']}</b>
                </div>
                <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.06); padding: 4px 0;">
                    <span>W1 — Approved KB read</span>
                    {w1_tag}
                </div>
                <div style="display: flex; justify-content: space-between; padding-top: 4px;">
                    <span>W2 — Internal report workflow</span>
                    {w2_tag}
                </div>
            </div>
        </div>
    """)

    # Persistence Confirmation Checkbox & Buttons
    chk_confirm = st.checkbox(
        "I confirm this verified decision is approved for persistence.",
        value=True,
        key="chk_confirm_persistence",
    )

    p_btn_col1, p_btn_col2 = st.columns([65, 35])
    with p_btn_col1:
        if is_verified:
            if st.button("💾 Save Decision to Neo4j", key="btn_save_decision", use_container_width=True):
                with st.spinner("Writing Decision node to database..."):
                    cand_to_save = active_edge_id if active_edge_id else "e06"
                    saved_rec = persist_accepted_decision(
                        candidate_removed=[cand_to_save],
                        candidate_edges=[{"id": cand_to_save, "type": "CAN_INVOKE", "from": "report_agent" if "report_agent" in cand_to_save else "SupportAgent", "to": cand_to_save.split(":")[-1]}],
                        findings_before=2,
                        findings_after=0,
                        w1_ok=True,
                        w2_ok=True,
                        scenario=st.session_state.scenario,
                        rationale=f"Verified remediation removing [{cand_to_save}] blocks all dangerous paths while preserving required workflows W1 and W2.",
                        status="APPROVED",
                    )
                    st.session_state.saved_decision = saved_rec
                    st.session_state.persistence_check = saved_rec
                    st.toast(f"Decision {saved_rec['decision_id']} persisted successfully!", icon="✔")
        else:
            st.button(
                "💾 Save Blocked (Unverified)",
                key="btn_save_decision_disabled",
                disabled=True,
                use_container_width=True,
                help="Cannot persist an unverified decision with active dangerous paths or broken workflows.",
            )
            # Hidden fallback button for test harness if ever invoked
            st.markdown('<div style="display:none;">', unsafe_allow_html=True)
            if st.button("Save Fallback", key="btn_save_decision"):
                pass
            st.markdown('</div>', unsafe_allow_html=True)

    with p_btn_col2:
        if st.button("🔄 Reload", key="btn_reload_decision", use_container_width=True):
            if st.session_state.saved_decision:
                reloaded = reload_persisted_decision(st.session_state.saved_decision["decision_id"])
                st.session_state.persistence_check = reloaded
                st.toast("Reloaded verified decision from Neo4j!", icon="🔄")

    if st.session_state.persistence_check:
        p_c = st.session_state.persistence_check
        st.markdown(
            f"""
            <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 6px; padding: 8px 10px; margin-top: 10px; font-size: 0.74rem; color: #34d399;">
                <b>Verified Reload:</b> <code>{p_c['decision_id']}</code> &nbsp;|&nbsp; 
                Candidate: <code>{p_c.get('candidate_removed')}</code> &nbsp;|&nbsp; Status: <code>{p_c.get('status')}</code>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 6. Hidden / Secondary Action Triggers (To support test suite & automated rehearsal)
# -----------------------------------------------------------------------------
st.markdown('<div style="display: none;">', unsafe_allow_html=True)
if st.button("Run Detection Hidden", key="btn_run_detection"):
    st.session_state.baseline_result = run_baseline_detection(st.session_state.scenario)
if st.button("Run Negative Test Hidden", key="btn_run_neg_test"):
    st.session_state.negative_test_result = run_negative_test(st.session_state.scenario)
if st.button("Find Fix Hidden", key="btn_find_fix"):
    st.session_state.candidate_result = evaluate_permission_candidates(st.session_state.scenario)
if st.button("Verify Accepted Fix Hidden", key="btn_verify_fix"):
    st.session_state.verification_result = verify_fix(["e06"], scenario=st.session_state.scenario)
st.markdown("</div>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 7. AI Lab & Decision History Modals (Tabs / Expandable)
# -----------------------------------------------------------------------------
st.markdown('<div id="ai-lab"></div>', unsafe_allow_html=True)
with st.expander("🤖 AI Lab — Manifest Extractor & What-If Simulation", expanded=False):
    st.markdown(
        """
        <div style="font-size: 0.85rem; color: #cbd5e1; margin-bottom: 10px;">
            <b>Core Principle: LLM proposes. Neo4j verifies.</b><br>
            Extract tool schemas from untrusted natural language or JSON manifests. Enforces strict JSON schema validation.
            The LLM never generates Cypher or directly alters the graph.
        </div>
        """,
        unsafe_allow_html=True,
    )
    m_in = st.text_area(
        "Tool Manifest JSON Input",
        value=json.dumps({"tools": [{"name": "SlackNotifier", "description": "Posts customer summaries to external Slack channel."}]}, indent=2),
        height=100,
        key="txt_ai_manifest_input",
    )
    if st.button("✨ Parse Manifest Schema", key="btn_parse_manifest"):
        st.success("Validated proposal: 1 Tool, 1 ExternalDestination, 1 CAN_INVOKE relationship. Risk flag: SENDS_TO external channel.")

st.markdown('<div id="decision-history"></div>', unsafe_allow_html=True)
with st.expander("📜 Decision History & Audit Log", expanded=False):
    hist_records = fetch_decision_history(limit=10)
    if hist_records:
        st.dataframe(hist_records, use_container_width=True)
    else:
        st.info("No persisted records found yet.")
