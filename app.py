import streamlit as st
import pandas as pd
from agentfence.db import get_driver
from agentfence.seed import seed_graph
from agentfence.detector import detect_paths
from agentfence.workflows import check_workflows
from agentfence.fixer import find_fix
from agentfence.decisions import save_decision, get_active_removed_edge_ids
from agentfence.ai_detector import detect_paths_with_sarvam
from agentfence.explainer import explain_findings

st.set_page_config(
    page_title="AgentFence — AI Agent Data-Path Security",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AgentFence — AI-Agent Data-Path Security")
st.markdown(
    "Modeled AI-agent data-path security and permission remediation using **Neo4j** & **Sarvam AI**."
)

# Connect to database
try:
    driver = get_driver()
except Exception as e:
    st.error(f"Failed to connect to Neo4j: {e}")
    st.stop()

# Sidebar: Environment & Scenario Control
st.sidebar.header("Scenario & Graph Controls")
scenario = st.sidebar.selectbox("Select Scenario", ["base", "negative"], index=0)

if st.sidebar.button("Re-seed Graph"):
    with st.spinner(f"Seeding '{scenario}' scenario in Neo4j..."):
        try:
            seed_graph(driver, scenario=scenario)
            st.sidebar.success(f"Graph seeded with '{scenario}' scenario!")
        except Exception as e:
            st.sidebar.error(f"Error seeding graph: {e}")

st.sidebar.markdown("---")
st.sidebar.markdown("### System Architecture")
st.sidebar.markdown(
    "- **Neo4j:** Graph storage & Cypher path queries\n"
    "- **Security Engine:** Deterministic detector, W1/W2 checks, 5-candidate evaluation\n"
    "- **Sarvam AI:** Schema-assisted query proposal & plain-English security explanations\n"
    "- **Streamlit:** Analyst console"
)

# Active Decisions
active_edge_ids = get_active_removed_edge_ids(driver)
if active_edge_ids:
    st.sidebar.info(f"Active Persisted Removals ({len(active_edge_ids)}): {list(active_edge_ids)}")

# Tabs for 4 core sections
tab1, tab2, tab3, tab4 = st.tabs([
    "1. Standard Security Analysis",
    "2. AI-Assisted Graph Detection",
    "3. AI Security Analyst",
    "4. Candidate Fixes & Persistence"
])

# -------------------------------------------------------------
# TAB 1: Standard Security Analysis (Deterministic)
# -------------------------------------------------------------
with tab1:
    st.header("Deterministic Path Detection")
    st.markdown("Authoritative verification using Cypher graph traversal.")

    findings = detect_paths(driver, scenario=scenario)
    st.metric("Dangerous Paths Detected", len(findings))

    if findings:
        for idx, f in enumerate(findings, 1):
            with st.expander(f"Finding #{idx}: {f.source} ➔ {f.destination}", expanded=True):
                st.write(f"**Path:** `{' ➔ '.join(f.path)}`")
                st.write(f"**Relationship IDs:** `{f.relationship_ids}`")
                col_p, col_d = st.columns(2)
                with col_p:
                    st.write("**Permission Edges (Configurable):**")
                    for p in f.permission_edge_ids:
                        st.code(p)
                with col_d:
                    st.write("**Data-Flow Evidence (Non-configurable):**")
                    for d in f.data_flow_edge_ids:
                        st.code(d)
    else:
        st.success(f"No dangerous paths found in scenario '{scenario}'.")

    st.subheader("Workflow Status (Baseline)")
    wf_results = check_workflows(driver, scenario=scenario)
    cols = st.columns(len(wf_results))
    for c, w in zip(cols, wf_results):
        with c:
            if w.passed:
                st.success(f"**{w.name}**: PASSED")
            else:
                st.error(f"**{w.name}**: FAILED")
            st.caption(w.reason)

# -------------------------------------------------------------
# TAB 2: AI-Assisted Graph Detection
# -------------------------------------------------------------
with tab2:
    st.header("Sarvam AI-Assisted Graph Detection")
    st.markdown(
        "Sarvam AI analyzes the Neo4j schema metadata and proposes read-only Cypher queries "
        "to discover suspicious data routes."
    )

    if st.button("Run Sarvam-Assisted Detection", type="primary"):
        with st.spinner("Querying Sarvam AI and validating Cypher..."):
            ai_res = detect_paths_with_sarvam(driver, scenario=scenario)
            st.session_state["sarvam_detection"] = ai_res

    if "sarvam_detection" in st.session_state:
        ai_res = st.session_state["sarvam_detection"]
        if ai_res.status == "SUCCESS":
            st.success(f"AI Discovery Succeeded: {len(ai_res.findings)} candidate path(s) returned.")
            with st.expander("Inspected Model-Generated Cypher Query"):
                st.code(ai_res.query_executed or "N/A", language="cypher")
            
            for idx, f in enumerate(ai_res.findings, 1):
                badge = "✅ Graph Validated" if f.is_validated else "⚠️ Unvalidated Model Suggestion"
                with st.expander(f"AI Finding #{idx}: {f.source} ➔ {f.destination} [{badge}]"):
                    st.write(f"**Path:** `{' ➔ '.join(f.path)}`")
                    st.write(f"**Evidence:** {f.evidence}")
                    st.write(f"**Relationship IDs:** `{f.relationship_ids}`")
        else:
            st.error(f"AI-Assisted Detection Error [{ai_res.status}]: {ai_res.error}")
            st.info("Deterministic detector remains fully functional in Tab 1.")

# -------------------------------------------------------------
# TAB 3: AI Security Analyst (Explanations)
# -------------------------------------------------------------
with tab3:
    st.header("Sarvam AI Security Analyst")
    st.markdown(
        "Plain-English explanation of detected risks, the accepted fix, rejected alternatives, "
        "and workflow impacts."
    )

    if st.button("Explain Findings"):
        with st.spinner("Generating security explanation via Sarvam AI..."):
            base_findings = detect_paths(driver, scenario=scenario)
            fix_res = find_fix(driver, scenario=scenario)
            base_wfs = check_workflows(driver, scenario=scenario)

            explanation = explain_findings(
                findings=base_findings,
                candidate_results=fix_res.candidates,
                workflows=base_wfs
            )
            st.session_state["explanation_result"] = explanation

    if "explanation_result" in st.session_state:
        exp = st.session_state["explanation_result"]
        source_badge = "Sarvam AI" if exp.source == "SARVAM_AI" else "AgentFence Analyst (Fallback)"
        st.caption(f"Explanation Engine: **{source_badge}**")

        st.subheader("1. Overall Risk Summary")
        st.warning(exp.risk_summary)

        st.subheader("2. Accepted Remediation Rationale")
        st.success(exp.accepted_fix_explanation)

        st.subheader("3. Alternative Candidate Analysis")
        for rej in exp.rejected_candidates_explanation:
            st.markdown(f"- **`{rej['candidate_id']}`**: {rej['reason']}")

        st.subheader("4. Deterministic W1 / W2 Verification Status")
        st.info(exp.w1_w2_status)

        st.subheader("5. Limitations & Evidence Scope")
        st.caption(exp.limitations)

# -------------------------------------------------------------
# TAB 4: Candidate Fixes & Persistence
# -------------------------------------------------------------
with tab4:
    st.header("Permission Remediation & Fix Simulation")
    st.markdown(
        "Evaluate five single-permission candidates in order without mutating the baseline graph."
    )

    fix_result = find_fix(driver, scenario=scenario)
    
    st.subheader("Candidate Evaluations")
    cand_data = []
    for c in fix_result.candidates:
        cand_data.append({
            "Candidate Edge": c.removed_edge_id,
            "Decision": c.decision,
            "Reason": c.reason,
            "Remaining Findings": len(c.remaining_findings),
            "W1": next((w.passed for w in c.workflows if w.name == "W1"), False),
            "W2": next((w.passed for w in c.workflows if w.name == "W2"), False),
        })
    st.dataframe(pd.DataFrame(cand_data), use_container_width=True)

    if fix_result.accepted:
        st.success(f"**Accepted Candidate:** `{fix_result.accepted}`")
        
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Findings After Fix:** {len(fix_result.findings_after_fix)}")
        with col2:
            wf_str = ", ".join(f"{w.name}: {'PASSED' if w.passed else 'FAILED'}" for w in fix_result.workflows_after_fix)
            st.write(f"**Workflows After Fix:** {wf_str}")

        if st.button(f"Persist Decision for '{fix_result.accepted}'"):
            with st.spinner("Persisting decision node in Neo4j..."):
                d_res = save_decision(driver, fix_result.accepted, scenario=scenario)
                st.success(f"Decision `{d_res.decision_id}` persisted successfully!")
                st.rerun()
    else:
        st.warning("No candidate met all criteria (0 findings and intact W1/W2 workflows).")
