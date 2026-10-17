from typing import List, Dict, Any, Optional
from agentfence.contracts import Finding, CandidateResult, WorkflowResult, ExplanationResult
from agentfence.sarvam_client import call_sarvam_chat


def explain_findings(
    findings: List[Finding],
    candidate_results: List[CandidateResult],
    workflows: List[WorkflowResult],
    use_sarvam: bool = True,
    mock_llm_text: Optional[str] = None
) -> ExplanationResult:
    """Generate structured explanations for findings, candidate fixes, and workflow checks.
    
    Uses Sarvam AI if available, and gracefully falls back to deterministic expert analysis
    if Sarvam encounters quota/network issues.
    """
    # 1. Deterministic evidence compilation
    w_status_str = ", ".join(f"{w.name}: {'PASSED' if w.passed else 'FAILED'} ({w.reason})" for w in workflows)
    
    accepted_c = next((c for c in candidate_results if c.decision == "ACCEPT"), None)
    accepted_str = (
        f"Candidate '{accepted_c.removed_edge_id}' is accepted because: {accepted_c.reason}"
        if accepted_c else "No single permission candidate met all criteria."
    )

    rejected_explanations = [
        {
            "candidate_id": c.removed_edge_id,
            "decision": c.decision,
            "reason": c.reason,
            "remaining_findings_count": len(c.remaining_findings),
        }
        for c in candidate_results if c.decision == "REJECT"
    ]

    path_explanations = [
        {
            "source": f.source,
            "destination": f.destination,
            "path": " -> ".join(f.path),
            "permissions": f.permission_edge_ids,
            "data_flows": f.data_flow_edge_ids,
            "severity": "CRITICAL - Unapproved egress of confidential data"
        }
        for f in findings
    ]

    evidence_summary = (
        f"Analyzed {len(findings)} dangerous path(s). "
        f"Evaluated {len(candidate_results)} candidate fixes. "
        f"Verified workflows: {w_status_str}."
    )

    limitations = (
        "Analysis is bounded by the modeled Neo4j graph topology and active permission policies. "
        "Deterministic workflow checks govern final verification."
    )

    risk_summary = (
        f"HIGH RISK: Detected {len(findings)} path(s) where confidential data ('payroll_report') "
        "flows to unauthorized external endpoints. Immediate permission revocation required."
    )

    # 2. Attempt Sarvam LLM explanation if requested
    llm_content = None
    if mock_llm_text:
        llm_content = mock_llm_text
    elif use_sarvam:
        system_prompt = (
            "You are AgentFence's AI Security Analyst explaining security findings from a Neo4j graph.\n"
            "Provide clear, executive explanations of the risk, the detected paths, why the accepted fix works, "
            "and why the alternative fixes were rejected. Do not hallucinate relationships not present in the evidence."
        )
        user_prompt = (
            f"Findings:\n{findings}\n\n"
            f"Candidates:\n{candidate_results}\n\n"
            f"Workflows:\n{workflows}\n"
        )
        try:
            resp = call_sarvam_chat(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                timeout=10
            )
            llm_content = resp.get("choices", [{}])[0].get("message", {}).get("content")
        except Exception:
            # Graceful fallback to deterministic analyst
            llm_content = None

    source = "SARVAM_AI" if llm_content else "FALLBACK_ANALYST"
    if llm_content:
        risk_summary = f"{risk_summary}\n\n[Sarvam AI Analysis]:\n{llm_content}"

    return ExplanationResult(
        risk_summary=risk_summary,
        path_explanations=path_explanations,
        accepted_fix_explanation=accepted_str,
        rejected_candidates_explanation=rejected_explanations,
        evidence_summary=evidence_summary,
        w1_w2_status=w_status_str,
        limitations=limitations,
        source=source,
    )
