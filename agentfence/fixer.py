from typing import List, Optional, Set
from neo4j import Driver
from agentfence.contracts import CandidateResult, FixResult
from agentfence.detector import detect_paths
from agentfence.workflows import check_workflows

# Ordered candidates:
# 1. ci:report_agent:document_reader
# 2. read:document_reader:payroll_report
# 3. ci:report_agent:webhook_poster
# 4. send:webhook_poster:attacker_endpoint
# 5. send:webhook_poster:shadow_endpoint

CANDIDATES = [
    "ci:report_agent:document_reader",
    "read:document_reader:payroll_report",
    "ci:report_agent:webhook_poster",
    "send:webhook_poster:attacker_endpoint",
    "send:webhook_poster:shadow_endpoint",
]

def find_fix(
    driver: Driver,
    scenario: str = "base",
    already_removed: Optional[Set[str] | list[str]] = None
) -> FixResult:
    """Evaluate 5 single-permission candidates in order and return FixResult.
    
    A candidate is evaluated by simulating its removal in addition to already_removed.
    Acceptance criteria:
    - Zero remaining dangerous findings
    - Both W1 and complete W2 workflows pass
    Rejection reason is clearly specified.
    """
    base_removed = set(already_removed) if already_removed else set()
    candidate_results: List[CandidateResult] = []
    accepted_candidate: Optional[str] = None

    for cand_id in CANDIDATES:
        simulated_removed = base_removed | {cand_id}
        
        # Check workflows
        wf_results = check_workflows(driver, scenario=scenario, removed_edge_ids=simulated_removed)
        w1_res = next((w for w in wf_results if w.name == "W1"), None)
        w2_res = next((w for w in wf_results if w.name == "W2"), None)
        
        # Check dangerous findings
        rem_findings = detect_paths(driver, scenario=scenario, removed_edge_ids=simulated_removed)
        
        # Determine decision and reason
        if w1_res and not w1_res.passed:
            decision = "REJECT"
            reason = "REJECT: W1 fails (essential read workflow is broken)"
        elif w2_res and not w2_res.passed:
            decision = "REJECT"
            reason = "REJECT: W2 fails (approved audit workflow is broken)"
        elif len(rem_findings) > 0:
            decision = "REJECT"
            reason = f"REJECT: Dangerous findings remain ({len(rem_findings)} unmitigated route(s))"
        else:
            decision = "ACCEPT"
            reason = "ACCEPT: All dangerous routes eliminated while W1 and W2 workflows remain fully intact"
            if accepted_candidate is None:
                accepted_candidate = cand_id

        candidate_results.append(
            CandidateResult(
                removed_edge_id=cand_id,
                decision=decision,
                reason=reason,
                remaining_findings=rem_findings,
                workflows=wf_results,
            )
        )

    # Calculate post-fix state with accepted candidate (if found) or baseline
    final_removed = base_removed | ({accepted_candidate} if accepted_candidate else set())
    findings_after = detect_paths(driver, scenario=scenario, removed_edge_ids=final_removed)
    workflows_after = check_workflows(driver, scenario=scenario, removed_edge_ids=final_removed)

    return FixResult(
        candidates=candidate_results,
        accepted=accepted_candidate,
        findings_after_fix=findings_after,
        workflows_after_fix=workflows_after,
    )
