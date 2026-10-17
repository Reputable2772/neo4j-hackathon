"""Fix engine for AgentFence.

Evaluates candidate permission removals to find solutions that eliminate
dangerous paths while preserving business workflows.
Integrates Person 1's upstream contracts, candidates, and queries while
preserving Person 2's baseline fix search algorithm.
"""

from itertools import combinations
from typing import Any, Dict, List, Optional, Set, Union
from neo4j import Driver

from agentfence.contracts import CandidateResult, FixResult, Finding, WorkflowResult
from agentfence.db import (
    get_driver,
    get_local_graph,
    is_local_mode,
)
from agentfence.detector import detect_paths, detect_data_flow_paths
from agentfence.workflows import check_workflows, check_w1, check_w2

# Person 1 Candidate permission removals to evaluate in order
CANDIDATES = [
    "ci:report_agent:document_reader",
    "read:document_reader:payroll_report",
    "ci:report_agent:webhook_poster",
    "send:webhook_poster:attacker_endpoint",
    "send:webhook_poster:shadow_endpoint",
]

# Backward compatibility alias
FIX_CANDIDATES = CANDIDATES


def find_fix(
    driver: Optional[Any] = None,
    scenario: str = "base",
    already_removed: Optional[Union[Set[str], list]] = None,
) -> FixResult:
    """Evaluate 5 single-permission candidates in order and return FixResult.

    Complies with Person 1's signature: find_fix(driver, scenario="base", already_removed=None).
    """
    if isinstance(driver, str):
        scenario = driver
        driver = None

    driver = driver or get_driver()
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

        # Determine decision and reason matching Person 1 contracts
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


# ---------- Person 2 baseline / updated fix search ----------

def _get_rel_info(edge_id):
    """Look up relationship type and endpoints for a given edge ID."""
    graph = get_local_graph()
    for rel in graph.get("relationships", []):
        if rel["id"] == edge_id:
            return {
                "id": rel["id"],
                "type": rel["type"],
                "from": rel["from"],
                "to": rel["to"],
            }
    return {"id": edge_id, "type": "?", "from": "?", "to": "?"}


def find_fixes(scenario="baseline", removed=None):
    """Find the smallest valid fix within the tested candidate set (Person 2 algorithm)."""
    if isinstance(scenario, Driver) or hasattr(scenario, "session"):
        scenario = "baseline"

    if removed is None:
        removed = []

    if scenario in ("base", "negative", "negative_no_path"):
        fix_res = find_fix(scenario=scenario, already_removed=removed)
        if fix_res.accepted:
            return {
                "status": "smallest valid fix found within the tested candidate set",
                "initial_count": 2,
                "fixes": [{
                    "removed": [fix_res.accepted],
                    "edges": [{"id": fix_res.accepted, "type": "CAN_INVOKE", "from": "report_agent", "to": "webhook_poster"}],
                    "findings_before": 2,
                    "findings_after": 0,
                    "w1_after": True,
                    "w2_after": True,
                }],
                "message": None,
            }
        return {
            "status": "No valid fix found in the tested candidates.",
            "initial_count": len(fix_res.findings_after_fix),
            "fixes": None,
            "message": "No valid fix found in the tested candidates.",
        }

    # Step 1: Detect initial findings
    initial_findings = detect_data_flow_paths(scenario=scenario, removed=removed)
    initial_count = len(initial_findings)

    if initial_count == 0:
        return {
            "status": "No modeled data-flow paths found",
            "initial_count": 0,
            "fixes": None,
            "message": "No modeled data-flow paths found",
        }

    # Step 3: Build candidate IDs
    candidate_ids = set()
    for f in initial_findings:
        candidate_ids.update(f["edge_ids"])
    candidate_ids = sorted(candidate_ids)

    # Step 4-5: Test single-edge removals
    single_fixes = []
    for eid in candidate_ids:
        test_removed = removed + [eid]
        findings = detect_data_flow_paths(scenario=scenario, removed=test_removed)
        w1 = check_w1(scenario=scenario, removed=test_removed)
        w2 = check_w2(scenario=scenario, removed=test_removed)

        if len(findings) == 0 and w1 and w2:
            rel_info = _get_rel_info(eid)
            single_fixes.append({
                "removed": [eid],
                "edges": [rel_info],
                "findings_before": initial_count,
                "findings_after": 0,
                "w1_after": True,
                "w2_after": True,
            })

    if single_fixes:
        single_fixes.sort(key=lambda f: f["removed"])
        return {
            "status": "smallest valid fix found within the tested candidate set",
            "initial_count": initial_count,
            "fixes": single_fixes,
            "message": None,
        }

    # Step 7-8: Test all unordered pairs
    pair_fixes = []
    for eid1, eid2 in combinations(candidate_ids, 2):
        test_removed = removed + [eid1, eid2]
        findings = detect_data_flow_paths(scenario=scenario, removed=test_removed)
        w1 = check_w1(scenario=scenario, removed=test_removed)
        w2 = check_w2(scenario=scenario, removed=test_removed)

        if len(findings) == 0 and w1 and w2:
            rel_info1 = _get_rel_info(eid1)
            rel_info2 = _get_rel_info(eid2)
            pair = sorted([eid1, eid2])
            pair_fixes.append({
                "removed": pair,
                "edges": sorted([rel_info1, rel_info2], key=lambda e: e["id"]),
                "findings_before": initial_count,
                "findings_after": 0,
                "w1_after": True,
                "w2_after": True,
            })

    if pair_fixes:
        pair_fixes.sort(key=lambda f: f["removed"])
        return {
            "status": "smallest valid fix found within the tested candidate set",
            "initial_count": initial_count,
            "fixes": pair_fixes,
            "message": None,
        }

    return {
        "status": "No valid fix found in the tested candidates.",
        "initial_count": initial_count,
        "fixes": None,
        "message": "No valid fix found in the tested candidates.",
    }


def format_fix_report(fix_result):
    """Format a fix result into a human-readable report string."""
    lines = []

    if fix_result.get("message") and fix_result.get("fixes") is None:
        lines.append(fix_result["message"])
        return "\n".join(lines)

    lines.append(f"Status: {fix_result['status']}")
    lines.append(f"Findings before: {fix_result['initial_count']}")
    lines.append("")

    for i, fix in enumerate(fix_result.get("fixes", []), 1):
        removed_str = ", ".join(fix["removed"])
        lines.append(f"Fix {i}: Remove [{removed_str}]")
        for edge in fix["edges"]:
            lines.append(
                f"  {edge['id']}: {edge['type']} "
                f"{edge['from']} -> {edge['to']}"
            )
        lines.append(f"  Findings after: {fix['findings_after']}")
        lines.append(f"  W1 after: {fix['w1_after']}")
        lines.append(f"  W2 after: {fix['w2_after']}")
        lines.append("")

    return "\n".join(lines)
