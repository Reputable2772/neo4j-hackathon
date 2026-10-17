"""Scenario comparison module for AgentFence.

Compares baseline and updated scenarios to identify new findings
introduced by the updated configuration.
"""

from agentfence.detector import detect_data_flow_paths


def compare_scenarios(removed=None):
    """Compare baseline and updated scenario findings.

    Args:
        removed: List of relationship IDs to treat as removed in both scenarios.

    Returns:
        A dict with:
        - baseline_count: int
        - updated_count: int
        - baseline_findings: list
        - updated_findings: list
        - new_in_updated: list of findings present in updated but not baseline
    """
    if removed is None:
        removed = []

    baseline_findings = detect_data_flow_paths(scenario="baseline", removed=removed)
    updated_findings = detect_data_flow_paths(scenario="updated", removed=removed)

    # Identify findings in updated but not in baseline using sorted edge IDs
    baseline_keys = set()
    for f in baseline_findings:
        key = (f["agent"], f["source"], f["destination"],
               tuple(f["tool_chain"]), tuple(f["edge_ids"]))
        baseline_keys.add(key)

    new_in_updated = []
    for f in updated_findings:
        key = (f["agent"], f["source"], f["destination"],
               tuple(f["tool_chain"]), tuple(f["edge_ids"]))
        if key not in baseline_keys:
            new_in_updated.append(f)

    return {
        "baseline_count": len(baseline_findings),
        "updated_count": len(updated_findings),
        "baseline_findings": baseline_findings,
        "updated_findings": updated_findings,
        "new_in_updated": new_in_updated,
    }
