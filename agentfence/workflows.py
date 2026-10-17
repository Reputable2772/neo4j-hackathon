"""Workflow verification engine for AgentFence.

Verifies that essential business workflows continue to operate safely.
Integrates Person 1's upstream contracts and queries while preserving
Person 2's baseline and updated workflow checks.
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union
from neo4j import Driver

from agentfence.contracts import WorkflowResult
from agentfence.db import (
    get_driver,
    get_local_graph,
    is_local_mode,
    run_query,
)

# Person 1 W1 Query:
# report_agent can invoke document_reader,
# reader can read payroll_report,
# and payroll_report returns data to reader.
W1_QUERY = """
MATCH (agent:Agent {id: 'report_agent', scenario: $scenario})-[ci:CAN_INVOKE {scenario: $scenario}]->(reader:Tool {id: 'document_reader', scenario: $scenario})
MATCH (reader)-[r_read:READS {scenario: $scenario}]->(res:Resource {id: 'payroll_report', scenario: $scenario})
MATCH (res)-[r_ret:RETURNS_DATA_TO {scenario: $scenario}]->(reader)
WHERE NOT ci.id IN $removed_edge_ids
  AND NOT r_read.id IN $removed_edge_ids
  AND NOT r_ret.id IN $removed_edge_ids
RETURN count(*) AS cnt
"""

# Person 1 W2 Query:
# agent invocation of reader and sender,
# read permission,
# data returning to reader,
# data passing to email_sender,
# and email_sender sending to approved internal_audit.
W2_QUERY = """
MATCH (agent:Agent {id: 'report_agent', scenario: $scenario})-[ci_reader:CAN_INVOKE {scenario: $scenario}]->(reader:Tool {id: 'document_reader', scenario: $scenario})
MATCH (agent)-[ci_sender:CAN_INVOKE {scenario: $scenario}]->(sender:Tool {id: 'email_sender', scenario: $scenario})
MATCH (reader)-[r_read:READS {scenario: $scenario}]->(res:Resource {id: 'payroll_report', scenario: $scenario})
MATCH (res)-[r_ret:RETURNS_DATA_TO {scenario: $scenario}]->(reader)
MATCH (reader)-[r_pass:PASSES_DATA_TO {scenario: $scenario}]->(sender)
MATCH (sender)-[r_send:SENDS_TO {scenario: $scenario}]->(dest:Destination {id: 'internal_audit', approved: true, scenario: $scenario})
WHERE NOT ci_reader.id IN $removed_edge_ids
  AND NOT ci_sender.id IN $removed_edge_ids
  AND NOT r_read.id IN $removed_edge_ids
  AND NOT r_ret.id IN $removed_edge_ids
  AND NOT r_pass.id IN $removed_edge_ids
  AND NOT r_send.id IN $removed_edge_ids
RETURN count(*) AS cnt
"""


def check_workflows(
    driver: Optional[Any] = None,
    scenario: str = "base",
    removed_edge_ids: Optional[Union[Set[str], list]] = None,
    removed: Optional[Union[Set[str], list]] = None,
) -> List[WorkflowResult]:
    """Check W1 and W2 workflows against the graph taking removed edge overlay into account.

    Complies with Person 1's signature: check_workflows(driver, scenario="base", removed_edge_ids=None).
    """
    if isinstance(driver, str):
        scenario = driver
        driver = None

    effective_removed = removed_edge_ids if removed_edge_ids is not None else removed
    removed_list = list(effective_removed) if effective_removed else []

    driver = driver or get_driver()
    results: List[WorkflowResult] = []

    with driver.session() as session:
        # Check W1
        w1_record = session.run(W1_QUERY, scenario=scenario, removed_edge_ids=removed_list).single()
        w1_passed = w1_record["cnt"] > 0 if w1_record else False
        w1_reason = (
            "W1 passed: report_agent can read payroll_report via document_reader"
            if w1_passed
            else "W1 failed: report_agent cannot read payroll_report via document_reader"
        )
        results.append(WorkflowResult(name="W1", passed=w1_passed, reason=w1_reason))

        # Check W2
        w2_record = session.run(W2_QUERY, scenario=scenario, removed_edge_ids=removed_list).single()
        w2_passed = w2_record["cnt"] > 0 if w2_record else False
        w2_reason = (
            "W2 passed: complete reporting data-path to internal_audit is functional"
            if w2_passed
            else "W2 failed: complete reporting data-path to internal_audit is broken"
        )
        results.append(WorkflowResult(name="W2", passed=w2_passed, reason=w2_reason))

    return results


# ---------- Person 2 baseline / updated workflow verification ----------

def _is_active(rel, scenario, removed):
    """Check if a relationship is active in the given scenario and not removed."""
    return scenario in rel.get("scenarios", [scenario]) and rel["id"] not in removed


def _has_active_rel(scenario, removed, rel_type, from_name, to_name):
    """Check if an active relationship exists between two nodes (local mode)."""
    graph = get_local_graph()
    for rel in graph.get("relationships", []):
        if (rel["type"] == rel_type
                and rel["from"] == from_name
                and rel["to"] == to_name
                and _is_active(rel, scenario, removed)):
            return True
    return False


def check_w1(scenario="baseline", removed=None, driver=None):
    """Check W1 for either Person 1 or Person 2 scenario."""
    if isinstance(scenario, Driver) or hasattr(scenario, "session"):
        driver, scenario = scenario, "base"

    if removed is None:
        removed = []

    if scenario in ("base", "negative", "negative_no_path"):
        results = check_workflows(driver=driver, scenario=scenario, removed_edge_ids=removed)
        w1 = next((r for r in results if r.name == "W1"), None)
        return w1.passed if w1 else False

    # Person 2 baseline/updated
    if is_local_mode():
        return (
            _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "ReadKB")
            and _has_active_rel(scenario, removed, "READS", "ReadKB", "ApprovedKB")
        )

    cypher = """
    MATCH (a:Agent {name: 'SupportAgent'})-[ci:CAN_INVOKE]->(t:Tool {name: 'ReadKB'})-[r:READS]->(res:Resource {name: 'ApprovedKB'})
    WHERE $scenario IN ci.scenarios AND NOT ci.id IN $removed
      AND $scenario IN r.scenarios AND NOT r.id IN $removed
    RETURN count(*) AS cnt
    """
    try:
        result = run_query(cypher, {"scenario": scenario, "removed": removed})
        return result[0]["cnt"] > 0
    except Exception:
        return (
            _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "ReadKB")
            and _has_active_rel(scenario, removed, "READS", "ReadKB", "ApprovedKB")
        )


def check_w2(scenario="baseline", removed=None, driver=None):
    """Check W2 for either Person 1 or Person 2 scenario."""
    if isinstance(scenario, Driver) or hasattr(scenario, "session"):
        driver, scenario = scenario, "base"

    if removed is None:
        removed = []

    if scenario in ("base", "negative", "negative_no_path"):
        results = check_workflows(driver=driver, scenario=scenario, removed_edge_ids=removed)
        w2 = next((r for r in results if r.name == "W2"), None)
        return w2.passed if w2 else False

    # Person 2 baseline/updated
    if is_local_mode():
        return (
            _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "ReadCustomers")
            and _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "Summarize")
            and _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "ReportTool")
            and _has_active_rel(scenario, removed, "READS", "ReadCustomers", "CustomerDB")
            and _has_active_rel(scenario, removed, "PASSES_DATA_TO", "ReadCustomers", "Summarize")
            and _has_active_rel(scenario, removed, "PASSES_DATA_TO", "Summarize", "ReportTool")
        )

    cypher = """
    MATCH (a:Agent {name: 'SupportAgent'})-[ci1:CAN_INVOKE]->(rc:Tool {name: 'ReadCustomers'})-[r:READS]->(db:Resource {name: 'CustomerDB'}),
          (a)-[ci2:CAN_INVOKE]->(s:Tool {name: 'Summarize'}),
          (a)-[ci3:CAN_INVOKE]->(rt:Tool {name: 'ReportTool'}),
          (rc)-[p1:PASSES_DATA_TO]->(s),
          (s)-[p2:PASSES_DATA_TO]->(rt)
    WHERE $scenario IN ci1.scenarios AND NOT ci1.id IN $removed
      AND $scenario IN ci2.scenarios AND NOT ci2.id IN $removed
      AND $scenario IN ci3.scenarios AND NOT ci3.id IN $removed
      AND $scenario IN r.scenarios AND NOT r.id IN $removed
      AND $scenario IN p1.scenarios AND NOT p1.id IN $removed
      AND $scenario IN p2.scenarios AND NOT p2.id IN $removed
    RETURN count(*) AS cnt
    """
    try:
        result = run_query(cypher, {"scenario": scenario, "removed": removed})
        return result[0]["cnt"] > 0
    except Exception:
        return (
            _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "ReadCustomers")
            and _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "Summarize")
            and _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "ReportTool")
            and _has_active_rel(scenario, removed, "READS", "ReadCustomers", "CustomerDB")
            and _has_active_rel(scenario, removed, "PASSES_DATA_TO", "ReadCustomers", "Summarize")
            and _has_active_rel(scenario, removed, "PASSES_DATA_TO", "Summarize", "ReportTool")
        )


def explain_w1(scenario="baseline", removed=None):
    """Check W1 and explain any missing relationships if broken."""
    if removed is None:
        removed = []
    if scenario in ("base", "negative", "negative_no_path"):
        ok = check_w1(scenario=scenario, removed=removed)
        return ok, [] if ok else ["W1 audit workflow path is broken by candidate removal"]

    missing = []
    if not _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "ReadKB"):
        missing.append("SupportAgent -[CAN_INVOKE]-> ReadKB (e03)")
    if not _has_active_rel(scenario, removed, "READS", "ReadKB", "ApprovedKB"):
        missing.append("ReadKB -[READS]-> ApprovedKB (e10)")
    return len(missing) == 0, missing


def explain_w2(scenario="baseline", removed=None):
    """Check W2 and explain any missing relationships if broken."""
    if removed is None:
        removed = []
    if scenario in ("base", "negative", "negative_no_path"):
        ok = check_w2(scenario=scenario, removed=removed)
        return ok, [] if ok else ["W2 alerting workflow path is broken by candidate removal"]

    missing = []
    if not _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "ReadCustomers"):
        missing.append("SupportAgent -[CAN_INVOKE]-> ReadCustomers (e01)")
    if not _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "Summarize"):
        missing.append("SupportAgent -[CAN_INVOKE]-> Summarize (e04)")
    if not _has_active_rel(scenario, removed, "CAN_INVOKE", "SupportAgent", "ReportTool"):
        missing.append("SupportAgent -[CAN_INVOKE]-> ReportTool (e02)")
    if not _has_active_rel(scenario, removed, "READS", "ReadCustomers", "CustomerDB"):
        missing.append("ReadCustomers -[READS]-> CustomerDB (e11)")
    if not _has_active_rel(scenario, removed, "PASSES_DATA_TO", "ReadCustomers", "Summarize"):
        missing.append("ReadCustomers -[PASSES_DATA_TO]-> Summarize (e13)")
    if not _has_active_rel(scenario, removed, "PASSES_DATA_TO", "Summarize", "ReportTool"):
        missing.append("Summarize -[PASSES_DATA_TO]-> ReportTool (e16)")
    return len(missing) == 0, missing


def check_all_workflows(scenario="baseline", removed=None):
    """Check both workflows and return a dict with their status."""
    if removed is None:
        removed = []
    return {
        "W1": check_w1(scenario=scenario, removed=removed),
        "W2": check_w2(scenario=scenario, removed=removed),
    }
