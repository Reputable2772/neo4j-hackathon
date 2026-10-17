from typing import List, Optional, Set
from neo4j import Driver
from agentfence.contracts import WorkflowResult

# W1 Query:
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

# W2 Query:
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
    driver: Driver,
    scenario: str = "base",
    removed_edge_ids: Optional[Set[str] | list[str]] = None
) -> List[WorkflowResult]:
    """Check W1 and W2 workflows against the graph taking removed edge overlay into account."""
    removed = list(removed_edge_ids) if removed_edge_ids else []
    results: List[WorkflowResult] = []

    with driver.session() as session:
        # Check W1
        w1_record = session.run(W1_QUERY, scenario=scenario, removed_edge_ids=removed).single()
        w1_passed = w1_record["cnt"] > 0 if w1_record else False
        w1_reason = "W1 passed: report_agent can read payroll_report via document_reader" if w1_passed else "W1 failed: report_agent cannot read payroll_report via document_reader"
        results.append(WorkflowResult(name="W1", passed=w1_passed, reason=w1_reason))

        # Check W2
        w2_record = session.run(W2_QUERY, scenario=scenario, removed_edge_ids=removed).single()
        w2_passed = w2_record["cnt"] > 0 if w2_record else False
        w2_reason = "W2 passed: complete reporting data-path to internal_audit is functional" if w2_passed else "W2 failed: complete reporting data-path to internal_audit is broken"
        results.append(WorkflowResult(name="W2", passed=w2_passed, reason=w2_reason))

    return results
