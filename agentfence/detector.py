from typing import List, Optional, Set
from neo4j import Driver
from agentfence.contracts import Finding

# Dangerous path detection query
# Path requirements:
# 1. report_agent can invoke document_reader
# 2. document_reader can read private resource (payroll_report)
# 3. payroll_report returns data to document_reader
# 4. document_reader passes data to webhook_poster (or intermediate tool)
# 5. report_agent can invoke the sender tool (webhook_poster)
# 6. sender tool sends to unapproved destination
#
# All relationships must match scenario and NOT be in removed_edge_ids.
#
# Query to find all complete dangerous data paths from private resource to unapproved destination:
DETECT_PATHS_QUERY = """
MATCH (agent:Agent {id: 'report_agent', scenario: $scenario})-[ci_reader:CAN_INVOKE {scenario: $scenario}]->(reader:Tool {scenario: $scenario})
MATCH (reader)-[r_read:READS {scenario: $scenario}]->(res:Resource {private: true, scenario: $scenario})
MATCH (res)-[r_ret:RETURNS_DATA_TO {scenario: $scenario}]->(reader)
MATCH (reader)-[r_pass:PASSES_DATA_TO {scenario: $scenario}]->(tool:Tool {scenario: $scenario})
MATCH (agent)-[ci_tool:CAN_INVOKE {scenario: $scenario}]->(tool)
MATCH (tool)-[r_send:SENDS_TO {scenario: $scenario}]->(dest:Destination {approved: false, scenario: $scenario})
WHERE NOT ci_reader.id IN $removed_edge_ids
  AND NOT r_read.id IN $removed_edge_ids
  AND NOT r_ret.id IN $removed_edge_ids
  AND NOT r_pass.id IN $removed_edge_ids
  AND NOT ci_tool.id IN $removed_edge_ids
  AND NOT r_send.id IN $removed_edge_ids
RETURN 
  res.id AS source,
  dest.id AS destination,
  [res.id, reader.id, tool.id, dest.id] AS path,
  [ci_reader.id, r_read.id, r_ret.id, r_pass.id, ci_tool.id, r_send.id] AS relationship_ids,
  [ci_reader.id, r_read.id, ci_tool.id, r_send.id] AS permission_edge_ids,
  [r_ret.id, r_pass.id] AS data_flow_edge_ids
ORDER BY dest.id ASC
"""

def detect_paths(
    driver: Driver,
    scenario: str = "base",
    removed_edge_ids: Optional[Set[str] | list[str]] = None
) -> List[Finding]:
    """Detect dangerous data paths in Neo4j without mutating graph relationships."""
    removed = list(removed_edge_ids) if removed_edge_ids else []
    findings: List[Finding] = []
    
    with driver.session() as session:
        result = session.run(
            DETECT_PATHS_QUERY,
            scenario=scenario,
            removed_edge_ids=removed
        )
        for record in result:
            findings.append(
                Finding(
                    source=record["source"],
                    destination=record["destination"],
                    path=record["path"],
                    relationship_ids=record["relationship_ids"],
                    permission_edge_ids=record["permission_edge_ids"],
                    data_flow_edge_ids=record["data_flow_edge_ids"],
                )
            )
            
    return findings
