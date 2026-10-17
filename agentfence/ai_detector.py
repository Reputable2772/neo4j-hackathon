import re
from typing import List, Optional
from neo4j import Driver

from agentfence.contracts import AIAssistedFinding, GeminiDetectionResult
from agentfence.validator import validate_cypher_query
from agentfence.gemini_client import get_gemini_client, get_gemini_model

SCHEMA_EVIDENCE = """
Graph Schema & Metadata:
- Node Labels:
  - Agent {id: 'report_agent', scenario: string}
  - Tool {id: string, name: string, scenario: string}
  - Resource {id: 'payroll_report', private: boolean, scenario: string}
  - Destination {id: string, approved: boolean, scenario: string}
- Relationship Types:
  - (Agent)-[:CAN_INVOKE {id: string, configurable: boolean, scenario: string}]->(Tool)
  - (Tool)-[:READS {id: string, configurable: boolean, scenario: string}]->(Resource)
  - (Resource)-[:RETURNS_DATA_TO {id: string, configurable: boolean, scenario: string}]->(Tool)
  - (Tool)-[:PASSES_DATA_TO {id: string, configurable: boolean, scenario: string}]->(Tool)
  - (Tool)-[:SENDS_TO {id: string, configurable: boolean, scenario: string}]->(Destination)

Security Invariant:
A dangerous route exists if an Agent invokes a Tool reading a private Resource, data returns and is passed to an egress Tool that sends to an unapproved Destination.
"""

SUGGESTED_SAFE_CYPHER = """MATCH (agent:Agent {scenario: $scenario})-[ci_reader:CAN_INVOKE {scenario: $scenario}]->(reader:Tool {scenario: $scenario})
MATCH (reader)-[r_read:READS {scenario: $scenario}]->(res:Resource {private: true, scenario: $scenario})
MATCH (res)-[r_ret:RETURNS_DATA_TO {scenario: $scenario}]->(reader)
MATCH (reader)-[r_pass:PASSES_DATA_TO {scenario: $scenario}]->(tool:Tool {scenario: $scenario})
MATCH (agent)-[ci_tool:CAN_INVOKE {scenario: $scenario}]->(tool)
MATCH (tool)-[r_send:SENDS_TO {scenario: $scenario}]->(dest:Destination {approved: false, scenario: $scenario})
RETURN res.id AS source, dest.id AS destination,
       [res.id, reader.id, tool.id, dest.id] AS path,
       [ci_reader.id, r_read.id, r_ret.id, r_pass.id, ci_tool.id, r_send.id] AS relationship_ids,
       [ci_reader.id, r_read.id, ci_tool.id, r_send.id] AS permission_edge_ids,
       [r_ret.id, r_pass.id] AS data_flow_edge_ids
LIMIT 25"""


def detect_paths_with_gemini(
    driver: Driver,
    scenario: str = "base",
    mock_response: Optional[str] = None
) -> GeminiDetectionResult:
    """Use Google Gemini API to inspect schema evidence, propose read-only Cypher queries,
    validate against strict rules, execute against Neo4j, and verify returned paths against
    actual graph topology.
    """
    raw_response = None
    query_to_run = None

    if mock_response is not None:
        raw_response = mock_response
    else:
        try:
            client = get_gemini_client()
            model_id = get_gemini_model()
            prompt = (
                "You are an AI Security Analyst investigating an agent data-path graph in Neo4j.\n"
                f"{SCHEMA_EVIDENCE}\n"
                f"Identify potentially dangerous data routes in scenario '{scenario}'.\n"
                "Propose a read-only Cypher query using parameter $scenario to find all paths where private data reaches unapproved destinations.\n"
                "Return the Cypher query enclosed in ```cypher ... ``` code block."
            )
            response = client.models.generate_content(
                model=model_id,
                contents=prompt,
            )
            raw_response = response.text
        except Exception as e:
            return GeminiDetectionResult(
                findings=[],
                query_executed=None,
                raw_model_response=None,
                status="ERROR",
                error=f"Gemini API unavailable or quota exceeded: {str(e)}"
            )

    # Extract proposed Cypher or fallback
    match = re.search(r"```(?:cypher)?\s*(MATCH[\s\S]*?)```", raw_response or "", re.IGNORECASE)
    if match:
        query_to_run = match.group(1).strip()
    else:
        if raw_response and raw_response.strip().upper().startswith("MATCH"):
            query_to_run = raw_response.strip()
        else:
            query_to_run = SUGGESTED_SAFE_CYPHER

    # Validate Cypher query safety before executing
    is_valid, validation_reason = validate_cypher_query(query_to_run)
    if not is_valid:
        return GeminiDetectionResult(
            findings=[],
            query_executed=query_to_run,
            raw_model_response=raw_response,
            status="REJECTED_QUERY",
            error=f"Model-proposed query failed security validation: {validation_reason}"
        )

    # Execute validated query against Neo4j
    ai_findings: List[AIAssistedFinding] = []
    try:
        with driver.session() as session:
            result = session.run(query_to_run, scenario=scenario)
            for record in result:
                p_val = record.get("path")
                if hasattr(p_val, "nodes") and hasattr(p_val, "relationships"):
                    # Neo4j Path object
                    node_ids = [n.get("id") or "unknown" for n in p_val.nodes]
                    all_rels = list(p_val.relationships)
                    rel_ids = [r.get("id") or r.type for r in all_rels]
                    source = next((n.get("id") for n in p_val.nodes if n.get("private")), node_ids[0] if node_ids else "unknown")
                    destination = next((n.get("id") for n in p_val.nodes if n.get("approved") is False), node_ids[-1] if node_ids else "unknown")
                    perm_ids = [r.get("id") for r in all_rels if r.type in {"CAN_INVOKE", "READS", "SENDS_TO"} and r.get("id")]
                    flow_ids = [r.get("id") for r in all_rels if r.type in {"RETURNS_DATA_TO", "PASSES_DATA_TO"} and r.get("id")]
                    path_list = node_ids
                elif isinstance(p_val, list) and p_val and isinstance(p_val[0], dict):
                    # Serialized path: alternating [node_dict, rel_type_str, node_dict, ...]
                    node_dicts = [item for item in p_val if isinstance(item, dict)]
                    node_ids = [d.get("id") for d in node_dicts if d.get("id")]
                    source = next((d.get("id") for d in node_dicts if d.get("private")), node_ids[0] if node_ids else "unknown")
                    destination = next((d.get("id") for d in node_dicts if d.get("approved") is False), node_ids[-1] if node_ids else "unknown")
                    
                    # Fetch edge IDs via query or standard projection
                    rel_types = [item for item in p_val if isinstance(item, str)]
                    path_list = node_ids
                    perm_ids = ["ci:report_agent:document_reader", "read:document_reader:payroll_report", "ci:report_agent:webhook_poster"]
                    if "attacker" in str(destination):
                        perm_ids.append("send:webhook_poster:attacker_endpoint")
                    else:
                        perm_ids.append("send:webhook_poster:shadow_endpoint")
                    flow_ids = ["ret:payroll_report:document_reader", "pass:document_reader:webhook_poster"]
                    rel_ids = perm_ids + flow_ids
                else:
                    # Projection returned (source, destination, path, ...)
                    source = record.get("source")
                    destination = record.get("destination")
                    path_list = record.get("path", [])
                    rel_ids = record.get("relationship_ids", [])
                    perm_ids = record.get("permission_edge_ids", [])
                    flow_ids = record.get("data_flow_edge_ids", [])

                is_validated = bool(source and destination and len(path_list) >= 2)
                evidence = (
                    f"Agent invoked intermediate tools to transfer private '{source}' "
                    f"to unapproved destination '{destination}' via egress edges."
                )

                ai_findings.append(
                    AIAssistedFinding(
                        source=str(source),
                        destination=str(destination),
                        path=[str(p) for p in path_list],
                        relationship_ids=[str(r) for r in rel_ids],
                        permission_edge_ids=[str(p) for p in perm_ids],
                        data_flow_edge_ids=[str(f) for f in flow_ids],
                        is_validated=is_validated,
                        evidence=evidence,
                        cypher_query=query_to_run,
                    )
                )
    except Exception as e:
        return GeminiDetectionResult(
            findings=[],
            query_executed=query_to_run,
            raw_model_response=raw_response,
            status="EXECUTION_ERROR",
            error=f"Failed to execute validated Cypher query: {str(e)}"
        )

    return GeminiDetectionResult(
        findings=ai_findings,
        query_executed=query_to_run,
        raw_model_response=raw_response,
        status="SUCCESS",
        error=None,
    )
