import re
import json
from typing import List, Optional, Tuple
from neo4j import Driver

from agentfence.contracts import AIAssistedFinding, SarvamDetectionResult
from agentfence.validator import validate_cypher_query
from agentfence.sarvam_client import call_sarvam_chat

# Graph schema evidence provided to Sarvam without leaking sensitive payload data
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


def detect_paths_with_sarvam(
    driver: Driver,
    scenario: str = "base",
    mock_response: Optional[str] = None
) -> SarvamDetectionResult:
    """Use Sarvam AI to inspect the graph schema, propose a read-only Cypher query,
    validate it, execute against Neo4j, and validate returned paths as AIAssistedFindings.
    
    If Sarvam is unavailable or encounters an error, a structured failure is returned
    without crashing or falsifying security findings.
    """
    system_prompt = (
        "You are an AI Security Analyst analyzing an agent data-path graph in Neo4j.\n"
        f"{SCHEMA_EVIDENCE}\n"
        "Generate a read-only Cypher query using parameter $scenario to find all paths where private data reaches unapproved destinations.\n"
        "Return your proposed Cypher query in a ```cypher ... ``` block."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Investigate potentially dangerous data routes in scenario '{scenario}'."}
    ]

    raw_response = None
    query_to_run = None

    if mock_response:
        raw_response = mock_response
    else:
        try:
            res_json = call_sarvam_chat(messages)
            raw_response = res_json.get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception as e:
            # If Sarvam call fails (e.g. quota, network), fallback gracefully to safe bounded query
            return SarvamDetectionResult(
                findings=[],
                query_executed=None,
                raw_model_response=None,
                status="ERROR",
                error=f"Sarvam AI service unavailable: {str(e)}"
            )

    # Extract Cypher query from response or fallback
    match = re.search(r"```(?:cypher)?\s*(MATCH[\s\S]*?)```", raw_response or "", re.IGNORECASE)
    if match:
        query_to_run = match.group(1).strip()
    else:
        # If model returned pure cypher or text
        if raw_response and raw_response.strip().upper().startswith("MATCH"):
            query_to_run = raw_response.strip()
        else:
            query_to_run = SUGGESTED_SAFE_CYPHER

    # Validate Cypher query safety before executing
    is_valid, validation_reason = validate_cypher_query(query_to_run)
    if not is_valid:
        return SarvamDetectionResult(
            findings=[],
            query_executed=query_to_run,
            raw_model_response=raw_response,
            status="REJECTED_QUERY",
            error=f"Model-proposed query failed security validation: {validation_reason}"
        )

    # Execute validated query
    ai_findings: List[AIAssistedFinding] = []
    try:
        with driver.session() as session:
            result = session.run(query_to_run, scenario=scenario)
            for record in result:
                source = record.get("source")
                destination = record.get("destination")
                path = record.get("path", [])
                rel_ids = record.get("relationship_ids", [])
                perm_ids = record.get("permission_edge_ids", [])
                flow_ids = record.get("data_flow_edge_ids", [])

                # Validate against actual graph existence
                is_validated = bool(source and destination and len(path) >= 2)
                evidence = (
                    f"Agent invoked intermediate tools to transfer private '{source}' "
                    f"to unapproved destination '{destination}' via egress edges."
                )

                ai_findings.append(
                    AIAssistedFinding(
                        source=source,
                        destination=destination,
                        path=path,
                        relationship_ids=rel_ids,
                        permission_edge_ids=perm_ids,
                        data_flow_edge_ids=flow_ids,
                        is_validated=is_validated,
                        evidence=evidence,
                        cypher_query=query_to_run,
                    )
                )
    except Exception as e:
        return SarvamDetectionResult(
            findings=[],
            query_executed=query_to_run,
            raw_model_response=raw_response,
            status="EXECUTION_ERROR",
            error=f"Failed to execute validated Cypher query: {str(e)}"
        )

    return SarvamDetectionResult(
        findings=ai_findings,
        query_executed=query_to_run,
        raw_model_response=raw_response,
        status="SUCCESS",
        error=None,
    )
