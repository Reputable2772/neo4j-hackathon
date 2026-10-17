from typing import Optional
from neo4j import Driver
from agentfence.db import get_driver, run_query

# =============================================================================
# Person 1 Neo4j Graph Model & Seed Queries
# =============================================================================

CLEAR_QUERY = """
MATCH (n {scenario: $scenario})
DETACH DELETE n
"""

SEED_NODES_QUERY = """
CREATE 
  (agent:Agent {id: 'report_agent', name: 'Report Agent', scenario: $scenario}),
  (reader:Tool {id: 'document_reader', name: 'Document Reader', scenario: $scenario}),
  (email:Tool {id: 'email_sender', name: 'Email Sender', scenario: $scenario}),
  (webhook:Tool {id: 'webhook_poster', name: 'Webhook Poster', scenario: $scenario}),
  (payroll:Resource {id: 'payroll_report', name: 'Payroll Report', private: true, scenario: $scenario}),
  (audit:Destination {id: 'internal_audit', name: 'Internal Audit', approved: true, scenario: $scenario}),
  (attacker:Destination {id: 'attacker_endpoint', name: 'Attacker Endpoint', approved: false, scenario: $scenario}),
  (shadow:Destination {id: 'shadow_endpoint', name: 'Shadow Endpoint', approved: false, scenario: $scenario})
"""

SEED_RELATIONSHIPS_BASE_QUERY = """
MATCH (agent:Agent {id: 'report_agent', scenario: $scenario}),
      (reader:Tool {id: 'document_reader', scenario: $scenario}),
      (email:Tool {id: 'email_sender', scenario: $scenario}),
      (webhook:Tool {id: 'webhook_poster', scenario: $scenario}),
      (payroll:Resource {id: 'payroll_report', scenario: $scenario}),
      (audit:Destination {id: 'internal_audit', scenario: $scenario}),
      (attacker:Destination {id: 'attacker_endpoint', scenario: $scenario}),
      (shadow:Destination {id: 'shadow_endpoint', scenario: $scenario})
CREATE
  (agent)-[:CAN_INVOKE {id: 'ci:report_agent:document_reader', configurable: true, scenario: $scenario}]->(reader),
  (agent)-[:CAN_INVOKE {id: 'ci:report_agent:email_sender', configurable: true, scenario: $scenario}]->(email),
  (agent)-[:CAN_INVOKE {id: 'ci:report_agent:webhook_poster', configurable: true, scenario: $scenario}]->(webhook),
  (reader)-[:READS {id: 'read:document_reader:payroll_report', configurable: true, scenario: $scenario}]->(payroll),
  (payroll)-[:RETURNS_DATA_TO {id: 'ret:payroll_report:document_reader', configurable: false, scenario: $scenario}]->(reader),
  (reader)-[:PASSES_DATA_TO {id: 'pass:document_reader:email_sender', configurable: false, scenario: $scenario}]->(email),
  (email)-[:SENDS_TO {id: 'send:email_sender:internal_audit', configurable: true, scenario: $scenario}]->(audit),
  (reader)-[:PASSES_DATA_TO {id: 'pass:document_reader:webhook_poster', configurable: false, scenario: $scenario}]->(webhook),
  (webhook)-[:SENDS_TO {id: 'send:webhook_poster:attacker_endpoint', configurable: true, scenario: $scenario}]->(attacker),
  (webhook)-[:SENDS_TO {id: 'send:webhook_poster:shadow_endpoint', configurable: true, scenario: $scenario}]->(shadow)
"""

SEED_RELATIONSHIPS_NEGATIVE_QUERY = """
MATCH (agent:Agent {id: 'report_agent', scenario: $scenario}),
      (reader:Tool {id: 'document_reader', scenario: $scenario}),
      (email:Tool {id: 'email_sender', scenario: $scenario}),
      (payroll:Resource {id: 'payroll_report', scenario: $scenario}),
      (audit:Destination {id: 'internal_audit', scenario: $scenario})
CREATE
  (agent)-[:CAN_INVOKE {id: 'ci:report_agent:document_reader', configurable: true, scenario: $scenario}]->(reader),
  (agent)-[:CAN_INVOKE {id: 'ci:report_agent:email_sender', configurable: true, scenario: $scenario}]->(email),
  (reader)-[:READS {id: 'read:document_reader:payroll_report', configurable: true, scenario: $scenario}]->(payroll),
  (payroll)-[:RETURNS_DATA_TO {id: 'ret:payroll_report:document_reader', configurable: false, scenario: $scenario}]->(reader),
  (reader)-[:PASSES_DATA_TO {id: 'pass:document_reader:email_sender', configurable: false, scenario: $scenario}]->(email),
  (email)-[:SENDS_TO {id: 'send:email_sender:internal_audit', configurable: true, scenario: $scenario}]->(audit)
"""


def seed_graph(driver: Optional[Driver] = None, scenario: str = "base") -> None:
    """Seed the Neo4j database with deterministic scenario graph."""
    driver = driver or get_driver()
    with driver.session() as session:
        session.run(CLEAR_QUERY, scenario=scenario)
        session.run(SEED_NODES_QUERY, scenario=scenario)
        if "negative" in scenario:
            session.run(SEED_RELATIONSHIPS_NEGATIVE_QUERY, scenario=scenario)
        else:
            session.run(SEED_RELATIONSHIPS_BASE_QUERY, scenario=scenario)


# =============================================================================
# Person 2 In-Memory Model Constants
# =============================================================================

AGENTS = [
    {"name": "SupportAgent", "role": "customer-facing support assistant"},
    {"name": "ReportBot", "role": "internal reporting assistant"},
]

TOOLS = [
    {"name": "ReadKB", "purpose": "read approved knowledge base articles"},
    {"name": "ReadCustomers", "purpose": "read customer records"},
    {"name": "Summarize", "purpose": "summarize data into a digest"},
    {"name": "EmailSender", "purpose": "send email to external addresses"},
    {"name": "ReportTool", "purpose": "produce internal reports"},
]

RESOURCES = [
    {"name": "ApprovedKB", "sensitivity": "public"},
    {"name": "CustomerDB", "sensitivity": "private"},
    {"name": "InboundInbox", "sensitivity": "untrusted"},
]

EXTERNAL_DESTINATIONS = [
    {"name": "ExternalEmail", "endpoint": "smtp://external-relay", "canSend": True, "approved": False},
]

RELATIONSHIPS = [
    # CAN_INVOKE - SupportAgent (5 edges)
    {"id": "e01", "type": "CAN_INVOKE", "from": "SupportAgent", "to": "ReadCustomers",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e02", "type": "CAN_INVOKE", "from": "SupportAgent", "to": "ReportTool",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e03", "type": "CAN_INVOKE", "from": "SupportAgent", "to": "ReadKB",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e04", "type": "CAN_INVOKE", "from": "SupportAgent", "to": "Summarize",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e06", "type": "CAN_INVOKE", "from": "SupportAgent", "to": "EmailSender",
     "props": {}, "scenarios": ["baseline", "updated"]},

    # CAN_INVOKE - ReportBot (4 edges)
    {"id": "e05", "type": "CAN_INVOKE", "from": "ReportBot", "to": "ReadKB",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e07", "type": "CAN_INVOKE", "from": "ReportBot", "to": "ReadCustomers",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e08", "type": "CAN_INVOKE", "from": "ReportBot", "to": "ReportTool",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e09", "type": "CAN_INVOKE", "from": "ReportBot", "to": "EmailSender",
     "props": {}, "scenarios": ["baseline", "updated"]},

    # READS - tools reading resources (3 edges)
    {"id": "e10", "type": "READS", "from": "ReadKB", "to": "ApprovedKB",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e11", "type": "READS", "from": "ReadCustomers", "to": "CustomerDB",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e12", "type": "READS", "from": "Summarize", "to": "InboundInbox",
     "props": {}, "scenarios": ["baseline", "updated"]},

    # PASSES_DATA_TO - data flow between tools (5 edges)
    {"id": "e13", "type": "PASSES_DATA_TO", "from": "ReadCustomers", "to": "Summarize",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e14", "type": "PASSES_DATA_TO", "from": "ReadKB", "to": "Summarize",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e15", "type": "PASSES_DATA_TO", "from": "ReadKB", "to": "ReportTool",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e16", "type": "PASSES_DATA_TO", "from": "Summarize", "to": "ReportTool",
     "props": {}, "scenarios": ["baseline", "updated"]},
    {"id": "e17", "type": "PASSES_DATA_TO", "from": "Summarize", "to": "EmailSender",
     "props": {}, "scenarios": ["baseline", "updated"]},

    # SENDS_TO - tools sending to external destinations (1 baseline edge)
    {"id": "e18", "type": "SENDS_TO", "from": "EmailSender", "to": "ExternalEmail",
     "props": {"canSend": True}, "scenarios": ["baseline", "updated"]},

    # e30 - updated scenario only
    {"id": "e30", "type": "SENDS_TO", "from": "ReportTool", "to": "ExternalEmail",
     "props": {"canSend": True}, "scenarios": ["updated"]},
]


def _node_label(name):
    """Return the Neo4j label for a given node name."""
    agent_names = {a["name"] for a in AGENTS}
    tool_names = {t["name"] for t in TOOLS}
    resource_names = {r["name"] for r in RESOURCES}
    dest_names = {d["name"] for d in EXTERNAL_DESTINATIONS}
    if name in agent_names:
        return "Agent"
    if name in tool_names:
        return "Tool"
    if name in resource_names:
        return "Resource"
    if name in dest_names:
        return "ExternalDestination"
    raise ValueError(f"Unknown node name: {name}")


def seed():
    """Idempotently create or update the AgentFence graph in Neo4j."""
    for a in AGENTS:
        run_query("MERGE (n:Agent {name: $name}) SET n.role = $role", {"name": a["name"], "role": a["role"]})
    for t in TOOLS:
        run_query("MERGE (n:Tool {name: $name}) SET n.purpose = $purpose", {"name": t["name"], "purpose": t["purpose"]})
    for r in RESOURCES:
        run_query("MERGE (n:Resource {name: $name}) SET n.sensitivity = $sensitivity", {"name": r["name"], "sensitivity": r["sensitivity"]})
    for d in EXTERNAL_DESTINATIONS:
        run_query("MERGE (n:ExternalDestination {name: $name}) SET n.endpoint = $endpoint, n.canSend = $canSend, n.approved = $approved",
                  {"name": d["name"], "endpoint": d["endpoint"], "canSend": d["canSend"], "approved": d["approved"]})
    for rel in RELATIONSHIPS:
        from_label = _node_label(rel["from"])
        to_label = _node_label(rel["to"])
        rel_type = rel["type"]
        props = dict(rel["props"])
        props["id"] = rel["id"]
        props["scenarios"] = rel["scenarios"]
        cypher = f"MATCH (a:{from_label} {{name: $from_name}}), (b:{to_label} {{name: $to_name}}) MERGE (a)-[r:{rel_type} {{id: $eid}}]->(b) SET r += $props"
        run_query(cypher, {"from_name": rel["from"], "to_name": rel["to"], "eid": rel["id"], "props": props})
