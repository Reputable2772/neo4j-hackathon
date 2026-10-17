from neo4j import Driver

# Seed queries with deterministic stable IDs and separate scenario property.
# Nodes:
# Agent: report_agent
# Tools: document_reader, email_sender, webhook_poster
# Private resource: payroll_report
# Approved internal destination: internal_audit
# Unapproved destinations: attacker_endpoint, shadow_endpoint

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

# Base scenario relationships:
# Permissions:
# 1. ci:report_agent:document_reader (CAN_INVOKE, configurable: true)
# 2. ci:report_agent:email_sender (CAN_INVOKE, configurable: true)
# 3. ci:report_agent:webhook_poster (CAN_INVOKE, configurable: true)
# 4. read:document_reader:payroll_report (READS, configurable: true)
# 5. send:email_sender:internal_audit (SENDS_TO, configurable: true)
# 6. send:webhook_poster:attacker_endpoint (SENDS_TO, configurable: true)
# 7. send:webhook_poster:shadow_endpoint (SENDS_TO, configurable: true)
#
# Data-flow evidence (NOT configurable, configurable: false):
# 8. ret:payroll_report:document_reader (RETURNS_DATA_TO)
# 9. pass:document_reader:email_sender (PASSES_DATA_TO)
# 10. pass:document_reader:webhook_poster (PASSES_DATA_TO)

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

# Negative fixture relationships:
# Breaks the route so no complete path from private resource to unapproved destination exists.
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

def seed_graph(driver: Driver, scenario: str = "base") -> None:
    """Seed the Neo4j database with deterministic scenario graph."""
    with driver.session() as session:
        session.run(CLEAR_QUERY, scenario=scenario)
        session.run(SEED_NODES_QUERY, scenario=scenario)
        if "negative" in scenario:
            session.run(SEED_RELATIONSHIPS_NEGATIVE_QUERY, scenario=scenario)
        else:
            session.run(SEED_RELATIONSHIPS_BASE_QUERY, scenario=scenario)
