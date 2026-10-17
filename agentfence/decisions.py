import uuid
from typing import Set, List
from neo4j import Driver
from agentfence.contracts import DecisionResult

# Decisions are stored in Neo4j as (:Decision {id, scenario, removed_edge_ids, status, timestamp})
# Notice we DO NOT mutate the baseline relationship edges themselves!
# We persist the decision record, and get_active_removed_edge_ids reads all active decisions.

SAVE_DECISION_QUERY = """
CREATE (d:Decision {
  id: $id,
  scenario: $scenario,
  removed_edge_ids: $removed_edge_ids,
  status: $status,
  created_at: datetime()
})
RETURN d.id AS id, d.removed_edge_ids AS removed_edge_ids, d.status AS status
"""

GET_ACTIVE_DECISIONS_QUERY = """
MATCH (d:Decision {status: 'ACTIVE'})
RETURN d.removed_edge_ids AS edge_ids
"""

def get_active_removed_edge_ids(driver: Driver) -> Set[str]:
    """Retrieve all removed edge IDs from active persisted decisions."""
    removed: Set[str] = set()
    with driver.session() as session:
        result = session.run(GET_ACTIVE_DECISIONS_QUERY)
        for record in result:
            edge_ids = record["edge_ids"]
            if edge_ids:
                if isinstance(edge_ids, list):
                    removed.update(edge_ids)
                elif isinstance(edge_ids, str):
                    removed.add(edge_ids)
    return removed

def save_decision(driver: Driver, candidate: str, scenario: str = "base") -> DecisionResult:
    """Persist an accepted fix decision into Neo4j without modifying baseline edges."""
    decision_id = f"dec_{uuid.uuid4().hex[:8]}"
    removed_ids = [candidate] if isinstance(candidate, str) else list(candidate)
    
    with driver.session() as session:
        session.run(
            SAVE_DECISION_QUERY,
            id=decision_id,
            scenario=scenario,
            removed_edge_ids=removed_ids,
            status="ACTIVE",
        )

    return DecisionResult(
        decision_id=decision_id,
        removed_edge_ids=removed_ids,
        status="ACTIVE",
        persisted=True
    )
