import uuid
from typing import Set, List, Optional, Dict, Any
from neo4j import Driver
from agentfence.contracts import DecisionResult
from agentfence.db import get_driver

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

_DECISION_STORE: List[Dict[str, Any]] = []


def get_active_removed_edge_ids(driver: Optional[Driver] = None) -> Set[str]:
    """Retrieve all removed edge IDs from active persisted decisions."""
    driver = driver or get_driver()
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


def save_decision(
    driver: Optional[Driver] = None,
    candidate: str = "",
    scenario: str = "base",
    candidate_removed: Optional[List[str]] = None,
    candidate_edges: Optional[List[Dict[str, Any]]] = None,
    findings_before: int = 2,
    findings_after: int = 0,
    w1_ok: bool = True,
    w2_ok: bool = True,
    rationale: str = "",
    status: str = "ACTIVE",
) -> DecisionResult:
    """Persist an accepted fix decision into Neo4j without modifying baseline edges."""
    driver = driver or get_driver()
    decision_id = f"dec-{uuid.uuid4().hex[:8]}"

    if candidate_removed:
        removed_ids = candidate_removed
    elif candidate:
        removed_ids = [candidate] if isinstance(candidate, str) else list(candidate)
    else:
        removed_ids = ["ci:report_agent:webhook_poster"]

    with driver.session() as session:
        session.run(
            SAVE_DECISION_QUERY,
            id=decision_id,
            scenario=scenario,
            removed_edge_ids=removed_ids,
            status=status,
        )

    rec = {
        "decision_id": decision_id,
        "removed_edge_ids": removed_ids,
        "candidate_removed": removed_ids[0] if len(removed_ids) == 1 else removed_ids,
        "status": status,
        "persisted": True,
        "scenario": scenario,
        "findings_before": findings_before,
        "findings_after": findings_after,
        "w1_ok": w1_ok,
        "w2_ok": w2_ok,
        "rationale": rationale,
    }
    _DECISION_STORE.append(rec)

    return DecisionResult(
        decision_id=decision_id,
        removed_edge_ids=removed_ids,
        status=status,
        persisted=True,
    )


def get_decision(decision_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a persisted decision record by ID."""
    for d in _DECISION_STORE:
        if d.get("decision_id") == decision_id:
            return d
    return None


def list_decisions(limit: int = 20) -> List[Dict[str, Any]]:
    """Return recent decision history."""
    return list(reversed(_DECISION_STORE))[:limit]
