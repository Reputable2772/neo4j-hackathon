"""Database and driver lifecycle management for AgentFence.

Supports both live Neo4j Aura connectivity and in-memory fixture mode.
Never claims live database connection unless verified by a real ping.
"""

import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable, AuthError

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_LOCAL_MODE = False
_FIXTURE_DECISIONS: List[Dict[str, Any]] = []


class FixtureRecord(dict):
    """Dict subclass that allows attribute access matching Neo4j Record."""
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'FixtureRecord' object has no attribute '{name}'")


class FixtureResult:
    """Mock result object providing .single() and iteration matching Neo4j Result."""
    def __init__(self, records: List[Dict[str, Any]]):
        self._records = [FixtureRecord(r) for r in records]

    def __iter__(self):
        return iter(self._records)

    def single(self) -> Optional[FixtureRecord]:
        return self._records[0] if self._records else None

    def __len__(self) -> int:
        return len(self._records)


class FixtureSession:
    """Mock session that evaluates Person 1's exact Cypher queries in fixture mode."""
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def run(self, query: str, **params) -> FixtureResult:
        q = query.strip()
        scenario = params.get("scenario", "base")
        removed_ids = set(params.get("removed_edge_ids") or [])

        # 1. Health check ping
        if "RETURN 1" in q:
            return FixtureResult([{"1": 1}])

        # Relationship count queries
        if "count(r) AS cnt" in q:
            return FixtureResult([{"cnt": 10}])

        # Node count queries
        if "count(n) AS cnt" in q:
            return FixtureResult([{"cnt": 8}])

        # Specific relationship existence query
        if "RETURN count(r)" in q or "RETURN count(r) AS" in q:
            return FixtureResult([{"cnt": 1}])

        # 2. Dangerous paths detection
        if "res.id AS source" in q or "private: true" in q:
            if "negative" in str(scenario):
                return FixtureResult([])

            # Base findings
            f1 = {
                "source": "payroll_report",
                "destination": "attacker_endpoint",
                "path": ["payroll_report", "document_reader", "webhook_poster", "attacker_endpoint"],
                "relationship_ids": [
                    "ci:report_agent:document_reader",
                    "read:document_reader:payroll_report",
                    "ret:payroll_report:document_reader",
                    "pass:document_reader:webhook_poster",
                    "ci:report_agent:webhook_poster",
                    "send:webhook_poster:attacker_endpoint",
                ],
                "permission_edge_ids": [
                    "ci:report_agent:document_reader",
                    "read:document_reader:payroll_report",
                    "ci:report_agent:webhook_poster",
                    "send:webhook_poster:attacker_endpoint",
                ],
                "data_flow_edge_ids": [
                    "ret:payroll_report:document_reader",
                    "pass:document_reader:webhook_poster",
                ],
            }
            f2 = {
                "source": "payroll_report",
                "destination": "shadow_endpoint",
                "path": ["payroll_report", "document_reader", "webhook_poster", "shadow_endpoint"],
                "relationship_ids": [
                    "ci:report_agent:document_reader",
                    "read:document_reader:payroll_report",
                    "ret:payroll_report:document_reader",
                    "pass:document_reader:webhook_poster",
                    "ci:report_agent:webhook_poster",
                    "send:webhook_poster:shadow_endpoint",
                ],
                "permission_edge_ids": [
                    "ci:report_agent:document_reader",
                    "read:document_reader:payroll_report",
                    "ci:report_agent:webhook_poster",
                    "send:webhook_poster:shadow_endpoint",
                ],
                "data_flow_edge_ids": [
                    "ret:payroll_report:document_reader",
                    "pass:document_reader:webhook_poster",
                ],
            }

            records = []
            # Check F1
            if not any(eid in removed_ids for eid in f1["relationship_ids"]):
                records.append(f1)
            # Check F2
            if not any(eid in removed_ids for eid in f2["relationship_ids"]):
                records.append(f2)

            return FixtureResult(records)

        # 3. W1 Workflow Check
        if "W1_QUERY" in q or ("payroll_report" in q and "internal_audit" not in q):
            w1_edges = {"ci:report_agent:document_reader", "read:document_reader:payroll_report", "ret:payroll_report:document_reader"}
            cnt = 0 if any(eid in removed_ids for eid in w1_edges) else 1
            return FixtureResult([{"cnt": cnt}])

        # 4. W2 Workflow Check
        if "W2_QUERY" in q or "internal_audit" in q:
            w2_edges = {
                "ci:report_agent:document_reader",
                "ci:report_agent:email_sender",
                "read:document_reader:payroll_report",
                "ret:payroll_report:document_reader",
                "pass:document_reader:email_sender",
                "send:email_sender:internal_audit",
            }
            cnt = 0 if any(eid in removed_ids for eid in w2_edges) else 1
            return FixtureResult([{"cnt": cnt}])

        # 5. Save Decision
        if "CREATE (d:Decision" in q:
            dec_id = params.get("id", "dec_default")
            r_ids = params.get("removed_edge_ids", [])
            stat = params.get("status", "ACTIVE")
            rec = {"id": dec_id, "removed_edge_ids": r_ids, "status": stat}
            _FIXTURE_DECISIONS.append(rec)
            return FixtureResult([rec])

        # 6. Active Decisions
        if "MATCH (d:Decision {status: 'ACTIVE'})" in q:
            return FixtureResult([{"edge_ids": d["removed_edge_ids"]} for d in _FIXTURE_DECISIONS])

        # 7. Seed / Clear commands
        return FixtureResult([])


class FixtureDriver:
    """Mock Driver providing a session in fixture mode."""
    def session(self, **kwargs) -> FixtureSession:
        return FixtureSession()

    def close(self):
        pass

    def verify_connectivity(self):
        raise ServiceUnavailable("Running in local fixture mode")


def is_local_mode() -> bool:
    """Return True if local fixture mode is active or Neo4j is not connected."""
    global _LOCAL_MODE
    if _LOCAL_MODE:
        return True
    status = health_check()
    return not status.get("ok", False)


def enable_local_mode():
    """Force local fixture mode for testing without database."""
    global _LOCAL_MODE
    _LOCAL_MODE = True


def disable_local_mode():
    """Disable forced local fixture mode."""
    global _LOCAL_MODE
    _LOCAL_MODE = False


def health_check() -> Dict[str, Any]:
    """Perform a live ping against Neo4j and return latency or error details."""
    uri = os.getenv("NEO4J_URI", "")
    user = os.getenv("NEO4J_USERNAME") or os.getenv("NEO4J_USER", "")
    password = os.getenv("NEO4J_PASSWORD", "")

    if not uri or uri.startswith("change_me") or not password or password.startswith("change_me"):
        return {
            "ok": False,
            "latency_ms": None,
            "error": "Neo4j credentials not configured in environment.",
        }

    try:
        start = time.perf_counter()
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            session.run("RETURN 1").single()
        latency = round((time.perf_counter() - start) * 1000, 2)
        driver.close()
        return {"ok": True, "latency_ms": latency, "error": None}
    except Exception as e:
        return {"ok": False, "latency_ms": None, "error": str(e)}


def get_connection_status() -> Dict[str, Any]:
    """Retrieve connection information without leaking secret credentials."""
    status = health_check()
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    return {
        "connected": status.get("ok", False),
        "uri": uri if not uri.startswith("change_me") else "bolt://localhost:7687 (placeholder)",
        "database": os.getenv("NEO4J_DATABASE", "neo4j"),
        "latency_ms": status.get("latency_ms"),
        "error": status.get("error"),
    }


def get_driver(
    uri: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
    auth: Optional[tuple] = None,
    force_live: bool = False,
) -> Driver:
    """Create and return a configured Neo4j Driver instance, or FixtureDriver in fixture mode."""
    global _LOCAL_MODE
    if not force_live and _LOCAL_MODE:
        return FixtureDriver()

    uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
    if auth is None:
        user = user or os.getenv("NEO4J_USERNAME") or os.getenv("NEO4J_USER", "neo4j")
        password = password or os.getenv("NEO4J_PASSWORD", "secretpassword")
        auth = (user, password)

    try:
        d = GraphDatabase.driver(uri, auth=auth)
        if force_live:
            return d
        # Verify if reachable; if not, fallback to FixtureDriver
        with d.session() as s:
            s.run("RETURN 1").single()
        return d
    except Exception:
        if force_live:
            raise
        return FixtureDriver()


_local_graph = None


def _init_local_graph():
    """Initialize in-memory graph representation."""
    global _local_graph
    if _local_graph is not None:
        return
    from agentfence.seed import AGENTS, TOOLS, RESOURCES, EXTERNAL_DESTINATIONS, RELATIONSHIPS
    _local_graph = {
        "agents": AGENTS,
        "tools": TOOLS,
        "resources": RESOURCES,
        "external_destinations": EXTERNAL_DESTINATIONS,
        "relationships": RELATIONSHIPS,
    }


def get_local_graph() -> Dict[str, Any]:
    """Return in-memory graph data."""
    global _local_graph
    if _local_graph is None:
        _init_local_graph()
    return _local_graph


def run_query(cypher: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Execute a parameterized query against Neo4j or fixture session."""
    driver = get_driver()
    with driver.session() as session:
        result = session.run(cypher, **(parameters or {}))
        return [dict(r) for r in result]
