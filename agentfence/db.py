import os
from typing import Optional
from neo4j import GraphDatabase, Driver

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def get_driver(
    uri: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
    auth: Optional[tuple] = None
) -> Driver:
    """Create and return a configured Neo4j Driver instance."""
    uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
    if auth is None:
        user = user or os.getenv("NEO4J_USERNAME") or os.getenv("NEO4J_USER", "neo4j")
        password = password or os.getenv("NEO4J_PASSWORD", "secretpassword")
        auth = (user, password)
    return GraphDatabase.driver(uri, auth=auth)
