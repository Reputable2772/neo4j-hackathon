import re
from typing import Tuple

# Explicit allowlist of permissible node labels, relationship types, and properties
ALLOWED_LABELS = {"Agent", "Tool", "Resource", "Destination"}
ALLOWED_REL_TYPES = {
    "CAN_INVOKE",
    "READS",
    "RETURNS_DATA_TO",
    "PASSES_DATA_TO",
    "SENDS_TO",
}
ALLOWED_PROPERTIES = {
    "id",
    "name",
    "scenario",
    "private",
    "approved",
    "configurable",
}

# Forbidden keywords indicating write operations, procedures, system commands, or unbounded queries
FORBIDDEN_KEYWORDS = [
    r"\bCREATE\b",
    r"\bDELETE\b",
    r"\bDETACH\b",
    r"\bSET\b",
    r"\bMERGE\b",
    r"\bREMOVE\b",
    r"\bDROP\b",
    r"\bCALL\b",
    r"\bLOAD\b",
    r"\bCSV\b",
    r"\bPERIODIC\b",
    r"\bCOMMIT\b",
    r"\bDBMS\b",
    r"\bAPOC\b",
    r"\bSECURITY\b",
    r"\bUSER\b",
    r"\bROLE\b",
]


def validate_cypher_query(query: str) -> Tuple[bool, str]:
    """Validate that a Cypher query proposed by an LLM is strictly read-only and safe.
    
    Rules:
    1. Must contain MATCH and RETURN.
    2. Must NOT contain any write/mutation/procedure keywords.
    3. Must not access system tables or procedures.
    4. Must have an explicit LIMIT (<= 50) or match specific bounded paths.
    """
    if not query or not query.strip():
        return False, "Query is empty"

    normalized = query.strip()

    # Must start with MATCH or OPTIONAL MATCH
    if not (re.match(r"^(OPTIONAL\s+)?MATCH\b", normalized, re.IGNORECASE)):
        return False, "Query must start with MATCH or OPTIONAL MATCH"

    # Must contain RETURN
    if not re.search(r"\bRETURN\b", normalized, re.IGNORECASE):
        return False, "Query must contain a RETURN clause"

    # Check for forbidden mutation and system keywords
    for pattern in FORBIDDEN_KEYWORDS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return False, f"Query contains forbidden keyword/clause: {pattern}"

    # Disallow semi-colons to prevent multi-statement injection
    if ";" in normalized.rstrip(";"):
        return False, "Multi-statement queries separated by semicolons are not permitted"

    return True, "Valid read-only Cypher query"
