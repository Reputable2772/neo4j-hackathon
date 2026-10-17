"""Detection engine for AgentFence.

Detects dangerous data-flow paths and capability exposure.
Integrates Person 1's upstream contracts and queries while preserving
Person 2's baseline and updated scenarios and capability detection.
"""

from typing import Any, Dict, List, Optional, Set, Union
from neo4j import Driver

from agentfence.contracts import Finding
from agentfence.db import (
    get_driver,
    get_local_graph,
    is_local_mode,
    run_query,
)

# Person 1: Dangerous path detection query
# Path requirements:
# 1. report_agent can invoke document_reader
# 2. document_reader can read private resource (payroll_report)
# 3. payroll_report returns data to document_reader
# 4. document_reader passes data to webhook_poster (or intermediate tool)
# 5. report_agent can invoke the sender tool (webhook_poster)
# 6. sender tool sends to unapproved destination
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


def _is_active(rel, scenario, removed):
    """Check if a relationship is active in the given scenario and not removed."""
    return scenario in rel.get("scenarios", [scenario]) and rel["id"] not in removed


def _get_active_rels(scenario, removed, rel_type=None):
    """Get all active relationships from the local graph, optionally filtered by type."""
    graph = get_local_graph()
    rels = graph.get("relationships", [])
    result = []
    for r in rels:
        if rel_type and r["type"] != rel_type:
            continue
        if _is_active(r, scenario, removed):
            result.append(r)
    return result


def _check_sender(
    agent_name, resource_name, last_tool,
    tool_chain, chain_eids,
    agent_tools, can_invoke_ids, sends_to,
    findings, seen,
):
    """Helper to check if last_tool can send to external destination and record finding."""
    for dest, send_eid in sends_to.get(last_tool, []):
        key = (agent_name, resource_name, dest, tuple(tool_chain))
        if key in seen:
            continue
        seen.add(key)

        # Collect all edge IDs
        all_eids = list(chain_eids) + [send_eid]
        for t in tool_chain:
            ci_eid = can_invoke_ids.get((agent_name, t))
            if ci_eid:
                all_eids.append(ci_eid)

        path_sentence = _build_path_sentence(
            agent_name, resource_name, tool_chain, dest
        )
        findings.append({
            "agent": agent_name,
            "source": resource_name,
            "destination": dest,
            "tool_chain": list(tool_chain),
            "edge_ids": sorted(set(all_eids)),
            "path": path_sentence,
        })


def _detect_local(scenario, removed):
    """Detect data-flow paths using the in-memory graph (Person 2 baseline/updated)."""
    can_invoke = {}
    can_invoke_ids = {}
    reads = {}
    passes_data_to = {}
    sends_to = {}

    for rel in _get_active_rels(scenario, removed, "CAN_INVOKE"):
        agent = rel["from"]
        tool = rel["to"]
        can_invoke.setdefault(agent, set()).add(tool)
        can_invoke_ids[(agent, tool)] = rel["id"]

    graph = get_local_graph()
    for rel in _get_active_rels(scenario, removed, "READS"):
        tool = rel["from"]
        resource = rel["to"]
        sens = None
        for r in graph.get("resources", []):
            if r["name"] == resource:
                sens = r["sensitivity"]
                break
        reads.setdefault(tool, []).append((resource, sens, rel["id"]))

    for rel in _get_active_rels(scenario, removed, "PASSES_DATA_TO"):
        passes_data_to.setdefault(rel["from"], []).append((rel["to"], rel["id"]))

    for rel in _get_active_rels(scenario, removed, "SENDS_TO"):
        if rel["props"].get("canSend", False):
            sends_to.setdefault(rel["from"], []).append((rel["to"], rel["id"]))

    findings = []
    seen = set()
    agents = [a["name"] for a in graph.get("agents", [])]

    for agent_name in agents:
        agent_tools = can_invoke.get(agent_name, set())

        for reader_tool, read_entries in reads.items():
            for resource_name, sensitivity, read_eid in read_entries:
                if sensitivity not in ("private", "untrusted"):
                    continue
                if reader_tool not in agent_tools:
                    continue

                # 0 hops: reader_tool directly sends
                _check_sender(
                    agent_name, resource_name, reader_tool,
                    [reader_tool], [read_eid],
                    agent_tools, can_invoke_ids, sends_to,
                    findings, seen,
                )

                # 1 hop: reader_tool -> t1
                for t1, p1_eid in passes_data_to.get(reader_tool, []):
                    if t1 not in agent_tools:
                        continue
                    _check_sender(
                        agent_name, resource_name, t1,
                        [reader_tool, t1], [read_eid, p1_eid],
                        agent_tools, can_invoke_ids, sends_to,
                        findings, seen,
                    )

                    # 2 hops: reader_tool -> t1 -> t2
                    for t2, p2_eid in passes_data_to.get(t1, []):
                        if t2 not in agent_tools:
                            continue
                        _check_sender(
                            agent_name, resource_name, t2,
                            [reader_tool, t1, t2], [read_eid, p1_eid, p2_eid],
                            agent_tools, can_invoke_ids, sends_to,
                            findings, seen,
                        )

    findings.sort(key=lambda f: (f["agent"], f["source"], f["destination"], tuple(f["tool_chain"])))
    return findings


def detect_paths(
    driver: Optional[Any] = None,
    scenario: str = "base",
    removed_edge_ids: Optional[Union[Set[str], list]] = None,
    removed: Optional[Union[Set[str], list]] = None,
) -> List[Finding]:
    """Detect dangerous data paths in Neo4j without mutating graph relationships.

    Complies with Person 1's signature: detect_paths(driver, scenario="base", removed_edge_ids=None).
    Also supports driver omitted, scenario passed positionally, and backward compatibility.
    """
    if isinstance(driver, str):
        scenario = driver
        driver = None

    effective_removed = removed_edge_ids if removed_edge_ids is not None else removed
    removed_list = list(effective_removed) if effective_removed else []

    driver = driver or get_driver()
    findings: List[Finding] = []

    with driver.session() as session:
        result = session.run(
            DETECT_PATHS_QUERY,
            scenario=scenario,
            removed_edge_ids=removed_list,
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


def detect_data_flow_paths(
    scenario: str = "baseline",
    removed: Optional[List[str]] = None,
    driver: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Detect data-flow paths for Person 2 baseline/updated scenarios or legacy callers.

    Returns dicts conforming to Person 2 expectations.
    """
    if isinstance(scenario, Driver) or hasattr(scenario, "session"):
        # Swapped positional args
        driver, scenario = scenario, "base"

    if removed is None:
        removed = []

    if scenario in ("baseline", "updated"):
        if is_local_mode():
            return _detect_local(scenario, removed)

        cypher = """
        MATCH (res:Resource)<-[r_reads:READS]-(t0:Tool)-[r_sends:SENDS_TO]->(dest:ExternalDestination)
        WHERE res.sensitivity IN ['private', 'untrusted']
          AND $scenario IN r_reads.scenarios AND NOT r_reads.id IN $removed
          AND $scenario IN r_sends.scenarios AND NOT r_sends.id IN $removed
          AND r_sends.canSend = true
        WITH res, dest, [t0] AS tools, [r_reads.id, r_sends.id] AS edge_ids
        MATCH (agent:Agent)-[ci:CAN_INVOKE]->(t)
        WHERE t IN tools
          AND $scenario IN ci.scenarios AND NOT ci.id IN $removed
        WITH agent, res, dest, tools, edge_ids, collect(DISTINCT ci.id) AS ci_ids, collect(DISTINCT t) AS invokable
        WHERE size(invokable) = size(tools)
        RETURN agent.name AS agent, res.name AS source, dest.name AS destination,
               [t IN tools | t.name] AS tool_chain, edge_ids + ci_ids AS all_edge_ids

        UNION ALL

        MATCH (res:Resource)<-[r_reads:READS]-(t0:Tool)-[r_pass1:PASSES_DATA_TO]->(t1:Tool)-[r_sends:SENDS_TO]->(dest:ExternalDestination)
        WHERE res.sensitivity IN ['private', 'untrusted']
          AND $scenario IN r_reads.scenarios AND NOT r_reads.id IN $removed
          AND $scenario IN r_pass1.scenarios AND NOT r_pass1.id IN $removed
          AND $scenario IN r_sends.scenarios AND NOT r_sends.id IN $removed
          AND r_sends.canSend = true
        WITH res, dest, [t0, t1] AS tools, [r_reads.id, r_pass1.id, r_sends.id] AS edge_ids
        MATCH (agent:Agent)-[ci:CAN_INVOKE]->(t)
        WHERE t IN tools
          AND $scenario IN ci.scenarios AND NOT ci.id IN $removed
        WITH agent, res, dest, tools, edge_ids, collect(DISTINCT ci.id) AS ci_ids, collect(DISTINCT t) AS invokable
        WHERE size(invokable) = size(tools)
        RETURN agent.name AS agent, res.name AS source, dest.name AS destination,
               [t IN tools | t.name] AS tool_chain, edge_ids + ci_ids AS all_edge_ids

        UNION ALL

        MATCH (res:Resource)<-[r_reads:READS]-(t0:Tool)-[r_pass1:PASSES_DATA_TO]->(t1:Tool)-[r_pass2:PASSES_DATA_TO]->(t2:Tool)-[r_sends:SENDS_TO]->(dest:ExternalDestination)
        WHERE res.sensitivity IN ['private', 'untrusted']
          AND $scenario IN r_reads.scenarios AND NOT r_reads.id IN $removed
          AND $scenario IN r_pass1.scenarios AND NOT r_pass1.id IN $removed
          AND $scenario IN r_pass2.scenarios AND NOT r_pass2.id IN $removed
          AND $scenario IN r_sends.scenarios AND NOT r_sends.id IN $removed
          AND r_sends.canSend = true
        WITH res, dest, [t0, t1, t2] AS tools, [r_reads.id, r_pass1.id, r_pass2.id, r_sends.id] AS edge_ids
        MATCH (agent:Agent)-[ci:CAN_INVOKE]->(t)
        WHERE t IN tools
          AND $scenario IN ci.scenarios AND NOT ci.id IN $removed
        WITH agent, res, dest, tools, edge_ids, collect(DISTINCT ci.id) AS ci_ids, collect(DISTINCT t) AS invokable
        WHERE size(invokable) = size(tools)
        RETURN agent.name AS agent, res.name AS source, dest.name AS destination,
               [t IN tools | t.name] AS tool_chain, edge_ids + ci_ids AS all_edge_ids
        """

        try:
            results = run_query(cypher, {"scenario": scenario, "removed": removed})
            seen = set()
            findings = []
            for row in results:
                key = (row["agent"], row["source"], row["destination"], tuple(row["tool_chain"]))
                if key in seen:
                    continue
                seen.add(key)
                edge_ids = sorted(set(row["all_edge_ids"]))
                tool_chain = row["tool_chain"]
                path_sentence = _build_path_sentence(
                    row["agent"], row["source"], tool_chain, row["destination"]
                )
                findings.append({
                    "agent": row["agent"],
                    "source": row["source"],
                    "destination": row["destination"],
                    "tool_chain": tool_chain,
                    "edge_ids": edge_ids,
                    "path": path_sentence,
                })
            findings.sort(key=lambda f: (f["agent"], f["source"], f["destination"], tuple(f["tool_chain"])))
            return findings
        except Exception:
            return _detect_local(scenario, removed)

    # For base/negative scenarios, bridge through detect_paths
    person1_findings = detect_paths(driver=driver, scenario=scenario, removed_edge_ids=removed)
    res = []
    for f in person1_findings:
        res.append({
            "agent": "report_agent",
            "source": f.source,
            "destination": f.destination,
            "tool_chain": f.path[1:-1] if len(f.path) > 2 else [],
            "edge_ids": f.relationship_ids,
            "path": f"report_agent: {f.source} -> [{' -> '.join(f.path[1:-1])}] -> {f.destination}",
        })
    return res


def _build_path_sentence(agent, source, tool_chain, destination):
    """Build a readable path sentence for a finding."""
    chain_str = " -> ".join(tool_chain)
    return f"{agent}: {source} -> [{chain_str}] -> {destination}"


def get_agent_capabilities(scenario="baseline", removed=None):
    """Calculate the three risk capabilities for each agent."""
    if removed is None:
        removed = []

    graph = get_local_graph()

    can_invoke = {}
    for rel in _get_active_rels(scenario, removed, "CAN_INVOKE"):
        can_invoke.setdefault(rel["from"], set()).add(rel["to"])

    tool_reads_private = {}
    tool_reads_untrusted = {}
    for rel in _get_active_rels(scenario, removed, "READS"):
        resource = rel["to"]
        sens = None
        for r in graph.get("resources", []):
            if r["name"] == resource:
                sens = r["sensitivity"]
                break
        if sens == "private":
            tool_reads_private.setdefault(rel["from"], set()).add(resource)
        elif sens == "untrusted":
            tool_reads_untrusted.setdefault(rel["from"], set()).add(resource)

    tool_sends = {}
    for rel in _get_active_rels(scenario, removed, "SENDS_TO"):
        if rel["props"].get("canSend", False):
            tool_sends.setdefault(rel["from"], set()).add(rel["to"])

    breakdown = []
    agents = sorted(a["name"] for a in graph.get("agents", []))
    for agent in agents:
        tools = can_invoke.get(agent, set())
        priv_details = []
        for t in sorted(tools):
            if t in tool_reads_private:
                for res in sorted(tool_reads_private[t]):
                    priv_details.append(f"{res} (via {t})")

        unt_details = []
        for t in sorted(tools):
            if t in tool_reads_untrusted:
                for res in sorted(tool_reads_untrusted[t]):
                    unt_details.append(f"{res} (via {t})")

        send_details = []
        for t in sorted(tools):
            if t in tool_sends:
                for dst in sorted(tool_sends[t]):
                    send_details.append(f"{dst} (via {t})")

        has_private = len(priv_details) > 0
        has_untrusted = len(unt_details) > 0
        has_external = len(send_details) > 0
        has_all_three = has_private and has_untrusted and has_external

        read_tools = sorted([t for t in tools if t in tool_reads_private or t in tool_reads_untrusted])
        resources = sorted(list(set([r.split(" ")[0] for r in priv_details + unt_details])))
        send_tools = sorted([t for t in tools if t in tool_sends])
        destinations = sorted(list(set([d.split(" ")[0] for d in send_details])))

        breakdown.append({
            "agent": agent,
            "has_all_three": has_all_three,
            "has_private": has_private,
            "has_untrusted": has_untrusted,
            "has_external": has_external,
            "private_details": priv_details if priv_details else ["Not available"],
            "untrusted_details": unt_details if unt_details else ["Not available"],
            "external_details": send_details if send_details else ["Not available"],
            "read_tools": read_tools,
            "resources": resources,
            "send_tools": send_tools,
            "destinations": destinations,
        })

    return breakdown


def detect_capability_exposure(scenario="baseline", removed=None):
    """Detect agents with all three risk capabilities."""
    if removed is None:
        removed = []

    caps = get_agent_capabilities(scenario, removed)
    results = [c for c in caps if c["has_all_three"]]

    warnings = []
    for row in results:
        agent = row["agent"]
        resources = row["resources"]
        destinations = row["destinations"]
        warnings.append({
            "agent": agent,
            "read_tools": row["read_tools"],
            "resources": row["resources"],
            "send_tools": row["send_tools"],
            "destinations": row["destinations"],
            "warning": (
                f"{agent} can invoke tools that read private data, untrusted "
                f"content ({', '.join(resources)}) and can invoke tools "
                f"that send to external destinations ({', '.join(destinations)}). "
                f"This is a capability co-occurrence warning, not a confirmed exploit path."
            ),
        })
    return warnings
