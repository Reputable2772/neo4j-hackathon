import os
import pytest
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from agentfence.db import get_driver
from agentfence.seed import seed_graph
from agentfence.detector import detect_paths
from agentfence.workflows import check_workflows
from agentfence.fixer import find_fix
from agentfence.decisions import save_decision, get_active_removed_edge_ids


def check_neo4j_available():
    try:
        driver = get_driver()
        with driver.session() as session:
            session.run("RETURN 1")
        return True
    except (ServiceUnavailable, AuthError, Exception):
        return False


neo4j_available = check_neo4j_available()
skip_if_no_neo4j = pytest.mark.skipif(
    not neo4j_available,
    reason="Neo4j instance not reachable at configured NEO4J_URI"
)


@pytest.fixture(scope="module")
def driver():
    if not neo4j_available:
        pytest.skip("Neo4j not reachable")
    d = get_driver()
    yield d
    d.close()


@skip_if_no_neo4j
def test_seed_and_baseline_detector(driver):
    scenario = "test_base"
    seed_graph(driver, scenario=scenario)

    # 1. Baseline detector must return exactly two findings
    findings = detect_paths(driver, scenario=scenario)
    assert len(findings) == 2, f"Expected 2 baseline findings, got {len(findings)}"

    destinations = {f.destination for f in findings}
    assert destinations == {"attacker_endpoint", "shadow_endpoint"}

    for f in findings:
        assert f.source == "payroll_report"
        # Verify separation of permission and data-flow evidence
        assert "ret:payroll_report:document_reader" in f.data_flow_edge_ids
        assert "pass:document_reader:webhook_poster" in f.data_flow_edge_ids
        assert "ci:report_agent:webhook_poster" in f.permission_edge_ids


@skip_if_no_neo4j
def test_negative_fixture(driver):
    scenario = "test_negative"
    seed_graph(driver, scenario=scenario)

    # Negative fixture has no complete route to unapproved destinations
    findings = detect_paths(driver, scenario=scenario)
    assert len(findings) == 0, f"Expected 0 findings for negative fixture, got {len(findings)}"


@skip_if_no_neo4j
def test_simulated_removal_overlay_and_baseline_immutability(driver):
    scenario = "test_base"
    seed_graph(driver, scenario=scenario)

    # Count baseline relationships before simulation
    with driver.session() as s:
        initial_rel_count = s.run(
            "MATCH ()-[r {scenario: $scenario}]->() RETURN count(r) AS cnt",
            scenario=scenario
        ).single()["cnt"]

    # Simulating removal of ci:report_agent:webhook_poster must result in 0 findings
    removed_edge_ids = {"ci:report_agent:webhook_poster"}
    findings = detect_paths(driver, scenario=scenario, removed_edge_ids=removed_edge_ids)
    assert len(findings) == 0, f"Expected 0 findings when removing webhook poster, got {len(findings)}"

    # Confirm baseline graph is completely unchanged (no edge was actually removed/mutated)
    with driver.session() as s:
        final_rel_count = s.run(
            "MATCH ()-[r {scenario: $scenario}]->() RETURN count(r) AS cnt",
            scenario=scenario
        ).single()["cnt"]
    assert final_rel_count == initial_rel_count == 10

    # Without removal overlay, the two findings are still detected
    base_findings = detect_paths(driver, scenario=scenario)
    assert len(base_findings) == 2


@skip_if_no_neo4j
def test_idempotent_seed_behavior(driver):
    scenario = "test_idempotent"
    # Seed once
    seed_graph(driver, scenario=scenario)
    with driver.session() as s:
        nodes_run1 = s.run("MATCH (n {scenario: $scenario}) RETURN count(n) AS cnt", scenario=scenario).single()["cnt"]
        rels_run1 = s.run("MATCH ()-[r {scenario: $scenario}]->() RETURN count(r) AS cnt", scenario=scenario).single()["cnt"]

    assert nodes_run1 == 8
    assert rels_run1 == 10

    # Seed twice
    seed_graph(driver, scenario=scenario)
    with driver.session() as s:
        nodes_run2 = s.run("MATCH (n {scenario: $scenario}) RETURN count(n) AS cnt", scenario=scenario).single()["cnt"]
        rels_run2 = s.run("MATCH ()-[r {scenario: $scenario}]->() RETURN count(r) AS cnt", scenario=scenario).single()["cnt"]

    assert nodes_run2 == nodes_run1 == 8
    assert rels_run2 == rels_run1 == 10


@skip_if_no_neo4j
def test_workflows_baseline(driver):
    scenario = "test_base"
    seed_graph(driver, scenario=scenario)

    # 1. W1 and W2 pass on the base graph
    wf_results = check_workflows(driver, scenario=scenario)
    w_map = {w.name: w for w in wf_results}
    assert w_map["W1"].passed is True
    assert w_map["W2"].passed is True

    # 2. Both pass after simulated removal of ci:report_agent:webhook_poster
    wf_after_rem = check_workflows(driver, scenario=scenario, removed_edge_ids={"ci:report_agent:webhook_poster"})
    w_map_rem = {w.name: w for w in wf_after_rem}
    assert w_map_rem["W1"].passed is True
    assert w_map_rem["W2"].passed is True

    # 3. W1 fails if ci:report_agent:document_reader is removed
    wf_no_ci_reader = check_workflows(driver, scenario=scenario, removed_edge_ids={"ci:report_agent:document_reader"})
    assert not next(w for w in wf_no_ci_reader if w.name == "W1").passed

    # 4. W1 fails if read:document_reader:payroll_report is removed
    wf_no_read = check_workflows(driver, scenario=scenario, removed_edge_ids={"read:document_reader:payroll_report"})
    assert not next(w for w in wf_no_read if w.name == "W1").passed

    # 5. W2 fails if a required data-flow relationship is missing (e.g. ret:payroll_report:document_reader or pass:document_reader:email_sender)
    wf_no_ret = check_workflows(driver, scenario=scenario, removed_edge_ids={"ret:payroll_report:document_reader"})
    assert not next(w for w in wf_no_ret if w.name == "W2").passed

    wf_no_pass = check_workflows(driver, scenario=scenario, removed_edge_ids={"pass:document_reader:email_sender"})
    assert not next(w for w in wf_no_pass if w.name == "W2").passed

    # 6. Baseline relationships are not mutated during these checks
    with driver.session() as s:
        rel_count = s.run("MATCH ()-[r {scenario: $scenario}]->() RETURN count(r) AS cnt", scenario=scenario).single()["cnt"]
    assert rel_count == 10


@skip_if_no_neo4j
def test_five_candidate_evaluations_and_fix(driver):
    scenario = "test_base"
    seed_graph(driver, scenario=scenario)

    # Record baseline relationship counts/existence to ensure no graph mutation
    with driver.session() as s:
        initial_rel_count = s.run(
            "MATCH ()-[r {scenario: $scenario}]->() RETURN count(r) AS cnt",
            scenario=scenario
        ).single()["cnt"]

    fix_res = find_fix(driver, scenario=scenario)

    assert len(fix_res.candidates) == 5
    c_map = {c.removed_edge_id: c for c in fix_res.candidates}

    # 1. ci:report_agent:document_reader - REJECT because W1 fails
    assert c_map["ci:report_agent:document_reader"].decision == "REJECT"
    assert "W1 fails" in c_map["ci:report_agent:document_reader"].reason

    # 2. read:document_reader:payroll_report - REJECT because W1 fails
    assert c_map["read:document_reader:payroll_report"].decision == "REJECT"
    assert "W1 fails" in c_map["read:document_reader:payroll_report"].reason

    # 3. ci:report_agent:webhook_poster - ACCEPT
    assert c_map["ci:report_agent:webhook_poster"].decision == "ACCEPT"

    # 4. send:webhook_poster:attacker_endpoint - REJECT because shadow endpoint route remains
    assert c_map["send:webhook_poster:attacker_endpoint"].decision == "REJECT"
    assert len(c_map["send:webhook_poster:attacker_endpoint"].remaining_findings) == 1
    assert c_map["send:webhook_poster:attacker_endpoint"].remaining_findings[0].destination == "shadow_endpoint"

    # 5. send:webhook_poster:shadow_endpoint - REJECT because attacker endpoint route remains
    assert c_map["send:webhook_poster:shadow_endpoint"].decision == "REJECT"
    assert len(c_map["send:webhook_poster:shadow_endpoint"].remaining_findings) == 1
    assert c_map["send:webhook_poster:shadow_endpoint"].remaining_findings[0].destination == "attacker_endpoint"

    # Verify overall fix results:
    assert fix_res.accepted == "ci:report_agent:webhook_poster"
    assert len(fix_res.findings_after_fix) == 0
    assert all(w.passed for w in fix_res.workflows_after_fix)

    # Verify graph was NOT mutated!
    with driver.session() as s:
        final_rel_count = s.run(
            "MATCH ()-[r {scenario: $scenario}]->() RETURN count(r) AS cnt",
            scenario=scenario
        ).single()["cnt"]
    assert final_rel_count == initial_rel_count, "Baseline relationships were mutated during simulation!"


@skip_if_no_neo4j
def test_persistence_and_reload(driver):
    scenario = "test_persistence"
    seed_graph(driver, scenario=scenario)

    # Clear any previous test decisions
    with driver.session() as s:
        s.run("MATCH (d:Decision {scenario: $scenario}) DETACH DELETE d", scenario=scenario)

    fix_res = find_fix(driver, scenario=scenario)
    assert fix_res.accepted == "ci:report_agent:webhook_poster"

    # Save decision
    dec_result = save_decision(driver, fix_res.accepted, scenario=scenario)
    assert dec_result.persisted is True
    assert dec_result.status == "ACTIVE"

    # Reload active decisions
    active_edge_ids = get_active_removed_edge_ids(driver)
    assert "ci:report_agent:webhook_poster" in active_edge_ids

    # Query with active removed edge IDs
    findings = detect_paths(driver, scenario=scenario, removed_edge_ids=active_edge_ids)
    assert len(findings) == 0

    workflows = check_workflows(driver, scenario=scenario, removed_edge_ids=active_edge_ids)
    assert all(w.passed for w in workflows)
