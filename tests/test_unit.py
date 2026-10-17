import pytest
from unittest.mock import MagicMock
from agentfence.contracts import Finding, WorkflowResult, CandidateResult, FixResult, DecisionResult
from agentfence.seed import seed_graph, CLEAR_QUERY, SEED_NODES_QUERY, SEED_RELATIONSHIPS_BASE_QUERY, SEED_RELATIONSHIPS_NEGATIVE_QUERY
from agentfence.detector import detect_paths
from agentfence.workflows import check_workflows
from agentfence.fixer import find_fix, CANDIDATES
from agentfence.decisions import save_decision, get_active_removed_edge_ids


def test_contracts_initialization():
    f = Finding(
        source="payroll_report",
        destination="attacker_endpoint",
        path=["payroll_report", "document_reader", "webhook_poster", "attacker_endpoint"],
        relationship_ids=["ci:report_agent:document_reader", "read:document_reader:payroll_report"],
        permission_edge_ids=["ci:report_agent:document_reader"],
        data_flow_edge_ids=["ret:payroll_report:document_reader"]
    )
    assert f.source == "payroll_report"
    assert len(f.path) == 4

    w = WorkflowResult(name="W1", passed=True, reason="ok")
    assert w.passed is True

    c = CandidateResult(removed_edge_id="e1", decision="ACCEPT", reason="ok", remaining_findings=[], workflows=[w])
    assert c.decision == "ACCEPT"

    fix = FixResult(candidates=[c], accepted="e1", findings_after_fix=[], workflows_after_fix=[w])
    assert fix.accepted == "e1"

    d = DecisionResult(decision_id="d1", removed_edge_ids=["e1"], status="ACTIVE", persisted=True)
    assert d.persisted is True


def test_seed_graph_execution():
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__.return_value = session

    # Test base scenario seed
    seed_graph(driver, scenario="base")
    assert session.run.call_count == 3
    session.run.assert_any_call(CLEAR_QUERY, scenario="base")
    session.run.assert_any_call(SEED_NODES_QUERY, scenario="base")
    session.run.assert_any_call(SEED_RELATIONSHIPS_BASE_QUERY, scenario="base")

    # Test negative scenario seed
    session.reset_mock()
    seed_graph(driver, scenario="negative")
    assert session.run.call_count == 3
    session.run.assert_any_call(CLEAR_QUERY, scenario="negative")
    session.run.assert_any_call(SEED_NODES_QUERY, scenario="negative")
    session.run.assert_any_call(SEED_RELATIONSHIPS_NEGATIVE_QUERY, scenario="negative")


def test_detect_paths_unit():
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__.return_value = session

    # Mock records returned by session.run
    mock_record1 = {
        "source": "payroll_report",
        "destination": "attacker_endpoint",
        "path": ["payroll_report", "document_reader", "webhook_poster", "attacker_endpoint"],
        "relationship_ids": [
            "ci:report_agent:document_reader", "read:document_reader:payroll_report",
            "ret:payroll_report:document_reader", "pass:document_reader:webhook_poster",
            "ci:report_agent:webhook_poster", "send:webhook_poster:attacker_endpoint"
        ],
        "permission_edge_ids": [
            "ci:report_agent:document_reader", "read:document_reader:payroll_report",
            "ci:report_agent:webhook_poster", "send:webhook_poster:attacker_endpoint"
        ],
        "data_flow_edge_ids": [
            "ret:payroll_report:document_reader", "pass:document_reader:webhook_poster"
        ]
    }
    mock_record2 = {
        "source": "payroll_report",
        "destination": "shadow_endpoint",
        "path": ["payroll_report", "document_reader", "webhook_poster", "shadow_endpoint"],
        "relationship_ids": [
            "ci:report_agent:document_reader", "read:document_reader:payroll_report",
            "ret:payroll_report:document_reader", "pass:document_reader:webhook_poster",
            "ci:report_agent:webhook_poster", "send:webhook_poster:shadow_endpoint"
        ],
        "permission_edge_ids": [
            "ci:report_agent:document_reader", "read:document_reader:payroll_report",
            "ci:report_agent:webhook_poster", "send:webhook_poster:shadow_endpoint"
        ],
        "data_flow_edge_ids": [
            "ret:payroll_report:document_reader", "pass:document_reader:webhook_poster"
        ]
    }
    session.run.return_value = [mock_record1, mock_record2]

    findings = detect_paths(driver, scenario="base")
    assert len(findings) == 2
    assert findings[0].destination == "attacker_endpoint"
    assert findings[1].destination == "shadow_endpoint"
    assert "ret:payroll_report:document_reader" in findings[0].data_flow_edge_ids
    assert "ci:report_agent:webhook_poster" in findings[0].permission_edge_ids


def test_detect_paths_unit_with_removed_overlay():
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__.return_value = session

    # When ci:report_agent:webhook_poster is removed, Cypher returns empty list
    session.run.return_value = []

    findings = detect_paths(driver, scenario="base", removed_edge_ids={"ci:report_agent:webhook_poster"})
    assert len(findings) == 0
    # Verify session.run received the removed_edge_ids
    session.run.assert_called_once()
    _, kwargs = session.run.call_args
    assert kwargs["scenario"] == "base"
    assert "ci:report_agent:webhook_poster" in kwargs["removed_edge_ids"]


def test_workflows_unit():
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__.return_value = session

    # Mock return values for W1 and W2
    mock_w1_res = MagicMock()
    mock_w1_res.single.return_value = {"cnt": 1}
    mock_w2_res = MagicMock()
    mock_w2_res.single.return_value = {"cnt": 1}

    session.run.side_effect = [mock_w1_res, mock_w2_res]

    results = check_workflows(driver, scenario="base")
    assert len(results) == 2
    assert results[0].name == "W1" and results[0].passed is True
    assert results[1].name == "W2" and results[1].passed is True


def test_find_fix_evaluation_logic():
    driver = MagicMock()

    # We will simulate behavior of detect_paths and check_workflows across candidate evaluations:
    # Candidates:
    # 1. ci:report_agent:document_reader -> W1 fails
    # 2. read:document_reader:payroll_report -> W1 fails
    # 3. ci:report_agent:webhook_poster -> W1 passes, W2 passes, 0 findings -> ACCEPT
    # 4. send:webhook_poster:attacker_endpoint -> W1 passes, W2 passes, 1 finding remaining (shadow) -> REJECT
    # 5. send:webhook_poster:shadow_endpoint -> W1 passes, W2 passes, 1 finding remaining (attacker) -> REJECT

    def mock_check_workflows(driver, scenario="base", removed_edge_ids=None):
        removed = set(removed_edge_ids or [])
        if "ci:report_agent:document_reader" in removed or "read:document_reader:payroll_report" in removed:
            return [
                WorkflowResult(name="W1", passed=False, reason="W1 broken"),
                WorkflowResult(name="W2", passed=False, reason="W2 broken")
            ]
        return [
            WorkflowResult(name="W1", passed=True, reason="W1 ok"),
            WorkflowResult(name="W2", passed=True, reason="W2 ok")
        ]

    def mock_detect_paths(driver, scenario="base", removed_edge_ids=None):
        removed = set(removed_edge_ids or [])
        if "ci:report_agent:webhook_poster" in removed:
            return []
        findings = []
        if "send:webhook_poster:attacker_endpoint" not in removed:
            findings.append(Finding(
                source="payroll_report", destination="attacker_endpoint",
                path=[], relationship_ids=[], permission_edge_ids=[], data_flow_edge_ids=[]
            ))
        if "send:webhook_poster:shadow_endpoint" not in removed:
            findings.append(Finding(
                source="payroll_report", destination="shadow_endpoint",
                path=[], relationship_ids=[], permission_edge_ids=[], data_flow_edge_ids=[]
            ))
        return findings

    import agentfence.fixer
    original_check = agentfence.fixer.check_workflows
    original_detect = agentfence.fixer.detect_paths
    agentfence.fixer.check_workflows = mock_check_workflows
    agentfence.fixer.detect_paths = mock_detect_paths

    try:
        fix_res = find_fix(driver, scenario="base")

        assert len(fix_res.candidates) == 5
        cands = {c.removed_edge_id: c for c in fix_res.candidates}

        # Check candidate 1
        assert cands["ci:report_agent:document_reader"].decision == "REJECT"
        assert "W1 fails" in cands["ci:report_agent:document_reader"].reason

        # Check candidate 2
        assert cands["read:document_reader:payroll_report"].decision == "REJECT"
        assert "W1 fails" in cands["read:document_reader:payroll_report"].reason

        # Check candidate 3
        assert cands["ci:report_agent:webhook_poster"].decision == "ACCEPT"

        # Check candidate 4
        assert cands["send:webhook_poster:attacker_endpoint"].decision == "REJECT"
        assert "Dangerous findings remain" in cands["send:webhook_poster:attacker_endpoint"].reason

        # Check candidate 5
        assert cands["send:webhook_poster:shadow_endpoint"].decision == "REJECT"
        assert "Dangerous findings remain" in cands["send:webhook_poster:shadow_endpoint"].reason

        # Check overall FixResult
        assert fix_res.accepted == "ci:report_agent:webhook_poster"
        assert len(fix_res.findings_after_fix) == 0
        assert all(w.passed for w in fix_res.workflows_after_fix)
    finally:
        agentfence.fixer.check_workflows = original_check
        agentfence.fixer.detect_paths = original_detect


def test_decisions_persistence_unit():
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__.return_value = session

    # Test save_decision
    res = save_decision(driver, "ci:report_agent:webhook_poster", scenario="base")
    assert res.persisted is True
    assert res.status == "ACTIVE"
    assert res.removed_edge_ids == ["ci:report_agent:webhook_poster"]
    assert session.run.call_count == 1

    # Test get_active_removed_edge_ids
    session.reset_mock()
    session.run.return_value = [
        {"edge_ids": ["ci:report_agent:webhook_poster"]},
        {"edge_ids": "send:some_other_edge"}
    ]
    active_ids = get_active_removed_edge_ids(driver)
    assert active_ids == {"ci:report_agent:webhook_poster", "send:some_other_edge"}
