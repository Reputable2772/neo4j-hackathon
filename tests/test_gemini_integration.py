import pytest
from unittest.mock import MagicMock, patch

from agentfence.validator import validate_cypher_query
from agentfence.contracts import Finding, CandidateResult, WorkflowResult
from agentfence.explainer import explain_findings
from agentfence.ai_detector import detect_paths_with_gemini, SUGGESTED_SAFE_CYPHER


def test_validator_safe_queries():
    # Valid read-only bounded query
    q = "MATCH (a:Agent)-[r:CAN_INVOKE]->(t:Tool) RETURN a, r, t LIMIT 25"
    valid, reason = validate_cypher_query(q)
    assert valid is True

    # Valid optional match
    q2 = "OPTIONAL MATCH (n) RETURN n"
    valid, reason = validate_cypher_query(q2)
    assert valid is True


def test_validator_rejects_unsafe_queries():
    # Rejects CREATE
    q = "MATCH (n) CREATE (m:BadNode) RETURN m"
    valid, reason = validate_cypher_query(q)
    assert valid is False
    assert "CREATE" in reason

    # Rejects DELETE / DETACH
    q = "MATCH (n) DETACH DELETE n"
    valid, reason = validate_cypher_query(q)
    assert valid is False

    # Rejects CALL procedure
    q = "CALL dbms.components() YIELD name RETURN name"
    valid, reason = validate_cypher_query(q)
    assert valid is False

    # Rejects non-MATCH starts
    q = "RETURN 1"
    valid, reason = validate_cypher_query(q)
    assert valid is False

    # Rejects multi-statements
    q = "MATCH (n) RETURN n; MATCH (m) RETURN m"
    valid, reason = validate_cypher_query(q)
    assert valid is False


def test_explainer_fallback_and_structure():
    findings = [
        Finding(
            source="payroll_report",
            destination="attacker_endpoint",
            path=["payroll_report", "document_reader", "webhook_poster", "attacker_endpoint"],
            relationship_ids=["ci:report_agent:document_reader"],
            permission_edge_ids=["ci:report_agent:document_reader"],
            data_flow_edge_ids=["ret:payroll_report:document_reader"]
        )
    ]
    candidates = [
        CandidateResult(
            removed_edge_id="ci:report_agent:webhook_poster",
            decision="ACCEPT",
            reason="ACCEPT: All dangerous routes eliminated",
            remaining_findings=[],
            workflows=[WorkflowResult(name="W1", passed=True, reason="ok")]
        ),
        CandidateResult(
            removed_edge_id="ci:report_agent:document_reader",
            decision="REJECT",
            reason="REJECT: W1 fails",
            remaining_findings=[],
            workflows=[WorkflowResult(name="W1", passed=False, reason="broken")]
        )
    ]
    workflows = [
        WorkflowResult(name="W1", passed=True, reason="W1 passed"),
        WorkflowResult(name="W2", passed=True, reason="W2 passed")
    ]

    # Test fallback explanation when Gemini is not used or unavailable
    exp = explain_findings(findings, candidates, workflows, use_ai=False)
    assert exp.source == "FALLBACK_ANALYST"
    assert "HIGH RISK" in exp.risk_summary
    assert "ci:report_agent:webhook_poster" in exp.accepted_fix_explanation
    assert len(exp.rejected_candidates_explanation) == 1
    assert exp.rejected_candidates_explanation[0]["candidate_id"] == "ci:report_agent:document_reader"


def test_explainer_with_mock_gemini_text():
    findings = []
    candidates = []
    workflows = []
    exp = explain_findings(findings, candidates, workflows, mock_llm_text="Executive summary from Gemini AI.")
    assert exp.source == "GEMINI_AI"
    assert "Executive summary from Gemini AI" in exp.risk_summary


def test_ai_detector_mock_flow():
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__.return_value = session

    # Mock query execution record
    mock_record = {
        "source": "payroll_report",
        "destination": "attacker_endpoint",
        "path": ["payroll_report", "document_reader", "webhook_poster", "attacker_endpoint"],
        "relationship_ids": ["ci:1", "r:1"],
        "permission_edge_ids": ["ci:1"],
        "data_flow_edge_ids": ["r:1"],
    }
    session.run.return_value = [mock_record]

    mock_model_cypher = (
        "Here is the query:\n```cypher\n"
        "MATCH (a:Agent {scenario: $scenario})-[ci:CAN_INVOKE]->(t:Tool) RETURN 'payroll_report' AS source, 'attacker_endpoint' AS destination, ['payroll_report', 'attacker_endpoint'] AS path, ['ci:1'] AS relationship_ids, ['ci:1'] AS permission_edge_ids, [] AS data_flow_edge_ids\n"
        "```"
    )

    res = detect_paths_with_gemini(driver, scenario="base", mock_response=mock_model_cypher)
    assert res.status == "SUCCESS"
    assert len(res.findings) == 1
    assert res.findings[0].is_validated is True
    assert res.findings[0].source == "payroll_report"


def test_ai_detector_handles_rejected_query():
    driver = MagicMock()
    mock_bad_cypher = "```cypher\nMATCH (n) CREATE (m:Injected) RETURN m\n```"
    res = detect_paths_with_gemini(driver, scenario="base", mock_response=mock_bad_cypher)
    assert res.status == "REJECTED_QUERY"
    assert len(res.findings) == 0
    assert "failed security validation" in res.error


def test_ai_detector_handles_api_failure_gracefully():
    driver = MagicMock()
    # Force API failure when no key is set and no mock response provided
    with patch("agentfence.ai_detector.get_gemini_client", side_effect=ValueError("No API key")):
        res = detect_paths_with_gemini(driver, scenario="base")
        assert res.status == "ERROR"
        assert "unavailable" in res.error or "No API key" in res.error
        assert len(res.findings) == 0
