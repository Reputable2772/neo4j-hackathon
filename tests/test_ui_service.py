"""Tests for UI Service Adapter integrating Person 1's backend."""

import pytest
from agentfence.db import enable_local_mode

enable_local_mode()

from agentfence.ui_service import (
    get_system_status,
    run_baseline_detection,
    run_negative_test,
    evaluate_permission_candidates,
    verify_fix,
    persist_accepted_decision,
    reload_persisted_decision,
    fetch_decision_history,
)


class TestUIService:
    def test_get_system_status_in_local_mode(self):
        status = get_system_status()
        assert status["is_fixture"] is True
        assert status["mode"] == "local"
        assert status["connected"] is False  # Never claim green in local mode

    def test_run_baseline_detection(self):
        res = run_baseline_detection("base")
        assert res["finding_count"] == 2
        assert len(res["findings"]) == 2
        destinations = {f["destination"] for f in res["findings"]}
        assert destinations == {"attacker_endpoint", "shadow_endpoint"}
        sources = {f["source"] for f in res["findings"]}
        assert sources == {"payroll_report"}

    def test_run_negative_test(self):
        res = run_negative_test("negative")
        assert res["passed"] is True
        assert res["status"] == "PASS"
        assert res["finding_count"] == 0
        assert "0 findings" in res["display_text"]

    def test_evaluate_permission_candidates_5_4_1(self):
        res = evaluate_permission_candidates("base")
        assert res["total_evaluated"] == 5
        assert res["accepted_count"] == 1
        assert res["rejected_count"] == 4

        # Verify ci:report_agent:webhook_poster is the accepted candidate
        accepted = [c for c in res["candidates"] if c["decision"] == "ACCEPT"]
        assert len(accepted) == 1
        assert accepted[0]["edge_id"] == "ci:report_agent:webhook_poster"
        assert accepted[0]["tool"] == "webhook_poster"
        assert accepted[0]["paths_remaining"] == 0
        assert accepted[0]["w1_status"] == "PASS"
        assert accepted[0]["w2_status"] == "PASS"

        # Verify candidate 1 is rejected because it breaks W1
        c1 = [c for c in res["candidates"] if c["edge_id"] == "ci:report_agent:document_reader"][0]
        assert c1["decision"] == "REJECT"
        assert "W1 fails" in c1["reason"]

    def test_verify_fix_success(self):
        v = verify_fix(["ci:report_agent:webhook_poster"], scenario="base")
        assert v["verified"] is True
        assert v["paths_remaining"] == 0
        assert v["w1_status"] == "PASS"
        assert v["w2_status"] == "PASS"

    def test_verify_fix_failure(self):
        v = verify_fix(["ci:report_agent:document_reader"], scenario="base")
        assert v["verified"] is False
        assert v["w1_status"] == "FAIL"

    def test_persist_and_reload_decision(self):
        cand = "ci:report_agent:webhook_poster"
        dec = persist_accepted_decision(
            candidate_removed=[cand],
            candidate_edges=[{"id": cand, "type": "CAN_INVOKE", "from": "report_agent", "to": "webhook_poster"}],
            findings_before=2,
            findings_after=0,
            w1_ok=True,
            w2_ok=True,
            scenario="base",
            rationale="Automated remediation removing ci:report_agent:webhook_poster",
            status="APPROVED",
        )
        assert dec.decision_id is not None
        assert dec.status == "APPROVED"

        # Reload
        reloaded = reload_persisted_decision(dec.decision_id)
        assert reloaded is not None
        assert reloaded["decision_id"] == dec.decision_id
        assert reloaded["candidate_removed"] == cand

        # History list
        history = fetch_decision_history(limit=5)
        assert len(history) > 0
        assert any(d["decision_id"] == dec.decision_id for d in history)

    def test_refuse_unverified_persistence(self):
        with pytest.raises(ValueError, match="Cannot persist an unverified decision"):
            persist_accepted_decision(
                candidate_removed=["ci:report_agent:document_reader"],
                candidate_edges=[],
                findings_before=2,
                findings_after=0,
                w1_ok=False,  # Broken W1
                w2_ok=True,
                scenario="base",
            )
