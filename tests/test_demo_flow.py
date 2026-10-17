"""End-to-End Test for AgentFence Streamlit Demo Flow.

Uses Streamlit's native AppTest framework to simulate the user clicking through:
1. Run Detection -> 2 baseline dangerous paths
2. Run Negative Test -> 0 findings
3. Find Fix -> 5 candidates, 4 rejected, 1 accepted
4. Verify Accepted Fix -> 0 paths remaining, W1 PASS, W2 PASS
5. Save Accepted Decision -> Decision node persisted
6. Reload / Verify Persistence -> Confirmed reloaded from database
"""

import pytest
from streamlit.testing.v1 import AppTest
from agentfence.db import enable_local_mode

enable_local_mode()


class TestStreamlitDemoFlow:
    def test_full_demo_flow_interactive(self):
        """Simulate Person 2 driving the entire demo flow sequentially."""
        at = AppTest.from_file("app.py", default_timeout=30)
        at.run()
        assert not at.exception, f"App raised exception on initial load: {at.exception}"

        # -------------------------------------------------------------
        # Step 1: Baseline Detection
        # -------------------------------------------------------------
        btn_detect = at.button(key="btn_run_detection")
        assert btn_detect is not None
        btn_detect.click().run()
        assert not at.exception, f"Exception after Run Detection: {at.exception}"

        # Check session state
        baseline_res = at.session_state["baseline_result"]
        assert baseline_res is not None
        assert baseline_res["finding_count"] == 2
        assert len(baseline_res["findings"]) == 2

        # -------------------------------------------------------------
        # Step 2: Negative Test
        # -------------------------------------------------------------
        btn_neg = at.button(key="btn_run_neg_test")
        assert btn_neg is not None
        btn_neg.click().run()
        assert not at.exception, f"Exception after Run Negative Test: {at.exception}"

        neg_res = at.session_state["negative_test_result"]
        assert neg_res is not None
        assert neg_res["passed"] is True
        assert "0 findings" in neg_res["display_text"]

        # -------------------------------------------------------------
        # Step 3: Candidate Fix Search
        # -------------------------------------------------------------
        btn_fix = at.button(key="btn_find_fix")
        assert btn_fix is not None
        assert not btn_fix.disabled
        btn_fix.click().run()
        assert not at.exception, f"Exception after Find Fix: {at.exception}"

        c_res = at.session_state["candidate_result"]
        assert c_res is not None
        assert c_res["total_evaluated"] == 5
        assert c_res["accepted_count"] == 1
        assert c_res["rejected_count"] == 4

        # -------------------------------------------------------------
        # Step 4: Post-Fix Verification
        # -------------------------------------------------------------
        btn_verify = at.button(key="btn_verify_fix")
        assert btn_verify is not None
        assert not btn_verify.disabled
        btn_verify.click().run()
        assert not at.exception, f"Exception after Verify Fix: {at.exception}"

        v_res = at.session_state["verification_result"]
        assert v_res is not None
        assert v_res["verified"] is True
        assert v_res["paths_remaining"] == 0
        assert v_res["w1_status"] == "PASS"
        assert v_res["w2_status"] == "PASS"

        # -------------------------------------------------------------
        # Step 5: Save Decision
        # -------------------------------------------------------------
        chk_confirm = at.checkbox(key="chk_confirm_persistence")
        assert chk_confirm is not None
        chk_confirm.check().run()
        assert not at.exception

        btn_save = at.button(key="btn_save_decision")
        assert btn_save is not None
        assert not btn_save.disabled
        btn_save.click().run()
        assert not at.exception, f"Exception after Save Decision: {at.exception}"

        saved = at.session_state["saved_decision"]
        assert saved is not None
        assert saved["decision_id"].startswith("dec-")
        assert saved["status"] == "APPROVED"

        # -------------------------------------------------------------
        # Step 6: Reload / Verify Persistence
        # -------------------------------------------------------------
        btn_reload = at.button(key="btn_reload_decision")
        assert btn_reload is not None
        btn_reload.click().run()
        assert not at.exception, f"Exception after Reload: {at.exception}"

        p_check = at.session_state["persistence_check"]
        assert p_check is not None
        assert p_check["decision_id"] == saved["decision_id"]
        assert p_check["candidate_removed"] == "e06"

    def test_rehearsal_run_two_without_code_edits(self):
        """Second rehearsal run of the full demonstration to guarantee stability."""
        at = AppTest.from_file("app.py", default_timeout=30)
        at.run()
        assert not at.exception

        # Detection
        at.button(key="btn_run_detection").click().run()
        assert at.session_state["baseline_result"]["finding_count"] == 2

        # Negative test
        at.button(key="btn_run_neg_test").click().run()
        assert at.session_state["negative_test_result"]["passed"] is True

        # Fix Search
        at.button(key="btn_find_fix").click().run()
        assert at.session_state["candidate_result"]["accepted_count"] == 1
        assert at.session_state["candidate_result"]["rejected_count"] == 4

        # Verification
        at.button(key="btn_verify_fix").click().run()
        assert at.session_state["verification_result"]["verified"] is True

        # Persistence
        at.checkbox(key="chk_confirm_persistence").check().run()
        at.button(key="btn_save_decision").click().run()
        assert at.session_state["saved_decision"] is not None

        # Reload
        at.button(key="btn_reload_decision").click().run()
        assert at.session_state["persistence_check"] is not None

    def test_candidate_simulation_switching(self):
        """Test switching candidates in the simulator UI between e04 and e06."""
        at = AppTest.from_file("app.py", default_timeout=30)
        at.run()
        assert not at.exception

        # Select e04 (index 1)
        sel = at.selectbox(key="select_candidate_simulator")
        assert sel is not None
        sel.select_index(1).run()
        assert not at.exception
        v_res = at.session_state["verification_result"]
        assert v_res["verified"] is False
        assert v_res["w2_status"] == "FAIL"

        # Switch back to e06 (index 0)
        sel.select_index(0).run()
        assert not at.exception
        v_res2 = at.session_state["verification_result"]
        assert v_res2["verified"] is True
        assert v_res2["paths_remaining"] == 0
        assert v_res2["w1_status"] == "PASS"
        assert v_res2["w2_status"] == "PASS"

