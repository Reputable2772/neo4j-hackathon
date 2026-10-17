"""Tests for scenario comparison module."""

import pytest
from agentfence.db import enable_local_mode

enable_local_mode()

from agentfence.detector import detect_data_flow_paths
from agentfence.scenarios import compare_scenarios
from agentfence.fixer import find_fixes


class TestScenarioComparisons:
    """Tests matching Section 8 of the specification."""

    def test_baseline_finding_count(self):
        """Baseline must have exactly 2 findings."""
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        assert len(findings) == 2

    def test_updated_finding_count(self):
        """Updated scenario must have exactly 4 findings."""
        findings = detect_data_flow_paths(scenario="updated", removed=[])
        assert len(findings) == 4

    def test_compare_scenarios_counts(self):
        """compare_scenarios must report counts for both scenarios accurately."""
        comp = compare_scenarios()
        assert comp["baseline_count"] == 2
        assert comp["updated_count"] == 4
        assert len(comp["new_in_updated"]) == 2

    def test_new_findings_route(self):
        """The two additional findings in updated go through Summarize -> ReportTool -> ExternalEmail."""
        comp = compare_scenarios()
        new_findings = comp["new_in_updated"]
        assert len(new_findings) == 2

        for f in new_findings:
            assert f["agent"] == "SupportAgent"
            assert f["destination"] == "ExternalEmail"
            assert "ReportTool" in f["tool_chain"]
            assert f["tool_chain"][-2:] == ["ReportTool", "ExternalEmail"] or f["tool_chain"] == ["ReadCustomers", "Summarize", "ReportTool"] or f["tool_chain"] == ["Summarize", "ReportTool"]

        sources = {f["source"] for f in new_findings}
        assert sources == {"CustomerDB", "InboundInbox"}

    def test_remove_e17_in_updated_leaves_two_findings(self):
        """Removing e17 alone in updated scenario leaves exactly two findings."""
        findings = detect_data_flow_paths(scenario="updated", removed=["e17"])
        assert len(findings) == 2
        # The remaining 2 must be the ones going through ReportTool (e30)
        for f in findings:
            assert "ReportTool" in f["tool_chain"]

    def test_updated_fixes_evaluated_independently(self):
        """Updated fixes are evaluated independently of baseline fixes."""
        base_fixes = find_fixes(scenario="baseline")
        updated_fixes = find_fixes(scenario="updated")

        # Baseline fixes are single-edge
        for f in base_fixes["fixes"]:
            assert len(f["removed"]) == 1

        # Updated fixes are pairs: [e06, e30], [e17, e30], [e18, e30]
        for f in updated_fixes["fixes"]:
            assert len(f["removed"]) == 2

        pair_sets = [set(f["removed"]) for f in updated_fixes["fixes"]]
        assert {"e06", "e30"} in pair_sets
        assert {"e17", "e30"} in pair_sets
        assert {"e18", "e30"} in pair_sets

    def test_baseline_storage_remains_unchanged(self):
        """Baseline findings remain unchanged after evaluating updated and running simulations."""
        findings_before = detect_data_flow_paths(scenario="baseline", removed=[])
        _ = compare_scenarios()
        _ = find_fixes(scenario="updated")
        findings_after = detect_data_flow_paths(scenario="baseline", removed=[])

        assert len(findings_before) == len(findings_after) == 2
        assert findings_before == findings_after
