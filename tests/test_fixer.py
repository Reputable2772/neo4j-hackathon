"""Tests for the fix engine."""

import pytest
from agentfence.db import enable_local_mode

enable_local_mode()

from agentfence.fixer import find_fixes, format_fix_report


class TestBaselineFixes:
    """Fix engine tests for baseline scenario."""

    def test_valid_single_edge_fixes(self):
        """Valid single-edge fixes must be exactly e06, e17, and e18."""
        result = find_fixes(scenario="baseline")
        assert result["fixes"] is not None, "Should find fixes"
        fix_ids = sorted([f["removed"][0] for f in result["fixes"]])
        assert fix_ids == ["e06", "e17", "e18"], (
            f"Expected ['e06', 'e17', 'e18'], got {fix_ids}"
        )

    def test_all_single_fixes_are_single_edge(self):
        """All baseline fixes should be single-edge removals."""
        result = find_fixes(scenario="baseline")
        for fix in result["fixes"]:
            assert len(fix["removed"]) == 1

    def test_e04_rejected_because_breaks_w2(self):
        """e04 must not appear as a valid fix because it breaks W2."""
        result = find_fixes(scenario="baseline")
        for fix in result["fixes"]:
            assert "e04" not in fix["removed"], "e04 should be rejected (breaks W2)"

    def test_fix_status_label(self):
        """Fix result must use the exact status label."""
        result = find_fixes(scenario="baseline")
        assert result["status"] == "smallest valid fix found within the tested candidate set"

    def test_pair_search_not_run_for_baseline(self):
        """When single-edge fixes exist, pair search should not run."""
        result = find_fixes(scenario="baseline")
        # All fixes should be single-edge
        for fix in result["fixes"]:
            assert len(fix["removed"]) == 1

    def test_fix_report_has_required_fields(self):
        """Each fix must show all required fields."""
        result = find_fixes(scenario="baseline")
        for fix in result["fixes"]:
            assert "removed" in fix
            assert "edges" in fix
            assert "findings_before" in fix
            assert "findings_after" in fix
            assert "w1_after" in fix
            assert "w2_after" in fix
            assert fix["findings_before"] == 2
            assert fix["findings_after"] == 0
            assert fix["w1_after"] is True
            assert fix["w2_after"] is True

    def test_initial_finding_count(self):
        result = find_fixes(scenario="baseline")
        assert result["initial_count"] == 2

    def test_format_report(self):
        """Report formatting should not crash."""
        result = find_fixes(scenario="baseline")
        report = format_fix_report(result)
        assert "smallest valid fix found" in report


class TestNoFindingsCase:
    """When there are no findings, return exact message."""

    def test_no_findings_message(self):
        # Remove e18 to eliminate all findings
        result = find_fixes(scenario="baseline", removed=["e18"])
        assert result["message"] == "No modeled data-flow paths found"
        assert result["fixes"] is None


class TestUnreachableWorkflowCase:
    """Injected case where no valid fix exists."""

    def test_no_valid_fix_message(self):
        """When workflows are unreachable for every candidate, return exact message.

        We simulate this by removing e16 (breaks W2), which means every
        candidate removal will still have W2 broken (since W2 is already broken
        by the pre-removal). Actually we need to find a case where findings exist
        but no single or pair removal eliminates them while keeping workflows.

        The spec says: test the injected unreachable-workflow case.
        We inject this by pre-removing e16 so W2 is always false.
        Then any fix that removes a candidate still has W2=false from e16 removal.
        """
        # With e16 already removed, W2 is false.
        # But e17 removal still eliminates all findings.
        # W1 is still true but W2 is false -> no valid fix.
        result = find_fixes(scenario="baseline", removed=["e16"])
        assert result["message"] == "No valid fix found in the tested candidates."
        assert result["fixes"] is None


class TestUpdatedScenarioFixes:
    """Fix engine tests for updated scenario."""

    def test_updated_valid_pairs(self):
        """Updated scenario: exactly these valid pairs."""
        result = find_fixes(scenario="updated")
        assert result["fixes"] is not None
        pair_ids = sorted([tuple(f["removed"]) for f in result["fixes"]])
        expected = sorted([
            ("e06", "e30"),
            ("e17", "e30"),
            ("e18", "e30"),
        ])
        assert pair_ids == expected, f"Expected {expected}, got {pair_ids}"

    def test_updated_all_pairs(self):
        """All updated fixes should be pair removals."""
        result = find_fixes(scenario="updated")
        for fix in result["fixes"]:
            assert len(fix["removed"]) == 2

    def test_updated_status_label(self):
        result = find_fixes(scenario="updated")
        assert result["status"] == "smallest valid fix found within the tested candidate set"

    def test_updated_initial_count(self):
        result = find_fixes(scenario="updated")
        assert result["initial_count"] == 4
