"""Tests for the workflows module — validation gate G3 and workflow cases."""

import pytest
from agentfence.db import enable_local_mode

# Force local mode for testing without Neo4j
enable_local_mode()

from agentfence.workflows import check_w1, check_w2, check_all_workflows
from agentfence.detector import detect_data_flow_paths


class TestWorkflowsNoRemovals:
    """No removals: W1 and W2 are both true."""

    def test_w1_true_baseline(self):
        assert check_w1(scenario="baseline", removed=[]) is True

    def test_w2_true_baseline(self):
        assert check_w2(scenario="baseline", removed=[]) is True


class TestWorkflowRemovals:
    """Individual workflow removal tests."""

    def test_remove_e03_w1_false(self):
        """Removing e03 breaks W1."""
        assert check_w1(scenario="baseline", removed=["e03"]) is False

    def test_remove_e03_w2_true(self):
        """Removing e03 does not affect W2."""
        assert check_w2(scenario="baseline", removed=["e03"]) is True

    def test_remove_e16_w2_false(self):
        """Removing e16 breaks W2."""
        assert check_w2(scenario="baseline", removed=["e16"]) is False

    def test_remove_e16_w1_true(self):
        """Removing e16 does not affect W1."""
        assert check_w1(scenario="baseline", removed=["e16"]) is True

    def test_remove_e04_w2_false(self):
        """Removing e04 breaks W2."""
        assert check_w2(scenario="baseline", removed=["e04"]) is False


class TestG3FixAndWorkflowVerification:
    """G3: Combined detection + workflow checks with removals."""

    def test_remove_e17_zero_findings(self):
        """Removing e17 in baseline → zero findings."""
        findings = detect_data_flow_paths(scenario="baseline", removed=["e17"])
        assert len(findings) == 0, f"Expected 0 findings, got {len(findings)}"

    def test_remove_e17_w1_true(self):
        """Removing e17 → W1 remains true."""
        assert check_w1(scenario="baseline", removed=["e17"]) is True

    def test_remove_e17_w2_true(self):
        """Removing e17 → W2 remains true."""
        assert check_w2(scenario="baseline", removed=["e17"]) is True

    def test_remove_e04_zero_findings(self):
        """Removing e04 in baseline → zero findings."""
        findings = detect_data_flow_paths(scenario="baseline", removed=["e04"])
        assert len(findings) == 0, f"Expected 0 findings, got {len(findings)}"

    def test_remove_e04_w2_false_so_not_valid_fix(self):
        """Removing e04 breaks W2, so it cannot be accepted as a valid fix."""
        assert check_w2(scenario="baseline", removed=["e04"]) is False
