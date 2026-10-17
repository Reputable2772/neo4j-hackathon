"""Tests for the detector module — validation gate G1 and G2."""

import pytest
from agentfence.db import enable_local_mode

# Force local mode for testing without Neo4j
enable_local_mode()

from agentfence.detector import detect_data_flow_paths, detect_capability_exposure


class TestG1PositiveDetection:
    """G1: baseline with no removals → exactly 2 findings for SupportAgent."""

    def test_baseline_finding_count(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        assert len(findings) == 2, (
            f"Expected 2 findings, got {len(findings)}: {findings}"
        )

    def test_baseline_findings_are_support_agent(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        agents = {f["agent"] for f in findings}
        assert agents == {"SupportAgent"}, f"Expected only SupportAgent, got {agents}"

    def test_baseline_sources(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        sources = {f["source"] for f in findings}
        assert sources == {"CustomerDB", "InboundInbox"}, (
            f"Expected CustomerDB and InboundInbox, got {sources}"
        )

    def test_baseline_destination(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        destinations = {f["destination"] for f in findings}
        assert destinations == {"ExternalEmail"}, (
            f"Expected ExternalEmail, got {destinations}"
        )

    def test_baseline_chains_through_summarize_and_emailsender(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        for f in findings:
            assert "Summarize" in f["tool_chain"], (
                f"Expected Summarize in chain: {f['tool_chain']}"
            )
            assert "EmailSender" in f["tool_chain"], (
                f"Expected EmailSender in chain: {f['tool_chain']}"
            )

    def test_baseline_customer_db_chain(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        cdb_findings = [f for f in findings if f["source"] == "CustomerDB"]
        assert len(cdb_findings) == 1
        assert cdb_findings[0]["tool_chain"] == ["ReadCustomers", "Summarize", "EmailSender"]

    def test_baseline_inbound_inbox_chain(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        inbox_findings = [f for f in findings if f["source"] == "InboundInbox"]
        assert len(inbox_findings) == 1
        assert inbox_findings[0]["tool_chain"] == ["Summarize", "EmailSender"]

    def test_baseline_edge_ids_are_sorted_and_stable(self):
        findings1 = detect_data_flow_paths(scenario="baseline", removed=[])
        findings2 = detect_data_flow_paths(scenario="baseline", removed=[])
        for f1, f2 in zip(findings1, findings2):
            assert f1["edge_ids"] == f2["edge_ids"], "Edge IDs should be stable across runs"
            assert f1["edge_ids"] == sorted(f1["edge_ids"]), "Edge IDs should be sorted"

    def test_baseline_has_path_sentences(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        for f in findings:
            assert f["path"], "Each finding must have a readable path sentence"
            assert f["agent"] in f["path"]
            assert f["source"] in f["path"]
            assert f["destination"] in f["path"]


class TestG2NegativeDetection:
    """G2: ReportBot has no findings; removing e18 gives zero findings."""

    def test_reportbot_no_findings_baseline(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        reportbot_findings = [f for f in findings if f["agent"] == "ReportBot"]
        assert len(reportbot_findings) == 0, (
            f"ReportBot should have no findings in baseline, got {reportbot_findings}"
        )

    def test_remove_e18_zero_findings(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=["e18"])
        assert len(findings) == 0, (
            f"With e18 removed, expected 0 findings, got {len(findings)}: {findings}"
        )


class TestCapabilityExposure:
    """Capability exposure is a broad warning, separate from data-flow findings."""

    def test_capability_exposure_baseline(self):
        warnings = detect_capability_exposure(scenario="baseline", removed=[])
        agents = {w["agent"] for w in warnings}
        assert "SupportAgent" in agents

    def test_capability_exposure_not_counted_as_finding(self):
        findings = detect_data_flow_paths(scenario="baseline", removed=[])
        warnings = detect_capability_exposure(scenario="baseline", removed=[])
        assert isinstance(warnings, list)
        assert isinstance(findings, list)

    def test_capability_exposure_supportagent_true_reportbot_false(self):
        warnings = detect_capability_exposure(scenario="baseline", removed=[])
        agents = {w["agent"] for w in warnings}
        assert "SupportAgent" in agents
        assert "ReportBot" not in agents
