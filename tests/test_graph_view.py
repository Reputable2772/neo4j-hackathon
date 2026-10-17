"""Unit tests for AgentFence Interactive Graph Visualization."""

import pytest
from agentfence.db import get_local_graph
from agentfence.detector import detect_data_flow_paths
from agentfence.graph_view import render_graph_html, get_graph_relationships


class TestGraphView:
    def test_get_graph_relationships_baseline(self):
        rels = get_graph_relationships("baseline")
        assert len(rels) == 18
        ids = {r["id"] for r in rels}
        assert "e01" in ids
        assert "e17" in ids
        assert "e30" not in ids  # e30 only in updated

    def test_get_graph_relationships_updated(self):
        rels = get_graph_relationships("updated")
        assert len(rels) == 19
        ids = {r["id"] for r in rels}
        assert "e30" in ids

    def test_render_architecture_baseline_default(self):
        findings = detect_data_flow_paths("baseline")
        html = render_graph_html(
            scenario="baseline",
            removed=[],
            findings=findings,
            view_mode="architecture",
        )
        assert "<svg" in html
        assert "SupportAgent" in html
        assert "CustomerDB" in html
        assert "EmailSender" in html
        assert "ExternalEmail" in html
        assert "edge-danger" in html
        assert "Legend:" in html

    def test_render_threat_mode(self):
        findings = detect_data_flow_paths("baseline")
        html = render_graph_html(
            scenario="baseline",
            removed=[],
            findings=findings,
            view_mode="threat",
        )
        assert "threat-container" in html
        assert "SupportAgent" in html
        assert "CustomerDB" in html
        assert "InboundInbox" in html
        assert "Summarize" in html
        assert "ExternalEmail" in html

    def test_simulated_removals_reflected(self):
        findings = detect_data_flow_paths("baseline", removed=["e17"])
        html = render_graph_html(
            scenario="baseline",
            removed=["e17"],
            findings=findings,
            view_mode="architecture",
        )
        assert "[SEVERED]" in html
        assert "e17" in html

    def test_fix_preview_does_not_mutate_graph(self):
        graph_before = get_local_graph()
        rels_before_count = len(graph_before["relationships"])

        findings = detect_data_flow_paths("baseline")
        html = render_graph_html(
            scenario="baseline",
            removed=[],
            findings=findings,
            fix_preview_edges=["e17"],
            view_mode="architecture",
        )
        # Should render e17 as severed in preview
        assert "e17 [SEVERED]" in html

        graph_after = get_local_graph()
        rels_after_count = len(graph_after["relationships"])
        assert rels_before_count == rels_after_count == 19
        assert "e17" in [r["id"] for r in graph_after["relationships"]]

    def test_highlight_specific_finding(self):
        findings = detect_data_flow_paths("baseline")
        html = render_graph_html(
            scenario="baseline",
            removed=[],
            findings=findings,
            selected_finding_idx=0,
            view_mode="architecture",
        )
        assert "<svg" in html
        assert "edge-danger" in html
