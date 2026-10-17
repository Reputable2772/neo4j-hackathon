"""Interactive Workflow Graph Visualization for AgentFence.

Renders cinematic, high-fidelity SVG diagrams matching the futuristic cyber design concept:
- Glowing circular cyber nodes for Agents, Tools, Resources, and External Destinations
- Directional neon relationship paths: CAN_INVOKE, READS, PASSES_DATA_TO, SENDS_TO
- Modeled dangerous exfiltration paths highlighted in pulsating red
- Active vs severed (simulated removal) relationship styling with [SEVERED] overlays
- Floating translucent glass card for Selected Path inspection
- Multiple view modes: Full Architecture Graph and Focused Threat Route Diagram
"""

from agentfence.db import get_local_graph, is_local_mode, run_query


def get_graph_relationships(scenario):
    """Fetch active relationships for a scenario from Neo4j if connected, else local graph."""
    if not is_local_mode():
        try:
            cypher = """
            MATCH (s)-[r]->(t)
            WHERE $scenario IN r.scenarios
            RETURN r.id AS id, type(r) AS type, s.name AS from, t.name AS to, r.scenarios AS scenarios
            """
            rels = run_query(cypher, {"scenario": scenario})
            if rels:
                return rels
        except Exception:
            pass
    graph = get_local_graph()
    return [r for r in graph["relationships"] if scenario in r["scenarios"]]


def render_graph_html(
    scenario="baseline",
    removed=None,
    findings=None,
    selected_finding_idx=None,
    fix_preview_edges=None,
    view_mode="architecture",
    show_removed=True,
):
    """Build a complete, standalone HTML/SVG interactive visualization."""
    if removed is None:
        removed = []
    if findings is None:
        findings = []
    if fix_preview_edges is None:
        fix_preview_edges = []

    # Effective removals include pre-existing removals plus any fix preview removals
    effective_removed = set(removed) | set(fix_preview_edges)

    active_scenario_rels = get_graph_relationships(scenario)

    # Collect dangerous edge IDs
    dangerous_edge_ids = set()
    if selected_finding_idx is not None and 0 <= selected_finding_idx < len(findings):
        dangerous_edge_ids = set(findings[selected_finding_idx]["edge_ids"])
    else:
        for f in findings:
            dangerous_edge_ids.update(f["edge_ids"])

    # If fix preview is active, dangerous edges are recalculated after fix
    if fix_preview_edges:
        from agentfence.detector import detect_data_flow_paths
        preview_findings = detect_data_flow_paths(scenario=scenario, removed=list(effective_removed))
        dangerous_edge_ids = set()
        for pf in preview_findings:
            dangerous_edge_ids.update(pf["edge_ids"])

    if view_mode == "threat":
        return _render_threat_view_html(
            scenario=scenario,
            removed=effective_removed,
            dangerous_edge_ids=dangerous_edge_ids,
            findings=findings,
            selected_finding_idx=selected_finding_idx,
            fix_preview_edges=fix_preview_edges,
        )
    else:
        return _render_architecture_view_html(
            scenario=scenario,
            rels=active_scenario_rels,
            removed=effective_removed,
            dangerous_edge_ids=dangerous_edge_ids,
            findings=findings,
            selected_finding_idx=selected_finding_idx,
            fix_preview_edges=fix_preview_edges,
            show_removed=show_removed,
        )


def _render_threat_view_html(
    scenario,
    removed,
    dangerous_edge_ids,
    findings,
    selected_finding_idx,
    fix_preview_edges,
):
    """Render the vertical flow-chart Threat Route Diagram matching the reference screenshot."""
    e11_severed = "e11" in removed
    e12_severed = "e12" in removed
    e13_severed = "e13" in removed
    e17_severed = "e17" in removed
    e18_severed = "e18" in removed
    e16_severed = "e16" in removed
    e30_severed = "e30" in removed
    e04_severed = "e04" in removed
    e06_severed = "e06" in removed

    cust_route_broken = e11_severed or e13_severed or e17_severed or e18_severed or e04_severed or e06_severed
    inbox_route_broken = e12_severed or e17_severed or e18_severed or e04_severed or e06_severed

    passes_edge_color = "#64748b" if (cust_route_broken and inbox_route_broken) else "#ef4444"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
    <style>
        body {{
            background: #060913;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 10px;
            display: flex;
            justify-content: center;
        }}
        .threat-container {{
            width: 100%;
            max-width: 780px;
            background: #090e1a;
            border: 1px solid #1e293b;
            border-radius: 10px;
            padding: 24px;
            box-sizing: border-box;
            box-shadow: 0 0 30px rgba(0, 0, 0, 0.7);
        }}
        .t-node {{
            border-radius: 8px;
            padding: 12px 16px;
            text-align: center;
            box-sizing: border-box;
        }}
        .t-agent {{
            background: radial-gradient(circle at center, #1e3a8a 0%, #0f172a 100%);
            border: 2px solid #38bdf8;
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
            font-weight: 700;
            font-size: 1.1rem;
            color: #ffffff;
            width: 260px;
            margin: 0 auto;
        }}
        .row-split {{
            display: flex;
            gap: 16px;
            margin: 12px 0;
            justify-content: center;
        }}
        .t-resource-cust {{
            flex: 1;
            background: #1a0f14;
            border: 1px solid #ef4444;
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.25);
        }}
        .t-resource-inbox {{
            flex: 1;
            background: #1c140d;
            border: 1px solid #f59e0b;
            box-shadow: 0 0 10px rgba(245, 158, 11, 0.25);
        }}
        .t-tool {{
            flex: 1;
            background: #0f172a;
            border: 1px solid #334155;
        }}
        .t-tool-wide {{
            background: #0f172a;
            border: 1px solid #334155;
            width: 70%;
            margin: 0 auto;
        }}
        .t-dest {{
            background: #1a080c;
            border: 2px solid #ef4444;
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.4);
            width: 70%;
            margin: 0 auto;
        }}
        .t-label-title {{
            font-weight: 700;
            font-size: 0.95rem;
            color: #ffffff;
        }}
        .t-label-sub-red {{
            font-size: 0.75rem;
            color: #f87171;
            font-weight: 600;
        }}
        .t-label-sub-purple {{
            font-size: 0.75rem;
            color: #fbbf24;
            font-weight: 600;
        }}
        .t-label-sub-orange {{
            font-size: 0.75rem;
            color: #fca5a5;
        }}
        .t-arrow-section {{
            text-align: center;
            font-size: 0.8rem;
            font-weight: 600;
            display: flex;
            flex-direction: column;
            align-items: center;
            margin: 8px 0;
        }}
        .t-arrow-char {{
            font-size: 1.2rem;
            line-height: 1;
        }}
        .chip {{
            display: inline-block;
            padding: 1px 6px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-family: monospace;
            margin: 2px 0;
        }}
        .chip-active {{
            background: #7f1d1d;
            color: #fca5a5;
            border: 1px solid #ef4444;
        }}
        .chip-severed {{
            background: #1e293b;
            color: #ef4444;
            border: 1px solid #ef4444;
            text-decoration: line-through;
        }}
    </style>
    </head>
    <body>
    <div class="threat-container">
        <!-- Agent Node -->
        <div class="t-node t-agent">
            🤖 SupportAgent
        </div>

        <div class="t-arrow-section" style="color: #38bdf8;">
            <span class="t-arrow-char">↓</span>
            CAN_INVOKE
        </div>

        <!-- Resources Row -->
        <div class="row-split">
            <div class="t-node t-resource-cust">
                <div style="font-size: 1.2rem;">🗄️</div>
                <div class="t-label-title">CustomerDB</div>
                <div class="t-label-sub-red">Private data</div>
            </div>
            <div class="t-node t-resource-inbox">
                <div style="font-size: 1.2rem;">✉️</div>
                <div class="t-label-title">InboundInbox</div>
                <div class="t-label-sub-purple">Untrusted content</div>
            </div>
        </div>

        <div class="row-split" style="margin: 6px auto;">
            <div style="flex: 1; text-align: center; color: {'#94a3b8' if e11_severed else '#ef4444'}; font-size: 0.74rem; font-weight: 600;">
                <span class="t-arrow-char">↓</span>
                READS <span class="chip {'chip-severed' if e11_severed else 'chip-active'}">e11</span>
            </div>
            <div style="flex: 1; text-align: center; color: {'#94a3b8' if e12_severed else '#f59e0b'}; font-size: 0.74rem; font-weight: 600;">
                <span class="t-arrow-char">↓</span>
                READS <span class="chip {'chip-severed' if e12_severed else 'chip-active'}">e12</span>
            </div>
        </div>

        <!-- Ingestion Tools Row -->
        <div class="row-split">
            <div class="t-node t-tool" style="border-color: {'#ef4444' if not cust_route_broken else '#334155'};">
                <div class="t-label-title">⚙️ ReadCustomers</div>
            </div>
            <div class="t-node t-tool" style="border-color: {'#f59e0b' if not inbox_route_broken else '#334155'};">
                <div class="t-label-title">📥 ReadInbox (Summarize)</div>
            </div>
        </div>

        <div class="t-arrow-section" style="color: {passes_edge_color}; margin: 12px 0 6px 0;">
            PASSES_DATA_TO · modeled risky routes 
            <span class="chip {'chip-severed' if e13_severed else 'chip-active'}">e13</span>
            <span class="t-arrow-char" style="margin-top: 3px;">↓</span>
        </div>

        <!-- Central Processing Tool -->
        <div class="t-node t-tool-wide">
            <div style="font-size: 1.2rem;">⚙️</div>
            <div class="t-label-title" style="font-size: 1.05rem;">Summarize</div>
        </div>

        <div class="t-arrow-section" style="color: {'#94a3b8' if e17_severed else '#ef4444'}; margin: 10px 0;">
            <span class="t-arrow-char">↓</span>
            PASSES_DATA_TO <span class="chip {'chip-severed' if e17_severed else 'chip-active'}">e17</span>
        </div>

        <!-- Dispatch Tool -->
        <div class="t-node t-tool-wide" style="border-color: {'#64748b' if e18_severed or e17_severed else '#ef4444'};">
            <div style="font-size: 1.2rem;">✈️</div>
            <div class="t-label-title" style="font-size: 1.05rem;">EmailSender</div>
        </div>

        <div class="t-arrow-section" style="color: {'#94a3b8' if e18_severed else '#ef4444'}; margin: 10px 0;">
            SENDS_TO <span class="chip {'chip-severed' if e18_severed else 'chip-active'}">e18</span>
            <span class="t-arrow-char" style="margin-top: 3px;">↓</span>
        </div>

        <!-- Destination Node -->
        <div class="t-node t-dest">
            <div style="font-size: 1.3rem;">🌐</div>
            <div class="t-label-title" style="font-size: 1.05rem;">ExternalEmail</div>
            <div class="t-label-sub-orange">External destination (endpoint: smtp://external-relay)</div>
        </div>
    </div>
    </body>
    </html>
    """


def _render_architecture_view_html(
    scenario,
    rels,
    removed,
    dangerous_edge_ids,
    findings,
    selected_finding_idx,
    fix_preview_edges,
    show_removed,
):
    """Render the cinematic, glowing Neo4j graph in SVG matching the AgentFence hero concept."""

    # Precise circular node layout matching the visual reference (viewBox: 0 0 1000 580)
    # Layer 1 (Top): Agent
    # Layer 2 (Middle): Tools (ReadCustomers, ReadInbox, ReadKB, EmailSender)
    # Layer 3 (Bottom): Resources (CustomerDB, InboundInbox, ApprovedKB, ExternalEmail)
    CIRCULAR_NODES = {
        # Agent
        "SupportAgent": {
            "cx": 480, "cy": 105, "r": 38, "type": "agent",
            "icon": "🤖", "label": "SupportAgent", "sub": "(Agent)",
            "glow": "#0284c7", "fill": "#022c4a", "stroke": "#38bdf8"
        },
        # Tools
        "ReadCustomers": {
            "cx": 190, "cy": 255, "r": 30, "type": "tool",
            "icon": "📄", "label": "ReadCustomers", "sub": "(Tool)",
            "glow": "#0284c7", "fill": "#0b1c33", "stroke": "#38bdf8"
        },
        "ReadInbox": {
            "cx": 380, "cy": 255, "r": 30, "type": "tool",
            "icon": "✉️", "label": "ReadInbox", "sub": "(Tool)",
            "glow": "#0284c7", "fill": "#0b1c33", "stroke": "#38bdf8"
        },
        "Summarize": {
            "cx": 380, "cy": 255, "r": 30, "type": "tool",
            "icon": "⚙️", "label": "Summarize", "sub": "(Tool)",
            "glow": "#0284c7", "fill": "#0b1c33", "stroke": "#38bdf8"
        },
        "ReadKB": {
            "cx": 580, "cy": 255, "r": 30, "type": "tool",
            "icon": "📖", "label": "ReadKB", "sub": "(Tool)",
            "glow": "#10b981", "fill": "#06281e", "stroke": "#34d399"
        },
        "EmailSender": {
            "cx": 780, "cy": 255, "r": 32, "type": "tool",
            "icon": "✈️", "label": "EmailSender", "sub": "(Tool)",
            "glow": "#ef4444", "fill": "#2a0d13", "stroke": "#f87171"
        },
        "ReportTool": {
            "cx": 915, "cy": 255, "r": 26, "type": "tool",
            "icon": "📊", "label": "ReportTool", "sub": "(Tool)",
            "glow": "#8b5cf6", "fill": "#1e1338", "stroke": "#a78bfa"
        },
        # Resources & External Destinations
        "CustomerDB": {
            "cx": 190, "cy": 435, "r": 34, "type": "res_priv",
            "icon": "🗄️", "label": "CustomerDB", "sub": "(Private)",
            "glow": "#ef4444", "fill": "#2b0a11", "stroke": "#ef4444"
        },
        "InboundInbox": {
            "cx": 380, "cy": 435, "r": 34, "type": "res_unt",
            "icon": "📥", "label": "InboundInbox", "sub": "(Untrusted)",
            "glow": "#f59e0b", "fill": "#261506", "stroke": "#f59e0b"
        },
        "ApprovedKB": {
            "cx": 580, "cy": 435, "r": 34, "type": "res_pub",
            "icon": "📚", "label": "ApprovedKB", "sub": "(Approved)",
            "glow": "#10b981", "fill": "#05291b", "stroke": "#10b981"
        },
        "ExternalEmail": {
            "cx": 780, "cy": 435, "r": 36, "type": "dest",
            "icon": "🌐", "label": "ExternalEmail", "sub": "(Unapproved)",
            "glow": "#ef4444", "fill": "#360a12", "stroke": "#ef4444"
        },
    }

    # Generate SVG Edges
    svg_edges = []
    svg_edge_labels = []

    for r in rels:
        eid = r["id"]
        from_n = r["from"]
        to_n = r["to"]
        rel_type = r["type"]

        # If from_n or to_n maps to ReadInbox or Summarize, normalize
        if from_n not in CIRCULAR_NODES or to_n not in CIRCULAR_NODES:
            continue

        is_severed = eid in removed
        is_dangerous = eid in dangerous_edge_ids and not is_severed

        if is_severed and not show_removed:
            continue

        p1 = CIRCULAR_NODES[from_n]
        p2 = CIRCULAR_NODES[to_n]

        x1, y1 = p1["cx"], p1["cy"]
        x2, y2 = p2["cx"], p2["cy"]

        # Calculate angle and perimeter points
        import math
        angle = math.atan2(y2 - y1, x2 - x1)
        sx = x1 + p1["r"] * math.cos(angle)
        sy = y1 + p1["r"] * math.sin(angle)
        ex = x2 - (p2["r"] + 6) * math.cos(angle)
        ey = y2 - (p2["r"] + 6) * math.sin(angle)

        mid_x = (sx + ex) / 2
        mid_y = (sy + ey) / 2

        # Curved control point
        curve = 18 if abs(ex - sx) > 40 else 0
        cx = mid_x - curve * math.sin(angle)
        cy = mid_y + curve * math.cos(angle)

        severed_tag = " [SEVERED]" if is_severed else ""

        if is_severed:
            stroke_col = "#ef4444"
            stroke_w = "2.0"
            dash = "5,5"
            opacity = "0.55"
            marker = "url(#arrow-severed)"
            filter_str = ""
        elif is_dangerous:
            stroke_col = "#ef4444"
            stroke_w = "3.2"
            dash = "6,4" if rel_type == "PASSES_DATA_TO" else "none"
            opacity = "1.0"
            marker = "url(#arrow-dangerous)"
            filter_str = 'filter="url(#glow-red)"'
        else:
            stroke_col = "#0284c7" if rel_type == "CAN_INVOKE" else ("#10b981" if rel_type == "READS" and to_n == "ApprovedKB" else "#38bdf8")
            stroke_w = "1.8"
            dash = "none"
            opacity = "0.75"
            marker = "url(#arrow-cyan)"
            filter_str = 'filter="url(#glow-blue)"'

        edge_d = f"M {sx:.1f} {sy:.1f} Q {cx:.1f} {cy:.1f} {ex:.1f} {ey:.1f}"
        edge_cls = f"graph-edge {'edge-danger' if is_dangerous else ''}"

        svg_edges.append(
            f'<path d="{edge_d}" stroke="{stroke_col}" stroke-width="{stroke_w}" '
            f'stroke-dasharray="{dash}" opacity="{opacity}" fill="none" marker-end="{marker}" '
            f'{filter_str} class="{edge_cls}" data-eid="{eid}"/>'
        )

        # Label along the edge
        lx = (sx + 2 * cx + ex) / 4
        ly = (sy + 2 * cy + ey) / 4

        # If severed, render a bold severed badge with an (X)
        if is_severed:
            svg_edge_labels.append(
                f'<g transform="translate({lx:.1f}, {ly:.1f})">'
                f'<rect x="-42" y="-10" width="84" height="20" rx="10" fill="#2d0a10" stroke="#ef4444" stroke-width="1.5"/>'
                f'<text x="0" y="4" text-anchor="middle" fill="#fca5a5" font-size="9.5" font-family="monospace" font-weight="bold">✕ {eid}{severed_tag}</text>'
                f'</g>'
            )
        else:
            lbl_bg = "rgba(127, 29, 29, 0.85)" if is_dangerous else "rgba(15, 23, 42, 0.85)"
            lbl_stroke = "#ef4444" if is_dangerous else "#0284c7"
            lbl_txt = "#fca5a5" if is_dangerous else "#7dd3fc"
            svg_edge_labels.append(
                f'<g transform="translate({lx:.1f}, {ly:.1f})">'
                f'<rect x="-24" y="-8" width="48" height="16" rx="4" fill="{lbl_bg}" stroke="{lbl_stroke}" stroke-width="1"/>'
                f'<text x="0" y="3.5" text-anchor="middle" fill="{lbl_txt}" font-size="8.5" font-family="monospace" font-weight="bold">{eid}</text>'
                f'</g>'
            )

    # Generate Nodes
    svg_nodes = []
    for name, p in CIRCULAR_NODES.items():
        cx = p["cx"]
        cy = p["cy"]
        r = p["r"]
        icon = p["icon"]
        label = p["label"]
        sub = p["sub"]
        fill = p["fill"]
        stroke = p["stroke"]
        ntype = p["type"]

        is_danger_node = False
        if dangerous_edge_ids:
            for r_item in rels:
                if r_item["id"] in dangerous_edge_ids and (r_item["from"] == name or r_item["to"] == name):
                    is_danger_node = True
                    break

        glow_id = "glow-agent" if ntype == "agent" else ("glow-red" if (is_danger_node or ntype in ("res_priv", "dest")) else "glow-blue")
        border_w = "3.0" if (is_danger_node or ntype == "agent") else "2.0"

        # Special pulse ring for agent
        agent_pulse = ""
        if ntype == "agent":
            agent_pulse = (
                f'<circle cx="{cx}" cy="{cy}" r="{r + 8}" fill="none" stroke="#38bdf8" stroke-width="1.5" opacity="0.4" class="pulse-ring"/>'
                f'<circle cx="{cx}" cy="{cy}" r="{r + 16}" fill="none" stroke="#0284c7" stroke-width="1.0" opacity="0.2" class="pulse-ring-outer"/>'
            )

        # Danger node outer halo
        halo = ""
        if is_danger_node and ntype != "agent":
            halo = f'<circle cx="{cx}" cy="{cy}" r="{r + 6}" fill="none" stroke="#ef4444" stroke-width="1.5" opacity="0.45" stroke-dasharray="3,3"/>'

        svg_nodes.append(
            f'<g class="graph-node" data-name="{name}">'
            f'{agent_pulse}'
            f'{halo}'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{border_w}" filter="url(#{glow_id})"/>'
            f'<text x="{cx}" y="{cy + 6}" text-anchor="middle" font-size="{r * 0.6:.1f}" fill="#ffffff">{icon}</text>'
            f'<text x="{cx}" y="{cy + r + 15}" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="700" letter-spacing="-0.01em">{label}</text>'
            f'<text x="{cx}" y="{cy + r + 27}" text-anchor="middle" fill="{stroke}" font-size="9" font-weight="600">{sub}</text>'
            f'</g>'
        )

    edges_svg = "\n".join(svg_edges)
    labels_svg = "\n".join(svg_edge_labels)
    nodes_svg = "\n".join(svg_nodes)

    # Selected Path Card HTML
    f1_card = ""
    if findings:
        f0 = findings[0] if (selected_finding_idx is None or selected_finding_idx >= len(findings)) else findings[selected_finding_idx]
        eids_str = ", ".join(f0["edge_ids"][:4]) + ("..." if len(f0["edge_ids"]) > 4 else "")
        f1_card = f"""
        <div class="selected-path-overlay">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <div style="font-weight: 800; font-size: 0.88rem; color: #ffffff;">Selected Path: F1</div>
                <div style="cursor: pointer; color: #64748b; font-size: 0.9rem;">✕</div>
            </div>
            <div class="risk-badge">⚠️ High Risk</div>
            <div class="path-sequence">
                {f0['source']} → {' → '.join(f0['tool_chain'])} → {f0['destination']}
            </div>
            <div class="meta-row"><span>Agent:</span> <b>{f0['agent']}</b></div>
            <div class="meta-row"><span>Source:</span> <b>{f0['source']} (Private)</b></div>
            <div class="meta-row"><span>Destination:</span> <b>{f0['destination']} (Unapproved)</b></div>
            <div class="meta-row"><span>Relationships:</span> <code style="color: #38bdf8;">[{eids_str}]</code></div>
            <div style="margin-top: 8px; border-top: 1px solid rgba(239, 68, 68, 0.2); padding-top: 6px;">
                <div style="font-size: 0.72rem; color: #fca5a5; font-weight: 700;">Why is this a risk?</div>
                <div style="font-size: 0.72rem; color: #cbd5e1; line-height: 1.35; margin-top: 2px;">
                    Private customer data can flow to an unapproved external destination through the agent's allowed tools.
                </div>
            </div>
        </div>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
    <style>
        body {{
            background: #060913;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 4px;
            overflow: hidden;
        }}
        .canvas-wrapper {{
            width: 100%;
            height: 540px;
            background: radial-gradient(circle at 50% 20%, #0d1b38 0%, #060913 75%);
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-radius: 12px;
            position: relative;
            box-shadow: inset 0 0 50px rgba(0, 0, 0, 0.8), 0 0 25px rgba(2, 132, 199, 0.15);
        }}
        svg {{
            width: 100%;
            height: 100%;
            display: block;
        }}
        /* Cyber grid backdrop */
        .grid-line {{
            stroke: rgba(56, 189, 248, 0.05);
            stroke-width: 1;
        }}
        /* Floating Path Card Overlay */
        .selected-path-overlay {{
            position: absolute;
            top: 16px;
            right: 16px;
            width: 250px;
            background: rgba(11, 17, 32, 0.88);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(239, 68, 68, 0.45);
            border-radius: 10px;
            padding: 12px 14px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.7), 0 0 15px rgba(239, 68, 68, 0.2);
            z-index: 10;
        }}
        .risk-badge {{
            display: inline-block;
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.5);
            font-size: 0.68rem;
            font-weight: 800;
            padding: 2px 8px;
            border-radius: 9999px;
            margin-bottom: 6px;
            letter-spacing: 0.04em;
        }}
        .path-sequence {{
            color: #f87171;
            font-weight: 700;
            font-size: 0.78rem;
            line-height: 1.35;
            margin-bottom: 8px;
        }}
        .meta-row {{
            font-size: 0.72rem;
            color: #94a3b8;
            margin-bottom: 3px;
            display: flex;
            justify-content: space-between;
        }}
        .meta-row b {{
            color: #ffffff;
        }}
        /* Pulsing Glow Animations */
        @keyframes pulse-cyan {{
            0% {{ opacity: 0.3; transform: scale(0.98); }}
            50% {{ opacity: 0.7; transform: scale(1.02); }}
            100% {{ opacity: 0.3; transform: scale(0.98); }}
        }}
        .edge-danger {{
            stroke-dasharray: 6,4;
            animation: flow-danger 1.5s linear infinite;
        }}
        @keyframes flow-danger {{
            from {{ stroke-dashoffset: 20; }}
            to {{ stroke-dashoffset: 0; }}
        }}
        /* Nodes */
        .graph-node {{
            cursor: pointer;
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        }}
        .graph-node:hover {{
            transform: scale(1.06);
        }}
        /* Legend Bar */
        .legend-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            background: rgba(9, 14, 26, 0.95);
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 6px 14px;
            margin-top: 6px;
            font-size: 0.72rem;
            align-items: center;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 5px;
            color: #94a3b8;
        }}
        .dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }}
    </style>
    </head>
    <body>
    <div class="canvas-wrapper">
        <svg viewBox="0 0 1000 540" preserveAspectRatio="xMidYMid meet">
            <defs>
                <!-- Neon Glow Filters -->
                <filter id="glow-agent" x="-30%" y="-30%" width="160%" height="160%">
                    <feGaussianBlur stdDeviation="6" result="blur"/>
                    <feMerge>
                        <feMergeNode in="blur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
                <filter id="glow-blue" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="3" result="blur"/>
                    <feMerge>
                        <feMergeNode in="blur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
                <filter id="glow-red" x="-25%" y="-25%" width="150%" height="150%">
                    <feGaussianBlur stdDeviation="5" result="blur"/>
                    <feMerge>
                        <feMergeNode in="blur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
                <!-- Marker Arrows -->
                <marker id="arrow-cyan" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>
                </marker>
                <marker id="arrow-dangerous" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444"/>
                </marker>
                <marker id="arrow-severed" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444"/>
                </marker>
            </defs>

            <!-- Subtle Cyber Grid Background -->
            <g id="grid">
                <line x1="0" y1="105" x2="1000" y2="105" class="grid-line"/>
                <line x1="0" y1="255" x2="1000" y2="255" class="grid-line"/>
                <line x1="0" y1="435" x2="1000" y2="435" class="grid-line"/>
                <line x1="190" y1="0" x2="190" y2="540" class="grid-line"/>
                <line x1="380" y1="0" x2="380" y2="540" class="grid-line"/>
                <line x1="480" y1="0" x2="480" y2="540" class="grid-line"/>
                <line x1="580" y1="0" x2="580" y2="540" class="grid-line"/>
                <line x1="780" y1="0" x2="780" y2="540" class="grid-line"/>
            </g>

            <!-- Relationship Edges -->
            <g id="edges-group">
                {edges_svg}
            </g>

            <!-- Edge Labels -->
            <g id="labels-group">
                {labels_svg}
            </g>

            <!-- Circular Nodes -->
            <g id="nodes-group">
                {nodes_svg}
            </g>
        </svg>

        <!-- Floating Selected Path Card -->
        {f1_card}
    </div>

    <!-- Graph Legend matching required tokens -->
    <div class="legend-bar">
        <span style="font-weight: 700; color: #cbd5e1; margin-right: 4px;">Legend:</span>
        <div class="legend-item"><span class="dot" style="background: #38bdf8;"></span> Agent</div>
        <div class="legend-item"><span class="dot" style="background: #0284c7;"></span> Tool</div>
        <div class="legend-item"><span class="dot" style="background: #ef4444;"></span> Private Resource</div>
        <div class="legend-item"><span class="dot" style="background: #f59e0b;"></span> Untrusted Resource</div>
        <div class="legend-item"><span class="dot" style="background: #10b981;"></span> Approved Resource</div>
        <div class="legend-item"><span class="dot" style="background: #f87171;"></span> External Destination</div>
        <div class="legend-item"><span style="color: #ef4444; font-weight: bold;">───</span> Modeled Dangerous Path</div>
        <div class="legend-item"><span style="color: #0284c7; font-weight: bold;">───</span> Active Permission</div>
        <div class="legend-item"><span style="color: #ef4444; font-weight: bold;">- - -</span> Severed Edge</div>
    </div>
    </body>
    </html>
    """
