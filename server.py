#!/usr/bin/env python3
"""AgentFence HTTP Backend Server.

Runs at 0.0.0.0:80 (or PORT env var) using standard library http.server (no extra dependencies).
Provides REST API endpoints for:
- GET /health
- POST /api/seed
- GET /api/detect?scenario=base
- GET /api/workflows?scenario=base
- GET /api/fix?scenario=base
- POST /api/decisions
- GET /api/ai-detect?scenario=base
- POST /api/explain
"""

import os
import json
import dataclasses
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from agentfence.db import get_driver
from agentfence.seed import seed_graph
from agentfence.detector import detect_paths
from agentfence.workflows import check_workflows
from agentfence.fixer import find_fix
from agentfence.decisions import save_decision, get_active_removed_edge_ids
from agentfence.ai_detector import detect_paths_with_gemini
from agentfence.explainer import explain_findings


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, set):
            return list(o)
        return super().default(o)


class AgentFenceHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data, cls=EnhancedJSONEncoder).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        scenario = params.get("scenario", ["base"])[0]

        try:
            driver = get_driver()
            if path in ["/", "/health"]:
                self._send_json(200, {
                    "status": "healthy",
                    "service": "AgentFence Backend",
                    "scenario": scenario
                })
            elif path == "/api/detect":
                findings = detect_paths(driver, scenario=scenario)
                self._send_json(200, {
                    "scenario": scenario,
                    "findings_count": len(findings),
                    "findings": [dataclasses.asdict(f) for f in findings]
                })
            elif path == "/api/workflows":
                wfs = check_workflows(driver, scenario=scenario)
                self._send_json(200, {
                    "scenario": scenario,
                    "workflows": [dataclasses.asdict(w) for w in wfs]
                })
            elif path == "/api/fix":
                fix_res = find_fix(driver, scenario=scenario)
                self._send_json(200, dataclasses.asdict(fix_res))
            elif path == "/api/decisions":
                active_ids = get_active_removed_edge_ids(driver)
                self._send_json(200, {
                    "active_removed_edge_ids": list(active_ids)
                })
            elif path == "/api/ai-detect":
                ai_res = detect_paths_with_gemini(driver, scenario=scenario)
                self._send_json(200, dataclasses.asdict(ai_res))
            else:
                self._send_json(404, {"error": f"Endpoint '{path}' not found"})
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            body = json.loads(post_data.decode("utf-8")) if post_data else {}
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        try:
            driver = get_driver()
            if path == "/api/seed":
                scenario = body.get("scenario", "base")
                seed_graph(driver, scenario=scenario)
                self._send_json(200, {
                    "status": "success",
                    "message": f"Graph seeded for scenario '{scenario}'",
                    "scenario": scenario
                })
            elif path == "/api/decisions":
                candidate = body.get("candidate")
                scenario = body.get("scenario", "base")
                if not candidate:
                    self._send_json(400, {"error": "Missing 'candidate' in request body"})
                    return
                dec_res = save_decision(driver, candidate, scenario=scenario)
                self._send_json(200, dataclasses.asdict(dec_res))
            elif path == "/api/explain":
                scenario = body.get("scenario", "base")
                findings = detect_paths(driver, scenario=scenario)
                fix_res = find_fix(driver, scenario=scenario)
                wfs = check_workflows(driver, scenario=scenario)
                exp = explain_findings(findings, fix_res.candidates, wfs, use_ai=True)
                self._send_json(200, dataclasses.asdict(exp))
            else:
                self._send_json(404, {"error": f"Endpoint '{path}' not found"})
        except Exception as e:
            self._send_json(500, {"error": str(e)})


def run_server(host: str = "0.0.0.0", port: int = 80):
    server = HTTPServer((host, port), AgentFenceHandler)
    print(f"AgentFence Backend running at http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "80"))
    run_server(host, port)
