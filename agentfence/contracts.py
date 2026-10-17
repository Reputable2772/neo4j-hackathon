from dataclasses import dataclass, field
from typing import List, Optional, Set, Any


@dataclass
class Finding:
    source: str
    destination: str
    path: List[str]
    relationship_ids: List[str]
    permission_edge_ids: List[str]
    data_flow_edge_ids: List[str]

    def __getitem__(self, key: str) -> Any:
        if key == "tool_chain":
            return self.path[1:-1] if len(self.path) > 2 else []
        if key == "edge_ids":
            return self.relationship_ids
        if key == "agent":
            return "report_agent"
        if key == "path":
            if isinstance(self.path, list):
                return f"Path: {' → '.join(self.path)}"
            return str(self.path)
        if key == "path_sentence":
            return f"Agent can read {self.source} via {self.path[1]}, pass data to {self.path[2] if len(self.path) > 3 else ''}, and send to {self.destination}."
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, AttributeError):
            return default


@dataclass
class WorkflowResult:
    name: str  # "W1" or "W2"
    passed: bool
    reason: str

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, AttributeError):
            return default


@dataclass
class CandidateResult:
    removed_edge_id: str
    decision: str  # "ACCEPT" or "REJECT"
    reason: str
    remaining_findings: List[Finding]
    workflows: List[WorkflowResult]

    def __getitem__(self, key: str) -> Any:
        if key == "edge_id":
            return self.removed_edge_id
        if key == "tool":
            parts = self.removed_edge_id.split(":")
            return parts[-1] if len(parts) > 1 else self.removed_edge_id
        if key == "permission_label":
            parts = self.removed_edge_id.split(":")
            if len(parts) >= 3:
                return f"{parts[1]} CAN_INVOKE {parts[2]}"
            return self.removed_edge_id
        if key == "paths_remaining":
            return len(self.remaining_findings)
        if key == "w1_status":
            w1 = next((w for w in self.workflows if w.name == "W1"), None)
            return "PASS" if w1 and w1.passed else "FAIL"
        if key == "w2_status":
            w2 = next((w for w in self.workflows if w.name == "W2"), None)
            return "PASS" if w2 and w2.passed else "FAIL"
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, AttributeError):
            return default


@dataclass
class FixResult:
    candidates: List[CandidateResult]
    accepted: Optional[str]  # removed_edge_id that was accepted, or None
    findings_after_fix: List[Finding]
    workflows_after_fix: List[WorkflowResult]

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, AttributeError):
            return default


@dataclass
class DecisionResult:
    decision_id: str
    removed_edge_ids: List[str]
    status: str
    persisted: bool

    def __getitem__(self, key: str) -> Any:
        if key == "candidate_removed":
            return self.removed_edge_ids[0] if len(self.removed_edge_ids) == 1 else self.removed_edge_ids
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, AttributeError):
            return default


@dataclass
class AIAssistedFinding:
    source: str
    destination: str
    path: List[str]
    relationship_ids: List[str]
    permission_edge_ids: List[str]
    data_flow_edge_ids: List[str]
    is_validated: bool
    evidence: str
    cypher_query: str


@dataclass
class ExplanationResult:
    risk_summary: str
    path_explanations: List[dict]
    accepted_fix_explanation: str
    rejected_candidates_explanation: List[dict]
    evidence_summary: str
    w1_w2_status: str
    limitations: str
    source: str  # "GEMINI_AI" or "FALLBACK_ANALYST"


@dataclass
class GeminiDetectionResult:
    findings: List[AIAssistedFinding]
    query_executed: Optional[str]
    raw_model_response: Optional[str]
    status: str
    error: Optional[str] = None

