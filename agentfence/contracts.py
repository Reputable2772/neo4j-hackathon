from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class Finding:
    source: str
    destination: str
    path: List[str]
    relationship_ids: List[str]
    permission_edge_ids: List[str]
    data_flow_edge_ids: List[str]


@dataclass
class WorkflowResult:
    name: str  # "W1" or "W2"
    passed: bool
    reason: str


@dataclass
class CandidateResult:
    removed_edge_id: str
    decision: str  # "ACCEPT" or "REJECT"
    reason: str
    remaining_findings: List[Finding]
    workflows: List[WorkflowResult]


@dataclass
class FixResult:
    candidates: List[CandidateResult]
    accepted: Optional[str]  # removed_edge_id that was accepted, or None
    findings_after_fix: List[Finding]
    workflows_after_fix: List[WorkflowResult]


@dataclass
class DecisionResult:
    decision_id: str
    removed_edge_ids: List[str]
    status: str
    persisted: bool


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
    source: str  # "SARVAM_AI" or "FALLBACK_ANALYST"


@dataclass
class SarvamDetectionResult:
    findings: List[AIAssistedFinding]
    query_executed: Optional[str]
    raw_model_response: Optional[str]
    status: str
    error: Optional[str] = None
