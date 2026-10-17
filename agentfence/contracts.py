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
