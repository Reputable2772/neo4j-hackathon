# AgentFence 🛡️

**Secure the paths. Preserve the workflows.**

> *Graph-powered security analysis and permission-remediation verification for modeled AI-agent data paths.*  
> **Core Principle:** LLM proposes. Neo4j verifies.

---

## 1. Problem Statement & Solution

Modern enterprise AI systems connect autonomous agents to private databases, external APIs, and communication tools. When an agent is granted broad tool invocation privileges, data exfiltration routes emerge across interconnected tools:

```
[Private Resource] → [Reader Tool] → [Intermediate Tool] → [Sender Tool] → [External Destination]
```

Traditional IAM approaches either:
1. **Under-react**: Leave permissions unmonitored, allowing multi-hop data leakage.
2. **Over-react**: Naively revoke external or data-access permissions, breaking mission-critical business workflows.

### The AgentFence Approach
AgentFence uses property graph modeling in Neo4j to:
- **Detect dangerous data paths**: Trace deterministic data routes from private or untrusted resources to unapproved external destinations through directly invokable tool chains.
- **Run negative tests**: Prove that the engine evaluates end-to-end reachability rather than flagging any agent that merely possesses a sender tool.
- **Evaluate candidate fixes**: Test candidate permission removals in simulation overlays without mutating the live graph.
- **Verify legitimate workflows**: Ensure that legitimate workflows (e.g., approved read and audit reporting) remain fully functional before any fix is approved.
- **Persist auditable decisions**: Record immutable, human-approved remediation decisions in Neo4j (`:Decision` nodes).

---

## 2. Integrated Architecture

AgentFence unifies Person 1's backend security engine (`https://github.com/Reputable2772/neo4j-hackathon`) with Person 2's Streamlit presentation layer into one cohesive application.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   AgentFence Streamlit Dashboard                       │
│     (Cybersecurity UI: Detection, Negative Test, Fixer, Verifier)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Thin Presentation Adapter (ui_service.py)                │
│    - Status & Connectivity Verification (Live Aura vs Fixture Mode)   │
│    - Bridge to Person 1's Contracts & Decision Logic                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Merged Backend Modules                          │
│   ├── contracts.py     (Finding, WorkflowResult, CandidateResult, ...) │
│   ├── detector.py      (detect_paths, detect_data_flow_paths)          │
│   ├── workflows.py     (check_workflows, check_w1, check_w2)           │
│   ├── fixer.py         (find_fix, CANDIDATES, find_fixes)              │
│   ├── decisions.py     (save_decision, get_active_removed_edge_ids)    │
│   ├── seed.py          (seed_graph with scoped MERGE queries)          │
│   └── db.py            (Neo4j Driver lifecycle & FixtureDriver fallback)│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Bolt Protocol / In-Memory Fallback
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          Neo4j Graph Store                             │
│   - Nodes: :Agent, :Tool, :Resource, :Destination, :Decision           │
│   - Edges: :CAN_INVOKE, :READS, :RETURNS_DATA_TO, :PASSES_DATA_TO,     │
│            :SENDS_TO                                                   │
│   - Scenarios: "base", "negative", "baseline", "updated"               │
│   *(Preserves existing datasets via scoped label & property MERGE)*    │
└────────────────────────────────────────────────────────────────────────┘
```

### Shared Contracts (`agentfence/contracts.py`)
- `Finding`: Identifies data leak paths (`source`, `destination`, `path`, `relationship_ids`, `permission_edge_ids`, `data_flow_edge_ids`).
- `WorkflowResult`: Status of essential business workflows (`name`, `passed`, `reason`).
- `CandidateResult`: Outcome of candidate permission removal (`removed_edge_id`, `decision`, `reason`, `remaining_findings`, `workflows`).
- `FixResult`: Summary of candidate evaluations and post-fix state (`candidates`, `accepted`, `findings_after_fix`, `workflows_after_fix`).
- `DecisionResult`: Persisted audit record (`decision_id`, `removed_edge_ids`, `status`, `persisted`).

---

## 3. Supported Scenarios & Verification Gates

### A. Person 1 Security Benchmark (`scenario="base"`)
- **Agent**: `report_agent`
- **Tools**: `document_reader`, `email_sender`, `webhook_poster`
- **Resource**: `payroll_report` (private: true)
- **Destinations**: `internal_audit` (approved: true), `attacker_endpoint` (unapproved), `shadow_endpoint` (unapproved)
- **Baseline Dangerous Paths (2 findings)**:
  1. `payroll_report` → `document_reader` → `webhook_poster` → `attacker_endpoint`
  2. `payroll_report` → `document_reader` → `webhook_poster` → `shadow_endpoint`
- **Required Workflows**:
  - `W1` (Read): `report_agent` reads `payroll_report` via `document_reader`
  - `W2` (Audit): complete reporting data-path to `internal_audit` is functional
- **Evaluated Candidates (5 candidates)**:
  1. `ci:report_agent:document_reader` → **REJECT** (Breaks W1)
  2. `read:document_reader:payroll_report` → **REJECT** (Breaks W1)
  3. `ci:report_agent:webhook_poster` → **ACCEPT** (0 paths remain, W1 PASS, W2 PASS)
  4. `send:webhook_poster:attacker_endpoint` → **REJECT** (shadow_endpoint path remains)
  5. `send:webhook_poster:shadow_endpoint` → **REJECT** (attacker_endpoint path remains)

### B. Enterprise Support Model (`scenario="baseline"`)
- **Agent**: `SupportAgent`
- **Tools**: `ReadKB`, `ReadCustomers`, `Summarize`, `EmailSender`, `ReportTool`
- **Resources**: `ApprovedKB` (public), `CustomerDB` (private), `InboundInbox` (untrusted)
- **Destination**: `ExternalEmail` (unapproved)
- **Baseline Dangerous Paths (2 findings)**:
  1. `CustomerDB` → `ReadCustomers` → `Summarize` → `EmailSender` → `ExternalEmail`
  2. `InboundInbox` → `Summarize` → `EmailSender` → `ExternalEmail`
- **Winning Candidate**: `e06` (`SupportAgent CAN_INVOKE EmailSender`) → **ACCEPT** (0 paths remain, W1 PASS, W2 PASS).

---

## 4. Setup & Prerequisites

### Prerequisites
- Python 3.11, 3.12, or 3.13
- (Optional) Docker for running local Neo4j 5 container
- (Optional) Neo4j Aura cloud instance

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/Reputable2772/neo4j-hackathon.git
cd AgenticFence

# Create virtual environment
python -m venv .venv

# Activate on Windows:
.venv\Scripts\activate
# Or on Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Configuration
Create a `.env` file in the project root:
```ini
# Neo4j Database Connection (Placeholders - never commit real credentials)
NEO4J_URI=neo4j+s://<your-aura-instance>.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=<your-neo4j-password>
NEO4J_DATABASE=neo4j

# Local mode override (optional: set to true to force offline fixture mode)
AGENTFENCE_LOCAL_MODE=false
```

> **Honest Database Status:** If Neo4j credentials are not provided or connectivity fails, AgentFence automatically operates in in-memory fixture mode. The UI clearly labels this as `Local In-Memory Graph (Fixture Mode)` with an amber indicator. It never claims live Neo4j Aura connectivity unless a real ping succeeds.

### 3. Database Seeding (Optional)
To seed a live Neo4j instance:
```bash
python -m agentfence.seed
```

---

## 5. Startup & Execution

### Launch the Streamlit Dashboard
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

### Run the Complete Test Suite
```bash
pytest
```
Verbose test execution:
```bash
pytest -v
```

---

## 6. End-to-End Demo Script (Five Steps)

1. **Step 1: Baseline Detection**
   - Click **🚨 Run Detection**.
   - Result: 2 dangerous paths detected with complete tool chains and relationship IDs.
2. **Step 2: Negative Fixture Verification**
   - Click **🧪 Run Negative Test**.
   - Result: Confirms 0 findings for negative scenario. Proves reachability-based analysis over simple capability presence.
3. **Step 3: Candidate Fix Evaluation**
   - Click **Find Fix**.
   - Result: Evaluates all 5 candidates. 4 are rejected with explicit reasons; 1 is accepted.
4. **Step 4: Post-Fix Verification**
   - Select candidate `ci:report_agent:webhook_poster` (or `e06`).
   - Result: Confirms 0 dangerous paths remain, W1 PASS, W2 PASS → **VERIFIED SUCCESS**.
5. **Step 5: Decision Persistence & Reload**
   - Confirm approval and click **💾 Save Decision to Neo4j**.
   - Result: Persists decision with UUID (`dec-<id>`).
   - Click **🔄 Reload**: Queries database and confirms reloaded record matches.

---

## 7. Limitations & Security Guardrails

1. **Non-Destructive Simulation**: Candidate evaluation never deletes or mutates live Neo4j relationships. Remediation is represented as simulated removal overlays.
2. **Refusal to Persist Unverified Changes**: Decisions can only be persisted after successful verification (0 dangerous paths and passing workflows).
3. **Connectivity Verification**: Live database mode requires an active round-trip ping (`RETURN 1`). Missing or invalid credentials gracefully fall back to fixture mode.
4. **Safe Initialization**: All seed operations use scoped `MERGE` statements on specific labels so existing datasets (such as Neo4j sample data) are never touched.
