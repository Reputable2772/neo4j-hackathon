# AgentFence — AI-Agent Data-Path Security

AgentFence is a security verification and permission remediation engine for modeled AI-agent workflows using **Neo4j** and **Google Gemini AI**.

## Architecture & Responsibilities

- **Neo4j Graph Database:** Stores modeled agents, tools, private resources, destinations, permission relationships (`CAN_INVOKE`, `READS`, `SENDS_TO`), and data-flow evidence (`RETURNS_DATA_TO`, `PASSES_DATA_TO`).
- **Deterministic Security Engine:** 
  - Authoritative path detection (`agentfence/detector.py`).
  - Business workflow invariants W1 and W2 (`agentfence/workflows.py`).
  - Five-candidate permission remediation evaluator (`agentfence/fixer.py`).
  - Non-mutating decision persistence (`agentfence/decisions.py`).
- **Google Gemini AI (`google-genai` SDK):**
  - AI-assisted path discovery from graph schema metadata (`agentfence/ai_detector.py`).
  - Strict read-only Cypher validation (`agentfence/validator.py`).
  - Plain-English risk and remediation explanation (`agentfence/explainer.py`).
  - Graceful fallback when Gemini API key or quota is unavailable.

## Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Set your Neo4j and Gemini credentials:
```env
# Neo4j Database Connection
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=secretpassword
NEO4J_DATABASE=neo4j

# Google Gemini Configuration
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash-lite
```

## Reproducible Environment (Nix Flakes)

Enter the development shell:
```bash
nix develop
```

Run tests within the devshell:
```bash
nix develop --command pytest
```

## Running the Backend

Execute the full end-to-end backend verification script:
```bash
nix develop --command python -c "
from agentfence.db import get_driver
from agentfence.seed import seed_graph
from agentfence.detector import detect_paths
from agentfence.workflows import check_workflows
from agentfence.fixer import find_fix

driver = get_driver()
seed_graph(driver, scenario='base')
print('Baseline findings:', len(detect_paths(driver, scenario='base')))
print('Workflows:', [w.name for w in check_workflows(driver, scenario='base') if w.passed])
fix = find_fix(driver, scenario='base')
print('Accepted candidate:', fix.accepted)
"
```
