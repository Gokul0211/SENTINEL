# SENTINEL: Semantic Security Fabric for Production LLM Systems

## Overview

SENTINEL is an in-line, semantic-layer security fabric designed to sit between user inputs, retrieved context, LLM agent environments, and final system outputs. Standard Web Application Firewalls (WAFs) fail to secure LLMs because the attack surface consists of natural language rather than syntactic anomalies. SENTINEL addresses this by implementing five real-time semantic analysis layers.

This repository contains the complete implementation of the SENTINEL architecture, encompassing the proxy engine, five security layers, a cross-layer correlation engine, and a real-time HUD dashboard for monitoring threat events.

## Architecture

The system operates as an intermediary proxy (`/v1/chat/completions`) intercepting traffic to and from the LLM. 

### Core Components

*   **Threat Intelligence Bus (TIB):** An in-memory event bus and session state manager (`sentinel/core/threat_bus.py`). It tracks conversation history, aggregates threat scores across layers, and broadcasts `ThreatEvent` structures via WebSockets to the frontend.
*   **Correlation Engine:** Operates at the end of each request pipeline (`sentinel/core/correlation_engine.py`). It evaluates cross-layer signals to identify complex attacks (e.g., a slow-burn semantic shift combined with a system prompt extraction probe).

### Security Layers

1.  **Layer 1: Text & Image Injection Scanner (`sentinel/layers/layer1.py`)**
    *   *Function:* Synchronous filtering of explicit prompt injections, jailbreaks, and extraction probes.
    *   *Mechanism:* Two-tier analysis. Tier 1 uses high-performance regex patterns. Tier 2 uses semantic similarity via `all-MiniLM-L6-v2` embeddings against a curated vector set of known attack signatures.

2.  **Layer 2: RAG Integrity Monitor (`sentinel/layers/layer2_rag/`)**
    *   *Function:* Prevents knowledge poisoning by validating document chunks before ingestion and retrieval.
    *   *Mechanism:* Calculates "instruction density" using the L1 embedding model to detect if a chunk is attempting to issue directives. Employs HMAC-SHA256 signing for data provenance to detect post-ingestion tampering.

3.  **Layer 3: Conversational Drift Tracker (`sentinel/layers/layer3.py`)**
    *   *Function:* Identifies slow-burn attacks that attempt to bypass static filters through multi-turn escalation.
    *   *Mechanism:* Tracks semantic velocity by calculating the cosine distance between the embeddings of consecutive user turns. Monitors cumulative drift against the baseline topic.

4.  **Layer 4: Agentic Reasoning Auditor (`sentinel/layers/layer4_agentic/`)**
    *   *Function:* Secures function-calling and tool execution.
    *   *Mechanism:* Intercepts tool calls prior to execution. Parses chain-of-thought traces for self-authorization heuristics. Traces parameter provenance using edit distance to determine if a parameter originated from user input, retrieved context, or model hallucination. Includes a static risk matrix for tool categorization.

5.  **Layer 5: Output Semantic Firewall (`sentinel/layers/layer5_output/`)**
    *   *Function:* Final pass validation of LLM outputs.
    *   *Mechanism:* Scans for PII leakage using regex patterns (SSN, credit cards, API keys). Detects system prompt exfiltration using Jaccard similarity (token overlap) and semantic similarity against the known system prompt. Enforces policies defined in `sentinel_policy.yaml`.

## Setup and Installation

### Prerequisites
*   Python 3.10+
*   Windows environment (or Linux/macOS, though current paths/scripts assume Windows)

### Installation
1.  Navigate to the project root directory.
2.  Install dependencies:
    ```bash
    pip install fastapi uvicorn sentence-transformers pydantic websockets pyyaml pdfplumber Pillow
    ```
    *Note: ChromaDB integration is currently mocked via an in-memory dictionary in `chunk_store.py` to bypass C++ compiler dependency issues on standard Windows environments. The integrity logic remains fully functional.*

## Running the System

Start the FastAPI server utilizing Uvicorn:

```bash
python main.py
```

*   The API will be available at `http://localhost:8080`.
*   The HUD Dashboard is served at `http://localhost:8080/`.

## Endpoints

### Core Proxy
*   `POST /sentinel/chat`: The main interceptor endpoint. Takes `{ "content": "string", "session_id": "string" }` and passes it through L1 and L3 analysis, simulates an LLM response, and runs the L5 output scan.

### RAG Operations (Layer 2)
*   `POST /sentinel/rag/ingest`: Ingest a document chunk. Calculates trust score and signs it.
*   `GET /sentinel/rag/chunks`: List all active and quarantined chunks.
*   `POST /sentinel/rag/quarantine/{chunk_id}`: Manually move a chunk to quarantine.

### Agentic Operations (Layer 4)
*   `POST /sentinel/agent/tool_call`: Intercept and audit a tool call. Takes `{ "tool_name": "string", "parameters": {}, "reasoning_trace": "string", "session_id": "string", "history": [] }`.

### Output Scan (Layer 5)
*   `POST /sentinel/output/scan`: Standalone endpoint for final output scanning.

### Demo Scenarios
*   `POST /sentinel/demo/{scenario_id}`: Trigger automated attack sequences that process through the real security layers.
    *   `rag_agent`: Ingests a poisoned chunk and triggers a tool call matching that chunk's parameters to demonstrate the `RAG_PLUS_AGENT_ATTACK` correlation rule.
    *   `slow_burn`: Runs a predefined 5-turn chat sequence through L3 and L5 to demonstrate the `SLOW_BURN_INJECTION` and `EXFIL_AFTER_PROBE` correlation rules.

## Explainability and UI

The frontend dashboard (`dashboard/static/index.html`) subscribes to the `/ws/events` WebSocket. All components in the UI are driven by the `ThreatEvent` data structure. When a layer blocks a request, it populates the `explanation` dictionary with a detailed chain of findings, which the frontend renders natively in the Session Panel. No mock data is utilized in the UI visualization; all layer indicators and metrics reflect real-time analytical output.
