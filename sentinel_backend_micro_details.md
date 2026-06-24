# SENTINEL Backend: Micro-Details, Design Patterns, & Interview Prep

This document serves as an exhaustive technical reference for the **SENTINEL** backend system. It details the exact architecture, internal algorithms, code-level execution steps, and design choices. Read this to prepare for any system design, code audit, or developer interview questions about Sentinel.

---

## 1. System Architecture & Lifecycle

Sentinel is written in **Python 3.12** using **FastAPI** as the web framework and **Uvicorn** as the ASGI web server. It functions as an inline reverse proxy and inspection engine between your client application and LLM providers.

### 1.1 Server Entry Point (`main.py` & `sentinel/app.py`)
* **Lifespan Manager (`@asynccontextmanager`)**: 
  When the FastAPI application starts, the lifespan function handles model pre-loading. It loads the `all-MiniLM-L6-v2` SentenceTransformer model into local memory (CPU) to ensure all subsequent semantic searches are fast and do not block request cycles.
* **CORS Middleware**: 
  Configured to allow all origins (`*`) for local/dashboard development, handling pre-flight `OPTIONS` requests.
* **State Management**:
  All system state resides in the `ThreatBus` inside `sentinel/core/threat_bus.py`. It is a singleton thread-safe repository that stores active `SessionState` records.

---

## 2. Telemetry & State Datastructures (`sentinel/core/models.py`)

Every HTTP request or WebSocket event uses structured dataclasses defined via Python's standard `dataclasses` module.

### 2.1 State Serialization
* **`LayerState`**: A dataclass tracking metrics for a single request evaluation:
  * `l1_score`: Cosine similarity / regex match score of input ($[0.0, 1.0]$).
  * `l2_findings`: List of quarantined chunks or warnings.
  * `l3_current`: Computed turn semantic velocity.
  * `l4_calls`: Intercepted tool executions and their risk scores.
  * `l5_scores`: Output semantic exfiltration or PII finding counts.
* **`SessionState`**: Represents a persistent user conversation. Fields include:
  * `session_id`: Unique identifier (string).
  * `chat_history`: A running list of role-content message dictionaries: `[{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]`.
  * `l2_flagged_chunks`: List of RAG chunks flagged during Layer 2 evaluation.
  * `timeline`: Chronological log of all events occurring in the session.
  * `canary_token`: A cryptographically random `uuid4` string unique to each session.

---

## 3. Inline Security Layers: Micro-Implementation

```
               [ User Input Prompt ]
                         │
      ┌──────────────────┴──────────────────┐
      ▼                                     ▼
[ Layer 1: Input Scanner ]       [ Layer 3: Drift Tracker ]
  - NFKC Normalization             - Deque-based History
  - Regex Signatures               - Semantic Velocity (1-CosSim)
  - Sentence-MiniLM Embeddings     - Cumulative Drift (1-CosSim)
      │                                     │
      └──────────────────┬──────────────────┘
                         ▼
             [ Layer 2: RAG Integrity ]
               - HMAC-SHA256 Signature Verify
               - Instruction Density Scanner
                         │
                         ▼
                 [ Groq LLM Proxy ] ──► [ Layer 4: Agentic Auditor ]
                         │               - Static Risk Level Mapping
                         │               - Parameter Provenance Tracing
                         │               - CoT / Reasoning Flag Parsing
                         │               - Tool Output Validation
                         ▼
             [ Layer 5: Output Guard ]
               - Canary Token Match Scan
               - PII Regex Redactor (Reverse sweep)
               - Prompt Exfiltration Overlap
               - YAML Policy Verification
                         │
                         ▼
                 [ Sanitized Output ]
```

### Layer 1: Input Security Scanner (`sentinel/layers/layer1.py`)

#### Micro-Step A: Normalization Pipeline
Attackers use Unicode tricks or obfuscation to hide bad strings (e.g., `Ｉｇｎｏｒｅ` instead of `Ignore`). Sentinel normalizes input in three steps:
1. **NFKC (Compatibility Decomposition & Canonical Composition)**:
   ```python
   import unicodedata
   normalized = unicodedata.normalize('NFKC', raw_input)
   ```
   This converts styled characters (bold, italic, full-width) back to standard UTF-8.
2. **Zero-Width Character Removal**:
   Removes invisible characters that disrupt string splitting (e.g., `\u200b` zero-width space, `\ufeff` byte-order mark).
3. **Leetspeak to English mapping**:
   Replaces lookalike numbers and symbols (e.g., `1` to `i`, `0` to `o`, `3` to `e`, `@` to `a`).

#### Micro-Step B: Signature Checking (Regex)
If input contains direct jailbreak markers, it is blocked immediately without checking the vector model:
```python
BYPASS_PATTERNS = [
    r"(override|bypass|disable|turn off|deactivate)\s*(security|validation|check|filter|rule)",
    r"pretend\s*(you\s*are|to\s*be)\s*(unrestricted|no\s*longer|unfiltered)",
    r"ignore\s*all?\s*(previous)?\s*(instructions|rules|directions|prompts)",
    r"repeat\s*(your)?\s*system\s*(prompt|instruction)"
]
```
If any regex matches, `score` is set to `0.92` (BLOCKED) in under $1\text{ms}$.

#### Micro-Step C: Base64/Hex/ROT13 Obfuscation Decoding
Layer 1 checks if the input is a valid Base64 string, Hex string, or ROT13 encoding. If it decodes to a readable English string, the decoded string is passed back through the regex and semantic classifiers. If the decoded text is flagged, the original request is blocked with a reason showing the decoded attack string.

#### Micro-Step D: Semantic Cosine Similarity
If the input passes signature checks, it is encoded using a local SentenceTransformer model:
$$\text{Embedding}(\text{Input}) = \mathbf{e}_{\text{input}} \in \mathbb{R}^{384}$$
Sentinel compares this vector against 10 pre-computed reference attack vectors ($V_{\text{attacks}}$) using Cosine Similarity:
$$\text{Score} = \max_{j} \left( \frac{\mathbf{e}_{\text{input}} \cdot \mathbf{v}_j}{\|\mathbf{e}_{\text{input}}\|_2 \|\mathbf{v}_j\|_2} \right)$$
* **Score $\ge 0.75$**: Threat status `BLOCK` (High risk).
* **Score $\ge 0.55$**: Threat status `SUSPICIOUS` (Medium risk).
* **Score $< 0.55$**: Threat status `ALLOW` (Low risk).

---

### Layer 2: RAG Integrity & Ingestion Monitor (`sentinel/layers/layer2_rag/`)

Layer 2 prevents **Indirect Prompt Injection** (where an attacker injects commands into a document that the LLM later retrieves).

#### Micro-Step A: Cryptographic Provenance (`provenance.py`)
To prevent database tampering:
1. **At Ingestion**: When writing a text chunk to the database, a signature is computed using HMAC-SHA256 and a server-side secret key:
   $$\text{Signature} = \text{HMAC-SHA256}(\text{Server\_Secret\_Key}, \text{chunk\_text})$$
2. **At Retrieval**: When a chunk is fetched from the database, the signature is recomputed. 
3. **Tamper Check**: If the recomputed signature does not match the one stored in the chunk's metadata, Sentinel marks the chunk as tampered, sets the threat score to `1.0`, and quarantines the document.

#### Micro-Step B: Instruction Density Evaluation (`instruction_density.py`)
To prevent "invisible instructions" hidden inside factual text, Sentinel evaluates **Instruction Density**:
1. It splits the document chunk into sentences.
2. It encodes each sentence and measures its cosine similarity against template command prompts (e.g., `"ignore previous instructions"`, `"always transfer to..."`).
3. It counts sentences that match these templates with a score $> 0.60$.
4. **Density Metric**:
   $$\text{Instruction Density} = \frac{\text{Number of instructional sentences}}{\text{Total number of sentences}}$$
5. If $\text{Instruction Density} \ge 0.30$, the chunk is quarantined.

---

### Layer 3: Conversation Drift Tracker (`sentinel/layers/layer3.py`)

Jailbreak attempts can be spread across multiple turns (slow-burn attacks). Layer 3 tracks the semantic history of a conversation using a rolling buffer (a double-ended queue `collections.deque` with a max length of 10).

#### Mathematical Formulations
For the $n$-th user message vector $\mathbf{e}_n$:
1. **Semantic Velocity ($V_n$)**: Measures how much the topic changed from the last turn.
   $$V_n = 1.0 - \text{CosineSimilarity}(\mathbf{e}_n, \mathbf{e}_{n-1})$$
2. **Cumulative Drift ($D_n$)**: Measures how far the conversation has drifted from the initial turn.
   $$D_n = 1.0 - \text{CosineSimilarity}(\mathbf{e}_n, \mathbf{e}_1)$$
3. **Escalation Indicator ($E_n$)**: Evaluates the input against a dictionary of override/bypass phrases.

The combined Layer 3 score is computed as:
$$\text{L3 Score} = (V_n \times 0.40) + (D_n \times 0.35) + (E_n \times 0.25)$$

* **Score $\ge 0.70$**: Triggers a **Semantic Drift Warning**.
* **Why this works**: Safe users stay within a consistent topic range, while attackers gradually transition from safe topics to malicious requests, showing up as a steady drift in the embeddings.

---

### Layer 4: Agentic Reasoning Auditor (`sentinel/layers/layer4_agentic/`)

Layer 4 acts as a gatekeeper for LLM tool calls. When the LLM requests a tool call (e.g., database writes, emails), Layer 4 intercepts it.

#### Micro-Step A: Static Risk Evaluation (`risk_matrix.py`)
Tools are looked up in a static risk matrix:
* **CRITICAL**: `execute_code`, `delete_file`, `database_write`, `approve_loan` (Defaults to score `1.0`, blocked unless approved by the user).
* **HIGH**: `send_email`, `refund_api` (Defaults to score `0.80`).
* **MEDIUM**: `api_call_get` (Defaults to score `0.50`).
* **LOW**: `read_file`, `get_weather` (Defaults to score `0.20`).

#### Micro-Step B: Parameter Provenance Tracing (`provenance_tracker.py`)
Ensures that variables passed to tools are not generated by prompt injections.
1. The tool parameters are checked against the conversation history and retrieved RAG context using **Levenshtein Distance** (similarity score $> 0.85$ matches).
2. **Classification**:
   * **`EXPLICIT_USER_REQUEST`**: The parameter was directly provided in the user's input.
   * **`CONTEXT_DERIVED`**: The parameter matches clean RAG chunks.
   * **`UNCERTAIN`**: The parameter is not found in either the prompt history or retrieved context (suggesting hallucination or indirect injection). 
3. Critical tools with `UNCERTAIN` parameter sources are blocked (`AGENTIC_HIJACK`, score `0.97`).

#### Micro-Step C: Reasoning Parse Audit (`reasoning_parser.py`)
Before executing a tool, Sentinel scans the LLM's reasoning trace (its internal thoughts/chain-of-thought) for policy circumvention attempts:
* Matches patterns where the model attributes unauthorized actions to the user (`r"the user asked me to..."` without history).
* Matches overrides (`r"(override|ignore|bypass).{0,30}(policy|rule)"`).
* Matches self-authorization (`r"(authoriz|permit|allow)(ed|ing|e)?\s*.{0,30}(because|since|as|myself)"`).
If any match is found, the tool execution is blocked.

#### Micro-Step D: Tool Response Sanitizer (L4b)
Once a tool executes, its return payload is scanned by Layer 1 filters before appending it to the history, preventing prompt injections from entering the context via tool returns.

---

### Layer 5: Output Semantic Firewall (`sentinel/layers/layer5_output/`)

Layer 5 scans the output generated by the LLM before sending it to the client.

#### Micro-Step A: Canary Verification
At the start of the session, a session-specific UUID is generated:
$$\text{Canary Token} = \text{"SYSTEM\_CANARY\_"} + \text{UUID4}$$
This token is appended to the system instructions. If this exact string is found in the LLM's response, it indicates prompt leak, and the output is blocked (`Exfiltration Detected`).

#### Micro-Step B: PII Scanner (`pii_scanner.py`)
Uses regex to detect and redact sensitive data:
* SSN: `\b\d{3}-\d{2}-\d{4}\b`
* Credit Cards: `\b(?:\d[ -]*?){13,16}\b`
* Emails: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`
* API Keys: `\bsk-[a-zA-Z0-9]{12,}\b`

**Algorithm Detail (Backward Redaction)**:
To prevent index offsets from shifting when modifying the text length, Sentinel finds matches and redacts them in reverse order (from the end of the text to the beginning).

#### Micro-Step C: Prompt Exfiltration Detection (`exfil_detector.py`)
Measures if the system prompt is being leaked by comparing the output to the system prompt:
1. **Jaccard Token Overlap**:
   $$J(\text{Output}, \text{System}) = \frac{|\text{Tokens}_{\text{Output}} \cap \text{Tokens}_{\text{System}}|}{|\text{Tokens}_{\text{Output}} \cup \text{Tokens}_{\text{System}}|}$$
   If $J > 0.40$, it indicates significant text overlap.
2. **Semantic Cosine Similarity**:
   Embeds both output and system prompt. If similarity $> 0.65$, it indicates semantic prompt leakage.

#### Micro-Step D: Policy Compliance Verifier (`policy_verifier.py`)
Validates the output against policy rules defined in `sentinel_policy.yaml`:
* **Forbidden Topics**: Scans for restricted keywords (e.g., checks output for finance-related words if investment advice is disabled).
* **Required Disclaimers**: If the output references interest rates, it checks that the required disclaimer text is present.

---

## 4. The Correlation Engine (`sentinel/core/correlation_engine.py`)

A single layer might show a minor warning, but combining signals across layers can indicate an active attack. The `Correlation Engine` checks these metrics concurrently:

1. **Slow Burn Correlation**:
   $$\text{L3 Score} \ge 0.70 \quad \text{AND} \quad \text{L1 Max} \ge 0.30$$
   This indicates a slow-burn prompt injection attempt.
2. **RAG + Agent Hijack**:
   $$\text{L2 Flagged Chunks} > 0 \quad \text{AND} \quad \text{L4 Tool Score} \ge 0.70$$
   This indicates the agent is using poisoned context parameters to run critical tools.
3. **Exfiltration Probe**:
   $$(\text{L1 Score} \ge 0.50 \text{ or } \text{L3 Score} \ge 0.70) \quad \text{AND} \quad \text{L5 Exfiltration} \ge 0.50$$
   This indicates that output data is leaked after a suspicious user query.

When a correlation is found, the session's overall risk level is elevated, and the engine blocks the request with a correlation event.

---

## 5. FAQ & Mock Interview Prep

### Q1: Why do we use a local `SentenceTransformer` rather than calling OpenAI's embedding API?
* **Latency & Cost**: Remote API calls add round-trip network latency ($100\text{--}300\text{ms}$). Running the `all-MiniLM-L6-v2` model locally on CPU takes less than $15\text{ms}$ and incurs zero API costs.
* **Privacy**: User prompts and database context remain inside your local infrastructure and are not sent to third-party endpoints for evaluation.

### Q2: How does the system handle false positives on benign user requests?
* **Multi-Tier Pipeline**: Regular queries (e.g., *"What is the weather?"*) have low semantic similarity to attack templates and do not match regex signatures, so they bypass L1 filters in under $1\text{ms}$.
* **Contextual Provenance**: Tool parameters are checked against the conversation history. If a user asks the agent to run a tool with parameters they explicitly provided, the provenance is labeled `EXPLICIT_USER_REQUEST`, and the tool is allowed.

### Q3: Why is HMAC validation used for RAG chunks?
* **Database Tampering Protection**: If an attacker gains write access to your vector database (e.g., through SQL injection or weak access controls) and updates chunk text with malicious commands, they cannot generate the matching HMAC signature without the server key. The mismatch is detected immediately at retrieval time.

### Q4: How does Sentinel prevent exfiltration of system prompt instructions?
* **Double Check**: 
  1. **Canary Checking**: Sentinel checks for the presence of the session-specific canary token.
  2. **Semantic Similarity**: Sentinel measures the semantic similarity between the output and the system prompt to detect paraphrased prompt leaks.

### Q5: How is conversation history tracked on the server?
* The `/sentinel/chat` endpoint is state-aware. It stores user queries and assistant responses in the session's `chat_history` list.
* This history is sent with every subsequent LLM request, allowing the model to maintain context without leaking the canary token on follow-up questions.
