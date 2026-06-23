"""
SENTINEL Unified App — Single FastAPI server that serves:
  - /v1/chat/completions (LLM proxy)
  - /ws/events (WebSocket for real-time dashboard)
  - /sentinel/* (REST API — sessions, events, demo triggers, reset, chat)
  - / (Dashboard UI — static files)
"""

import uuid
import json
import asyncio
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import httpx

from sentinel.config import BLOCK_THRESHOLD, WARN_THRESHOLD, LLM_BACKEND, OPENAI_API_KEY
from sentinel.core.models import ThreatEvent, score_to_severity, score_to_action
from sentinel.core.threat_bus import threat_bus
from sentinel.core.mock_layers import mock_layer_score, reset_mock_state
from sentinel.layers.layer1 import layer1_check, L1Result
from sentinel.layers.layer2_rag import layer2_ingest, layer2_validate_context, layer2_get_chunks, layer2_quarantine
from sentinel.layers.layer3 import layer3_check, L3Result, reset_layer3_state
from sentinel.layers.layer4_agentic import audit_tool_call
from sentinel.layers.layer5_output import layer5_scan_output
from sentinel.core.correlation_engine import check_correlations
from sentinel.demo_scenarios import run_scenario, SCENARIOS

app = FastAPI(title="SENTINEL", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
#  Dashboard — serve static files
# ---------------------------------------------------------------------------

@app.get("/")
async def serve_dashboard():
    """Serve the dashboard index.html."""
    return FileResponse("dashboard/static/index.html")


# Mount static files AFTER the root route
app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")


# ---------------------------------------------------------------------------
#  WebSocket — real-time event streaming
# ---------------------------------------------------------------------------

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    await websocket.accept()
    queue = threat_bus.subscribe()

    # Send current state on connect
    try:
        await websocket.send_text(json.dumps({
            "type": "STATS_UPDATE",
            "payload": threat_bus.stats,
        }))
    except Exception:
        pass

    try:
        while True:
            message = await queue.get()
            await websocket.send_text(message)
    except WebSocketDisconnect:
        threat_bus.unsubscribe(queue)
    except Exception:
        threat_bus.unsubscribe(queue)


# ---------------------------------------------------------------------------
#  Proxy — /v1/chat/completions
# ---------------------------------------------------------------------------

@app.post("/v1/chat/completions")
async def proxy_completions(request: Request):
    """
    OpenAI-compatible proxy endpoint.
    Intercepts, analyzes, and optionally blocks LLM requests.
    """
    body = await request.json()
    session_id = request.headers.get("X-Session-Id", str(uuid.uuid4()))
    messages = body.get("messages", [])
    user_input = next(
        (m["content"] for m in reversed(messages) if m["role"] == "user"),
        "",
    )

    # Run real checks
    l1_result = await layer1_check(user_input)
    l3_result = await layer3_check(session_id, user_input)

    # Mock other layers
    l2_score = mock_layer_score("L2", session_id)
    l4_score = mock_layer_score("L4", session_id)
    l5_score = mock_layer_score("L5", session_id)

    # Combine — L1 and L3 are real, others are mock weight
    combined_score = max(l1_result.score, l3_result.score)
    severity = score_to_severity(combined_score)
    action = score_to_action(combined_score, BLOCK_THRESHOLD, WARN_THRESHOLD)

    # Build reason
    reason = l1_result.reason if l1_result.score >= l3_result.score else l3_result.reason

    # Build rich explainability chain
    chain = []
    if l1_result.score > 0.1:
        chain.append({
            "layer": "L1",
            "severity": score_to_severity(l1_result.score),
            "finding": f"Input Scanner ({('Tier 1 regex' if l1_result.tier_used == 1 else 'Tier 2 semantic')}): {l1_result.threat_class}",
            "evidence": l1_result.reason,
            "action": "BLOCK" if l1_result.score >= BLOCK_THRESHOLD else ("WARN" if l1_result.score >= WARN_THRESHOLD else "ALLOW"),
        })
    if l3_result.score > 0.1:
        chain.append({
            "layer": "L3",
            "severity": score_to_severity(l3_result.score),
            "finding": f"Drift Tracker: velocity={l3_result.semantic_velocity:.3f}, drift={l3_result.cumulative_drift:.3f}, turn={l3_result.turn_count}",
            "evidence": l3_result.reason,
            "action": "BLOCK" if l3_result.score >= BLOCK_THRESHOLD else ("WARN" if l3_result.score >= WARN_THRESHOLD else "ALLOW"),
        })
    # Add mock layer context
    chain.append({
        "layer": "L2",
        "severity": score_to_severity(l2_score),
        "finding": f"RAG Integrity (simulated): instruction_density={l2_score:.3f}",
        "evidence": "Mock score — L2 not fully implemented",
        "action": "MONITOR",
    })
    if action == "BLOCKED":
        chain.append({
            "layer": "TIB",
            "severity": "CRITICAL",
            "finding": f"Threat Intelligence Bus: score={combined_score:.3f} exceeded block threshold ({BLOCK_THRESHOLD})",
            "evidence": f"Dominant signal: {'L1' if l1_result.score >= l3_result.score else 'L3'}",
            "action": "BLOCK_REQUEST + TERMINATE_SESSION",
        })

    # Emit event
    event = ThreatEvent(
        event_id=f"evt_{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now().strftime("%H:%M:%S"),
        session_id=session_id,
        layer="L1" if l1_result.score >= l3_result.score else "L3",
        threat_type=l1_result.threat_class if l1_result.score >= l3_result.score else "DRIFT",
        severity=severity,
        threat_score=combined_score,
        action=action,
        evidence={
            "l1": l1_result.to_dict(),
            "l3": l3_result.to_dict(),
            "l2_mock": getattr(session, 'l2_findings', []),
            "l4_mock": getattr(session, 'l4_calls', []),
            "l5_mock": getattr(session, 'l5_scores', []),
        },
        explanation={
            "summary": reason,
            "chain": chain,
        },
        turn=l3_result.turn_count,
        note=reason[:60],
    )
    await threat_bus.emit(event)
    
    # Run cross-layer correlation
    await check_correlations(session_id)

    if action == "BLOCKED":
        return Response(
            content=json.dumps({
                "error": f"Request blocked by SENTINEL. Reason: {reason}",
                "threat_score": combined_score,
                "severity": severity,
            }),
            status_code=403,
            media_type="application/json",
            headers={
                "X-Sentinel-Risk-Level": severity,
                "X-Sentinel-Threat-Score": str(combined_score),
                "X-Sentinel-Request-ID": event.event_id,
            },
        )

    # Forward to real LLM backend (or return canned response in demo mode)
    if not OPENAI_API_KEY:
        # Demo mode — no real LLM backend
        return Response(
            content=json.dumps({
                "choices": [{
                    "message": {"role": "assistant", "content": "This is a demo response. Configure OPENAI_API_KEY to forward to a real LLM."},
                    "index": 0,
                    "finish_reason": "stop",
                }],
                "model": "sentinel-demo",
            }),
            media_type="application/json",
            headers={
                "X-Sentinel-Risk-Level": severity,
                "X-Sentinel-Threat-Score": str(combined_score),
                "X-Sentinel-Request-ID": event.event_id,
            },
        )

    # Forward to real LLM
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            LLM_BACKEND,
            json=body,
            headers={
                "Authorization": request.headers.get("Authorization", f"Bearer {OPENAI_API_KEY}"),
                "Content-Type": "application/json",
            },
        )
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type="application/json",
            headers={
                "X-Sentinel-Risk-Level": severity,
                "X-Sentinel-Threat-Score": str(combined_score),
                "X-Sentinel-Request-ID": event.event_id,
            },
        )


# ---------------------------------------------------------------------------
#  REST API — /sentinel/*
# ---------------------------------------------------------------------------

@app.get("/sentinel/sessions")
async def list_sessions():
    """Return list of active session summaries."""
    return [
        {
            "session_id": s.session_id,
            "risk": s.risk,
            "overall": s.overall,
            "turn_count": len(s.turns),
        }
        for s in threat_bus.sessions.values()
    ]


@app.get("/sentinel/sessions/{session_id}")
async def get_session(session_id: str):
    """Return full session detail: turns, scores, events."""
    session = threat_bus.sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.to_dict()


@app.get("/sentinel/events")
async def get_events(severity: str = None, limit: int = 50):
    """Return filtered event log."""
    events = threat_bus.events[-limit:]
    if severity:
        events = [e for e in events if e.severity == severity]
    return [e.to_dict() for e in events]


@app.post("/sentinel/demo/{scenario_id}")
async def trigger_demo(scenario_id: str, background_tasks: BackgroundTasks):
    """Trigger a demo attack scenario."""
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {scenario_id}")

    async def _chat_broadcast(msg):
        """Broadcast a chat message to all WebSocket clients."""
        payload = json.dumps({"type": "CHAT_MESSAGE", "payload": msg})
        await threat_bus._broadcast(payload)

    background_tasks.add_task(run_scenario, scenario_id, _chat_broadcast)
    return {
        "status": "started",
        "scenario": scenario_id,
        "name": SCENARIOS[scenario_id]["name"],
    }


@app.post("/sentinel/reset")
async def reset():
    """Clear all state — reset dashboard to zero."""
    threat_bus.reset()
    reset_mock_state()
    reset_layer3_state()

    # Broadcast reset to all clients
    payload = json.dumps({
        "type": "RESET",
        "payload": threat_bus.stats,
    })
    await threat_bus._broadcast(payload)

    return {"status": "reset"}


@app.post("/sentinel/chat")
async def chat_send(request: Request):
    """
    Interceptor chat endpoint — sends user message through the proxy pipeline
    and returns the result (or block notice).
    """
    body = await request.json()
    user_input = body.get("content", "")
    session_id = body.get("session_id", str(uuid.uuid4()))

    # Run L1 + L3
    l1_result = await layer1_check(user_input)
    l3_result = await layer3_check(session_id, user_input)
    combined_score = max(l1_result.score, l3_result.score)
    severity = score_to_severity(combined_score)
    action = score_to_action(combined_score, BLOCK_THRESHOLD, WARN_THRESHOLD)
    reason = l1_result.reason if l1_result.score >= l3_result.score else l3_result.reason

    # Build rich explainability chain
    chain = []
    if l1_result.score > 0.1:
        chain.append({
            "layer": "L1",
            "severity": score_to_severity(l1_result.score),
            "finding": f"Input Scanner ({'Tier 1 regex' if l1_result.tier_used == 1 else 'Tier 2 semantic'}): {l1_result.threat_class}",
            "evidence": l1_result.reason,
            "action": "BLOCK" if l1_result.score >= BLOCK_THRESHOLD else ("WARN" if l1_result.score >= WARN_THRESHOLD else "ALLOW"),
        })
    if l3_result.score > 0.1:
        chain.append({
            "layer": "L3",
            "severity": score_to_severity(l3_result.score),
            "finding": f"Drift Tracker: velocity={l3_result.semantic_velocity:.3f}, drift={l3_result.cumulative_drift:.3f}, turn={l3_result.turn_count}",
            "evidence": l3_result.reason,
            "action": "BLOCK" if l3_result.score >= BLOCK_THRESHOLD else ("WARN" if l3_result.score >= WARN_THRESHOLD else "ALLOW"),
        })
    if action == "BLOCKED":
        chain.append({
            "layer": "TIB",
            "severity": "CRITICAL",
            "finding": f"Threat Intelligence Bus: score={combined_score:.3f} exceeded block threshold ({BLOCK_THRESHOLD})",
            "evidence": f"Dominant signal: {'L1' if l1_result.score >= l3_result.score else 'L3'}",
            "action": "BLOCK_REQUEST + TERMINATE_SESSION",
        })

    # Emit event
    event = ThreatEvent(
        event_id=f"evt_{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now().strftime("%H:%M:%S"),
        session_id=session_id,
        layer="L1" if l1_result.score >= l3_result.score else "L3",
        threat_type=l1_result.threat_class if l1_result.score >= l3_result.score else "DRIFT",
        severity=severity,
        threat_score=combined_score,
        action=action,
        evidence={"l1": l1_result.to_dict(), "l3": l3_result.to_dict()},
        explanation={"summary": reason, "chain": chain},
        turn=l3_result.turn_count,
        note=reason[:60],
    )
    await threat_bus.emit(event)
    
    # Run correlation check on input
    await check_correlations(session_id)

    blocked = action == "BLOCKED"
    
    if blocked:
        return {
            "session_id": session_id,
            "blocked": True,
            "response": "I can't help with that — request terminated by SENTINEL.",
            "threat_score": combined_score,
            "severity": severity,
            "action": action,
            "explanation": {"summary": reason, "chain": chain},
        }

    # If allowed, simulate LLM processing and run Layer 5 Output Scan
    # (In a real proxy, we'd call the LLM here)
    llm_response = f"Simulated LLM response for: {user_input}"
    
    # L5 Output Scan
    l5_result, sanitized_response = await layer5_scan_output(
        response_text=llm_response,
        system_prompt=None,  # Replace with actual system prompt
        session_id=session_id
    )
    
    session = await threat_bus.get_session(session_id)
    if not hasattr(session, 'l5_scores'):
        session.l5_scores = []
    session.l5_scores.append(l5_result.score)
    
    if l5_result.score >= BLOCK_THRESHOLD:
        l5_severity = score_to_severity(l5_result.score)
        
        # Emit L5 block event
        l5_event = ThreatEvent(
            event_id=f"evt_{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now().strftime("%H:%M:%S"),
            session_id=session_id,
            layer="L5",
            threat_type=l5_result.threat_class,
            severity=l5_severity,
            threat_score=l5_result.score,
            action="BLOCKED",
            evidence={"l5": l5_result.to_dict()},
            explanation={"summary": l5_result.reason, "chain": [{
                "layer": "L5",
                "severity": l5_severity,
                "finding": f"Output Firewall: {l5_result.threat_class}",
                "evidence": l5_result.reason,
                "action": "BLOCK"
            }]},
            note=l5_result.reason[:60],
        )
        await threat_bus.emit(l5_event)
        await check_correlations(session_id)
        
        return {
            "session_id": session_id,
            "blocked": True,
            "response": "[REDACTED BY SENTINEL LAYER 5]",
            "threat_score": l5_result.score,
            "severity": l5_severity,
            "action": "BLOCKED",
            "explanation": {"summary": l5_result.reason, "chain": l5_event.explanation["chain"]},
        }

    return {
        "session_id": session_id,
        "blocked": False,
        "response": sanitized_response,
        "threat_score": combined_score,
        "severity": severity,
        "action": action,
        "explanation": {"summary": reason, "chain": chain},
    }

# --- Layer 2 / RAG Endpoints ---

@app.post("/sentinel/rag/ingest")
async def rag_ingest(request: Request):
    body = await request.json()
    text = body.get("text", "")
    source = body.get("source", "api")
    
    result = await layer2_ingest(text, source)
    return result

@app.get("/sentinel/rag/chunks")
async def list_chunks():
    chunks = layer2_get_chunks()
    return {"chunks": chunks}

@app.post("/sentinel/rag/quarantine/{chunk_id}")
async def quarantine_chunk(chunk_id: str):
    success = layer2_quarantine(chunk_id)
    return {"success": success}

# --- Layer 4 / Agentic Endpoints ---

@app.post("/sentinel/agent/tool_call")
async def intercept_tool_call(request: Request):
    body = await request.json()
    tool_name = body.get("tool_name", "")
    parameters = body.get("parameters", {})
    reasoning_trace = body.get("reasoning_trace", "")
    session_id = body.get("session_id", str(uuid.uuid4()))
    history = body.get("history", [])
    
    result = await audit_tool_call(tool_name, parameters, reasoning_trace, session_id, history)
    
    session = await threat_bus.get_session(session_id)
    if not hasattr(session, 'l4_calls'):
        session.l4_calls = []
    session.l4_calls.append(result.to_dict())
    
    # Emit event if high risk
    if result.score >= 0.7:
        event = ThreatEvent(
            event_id=f"evt_{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now().strftime("%H:%M:%S"),
            session_id=session_id,
            layer="L4",
            threat_type=result.threat_class,
            severity=score_to_severity(result.score),
            threat_score=result.score,
            action="BLOCKED" if not result.should_execute else "WARNED",
            evidence={"l4": result.to_dict()},
            explanation={"summary": result.reason, "chain": [{
                "layer": "L4",
                "severity": score_to_severity(result.score),
                "finding": f"Agentic Auditor: {result.threat_class}",
                "evidence": result.reason,
                "action": "BLOCK" if not result.should_execute else "WARN"
            }]},
            note=result.reason[:60],
        )
        await threat_bus.emit(event)
        await check_correlations(session_id)
        
    return result.to_dict()

# --- Layer 5 / Output Endpoints ---

@app.post("/sentinel/output/scan")
async def scan_output(request: Request):
    body = await request.json()
    response_text = body.get("response", "")
    system_prompt = body.get("system_prompt", "")
    session_id = body.get("session_id", str(uuid.uuid4()))
    
    result, sanitized = await layer5_scan_output(response_text, system_prompt, session_id)
    return {
        "result": result.to_dict(),
        "sanitized_response": sanitized
    }
