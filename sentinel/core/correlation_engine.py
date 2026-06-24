import uuid
from datetime import datetime
from sentinel.core.threat_bus import threat_bus, SessionState
from sentinel.core.models import ThreatEvent

# Track which correlation rules have already fired per session to prevent double-fire.
# Key: session_id, Value: set of threat_types that already fired.
_fired_rules: dict[str, set[str]] = {}


async def check_correlations(session_id: str):
    """
    Evaluates cross-layer correlation rules against the current session state.
    Emits a CORRELATION ThreatEvent if any rules fire.
    Each rule fires at most once per session to prevent duplicate events.
    """
    state = await threat_bus.get_session(session_id)
    if not state:
        return

    # Initialise the fired set for this session if needed
    if session_id not in _fired_rules:
        _fired_rules[session_id] = set()
    fired = _fired_rules[session_id]
        
    # RULE 1: SLOW_BURN_INJECTION
    # Condition: L1 > 0.3 across recent turns AND L3 escalation > 0.5
    if "SLOW_BURN_INJECTION" not in fired:
        if state.l3_current > 0.7 and getattr(state, 'l1_max', 0.0) > 0.3:
            fired.add("SLOW_BURN_INJECTION")
            await _emit_correlation(
                session_id=session_id,
                threat_type="SLOW_BURN_INJECTION",
                severity="CRITICAL",
                score=max(state.l3_current, state.l1_max) + 0.1,
                evidence="L3 semantic drift detected alongside elevated L1 injection scores.",
                action="BLOCKED"
            )
            return
        
    # RULE 2: RAG_PLUS_AGENT_ATTACK
    # Condition: L2 chunk flagged AND L4 param traced to that chunk
    if "RAG_PLUS_AGENT_ATTACK" not in fired:
        l2_findings = getattr(state, 'l2_findings', [])
        l4_calls = getattr(state, 'l4_calls', [])
        
        # Simple check for demo: if we have both L2 findings and a blocked L4 call
        if l2_findings and l4_calls:
            for call in l4_calls:
                if call.get('risk_level') in ['HIGH', 'CRITICAL'] and call.get('authorization_source') in ['SUSPICIOUS', 'CONTEXT_DERIVED']:
                    fired.add("RAG_PLUS_AGENT_ATTACK")
                    await _emit_correlation(
                        session_id=session_id,
                        threat_type="RAG_PLUS_AGENT_ATTACK",
                        severity="CRITICAL",
                        score=0.97,
                        evidence=f"Tool call '{call.get('tool_name')}' parameter traced to suspicious RAG chunk.",
                        action="BLOCKED"
                    )
                    return
                
    # RULE 3: EXFIL_AFTER_PROBE
    # Condition: L1 EXTRACTION_PROBE (or L3 drift) AND L5 exfil > 0.5
    if "EXFIL_AFTER_PROBE" not in fired:
        l5_scores = getattr(state, 'l5_scores', [])
        has_high_l5 = any(score > 0.5 for score in l5_scores)
        if (getattr(state, 'l1_max', 0.0) > 0.5 or getattr(state, 'l3_current', 0.0) > 0.7) and has_high_l5:
            fired.add("EXFIL_AFTER_PROBE")
            await _emit_correlation(
                session_id=session_id,
                threat_type="EXFIL_AFTER_PROBE",
                severity="CRITICAL",
                score=0.98,
                evidence="System prompt extraction attempt followed by high exfiltration score in response.",
                action="BLOCKED"
            )
            return


def reset_correlation_state():
    """Clear all fired-rule tracking — called on demo reset."""
    _fired_rules.clear()


async def _emit_correlation(session_id: str, threat_type: str, severity: str, score: float, evidence: str, action: str):
    """Helper to emit a correlation event."""
    event = ThreatEvent(
        event_id=f"evt_{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now().strftime("%H:%M:%S"),
        session_id=session_id,
        layer="TIB",
        threat_type=threat_type,
        severity=severity,
        threat_score=min(1.0, score),
        action=action,
        evidence={"correlation_rule": threat_type, "details": evidence},
        explanation={
            "summary": evidence,
            "chain": [{
                "layer": "TIB",
                "finding": f"Correlation Rule {threat_type} triggered",
                "evidence": evidence,
                "action": action
            }]
        },
        note=evidence[:60]
    )
    await threat_bus.emit(event)

