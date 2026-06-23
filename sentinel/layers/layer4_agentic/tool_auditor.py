from sentinel.core.models import L4Result
from .risk_matrix import evaluate_tool_risk, risk_to_score
from .provenance_tracker import trace_parameters, determine_authorization
from .reasoning_parser import parse_reasoning

async def audit_tool_call(
    tool_name: str,
    parameters: dict,
    reasoning_trace: str | None,
    session_id: str,
    conversation_history: list[dict],
) -> L4Result:
    """
    Main entry point for Layer 4. Audits a tool call before execution.
    """
    # 1. Base Risk Evaluation
    risk_level = evaluate_tool_risk(tool_name, parameters)
    base_score = risk_to_score(risk_level)
    
    # 2. Parameter Provenance
    provenance = trace_parameters(parameters, conversation_history)
    auth_source = determine_authorization(provenance)
    
    # 3. Reasoning Analysis
    reasoning_flags = parse_reasoning(reasoning_trace)
    
    # Calculate final score and decision
    final_score = base_score
    should_execute = True
    reasons = []
    
    if auth_source == "SUSPICIOUS":
        final_score = max(final_score, 0.9)
        reasons.append("Unverified parameter provenance (possible hallucination/injection)")
        if risk_level in ["HIGH", "CRITICAL"]:
            should_execute = False
            
    if auth_source == "CONTEXT_DERIVED":
        final_score = max(final_score, 0.7)
        # We don't auto-block context derived, but we flag it for correlation engine
        reasons.append("Parameters derived from retrieved context")
        
    if reasoning_flags:
        final_score = max(final_score, 0.8)
        reasons.extend(reasoning_flags)
        
    threat_class = "CLEAN"
    if not should_execute:
        threat_class = "AGENTIC_HIJACK"
    elif final_score >= 0.7:
        threat_class = "SUSPICIOUS_TOOL_CALL"
        
    reason_str = " | ".join(reasons) if reasons else f"Authorized via {auth_source}"
    
    return L4Result(
        score=final_score,
        threat_class=threat_class,
        authorization_source=auth_source,
        risk_level=risk_level,
        should_execute=should_execute,
        reason=reason_str
    )
