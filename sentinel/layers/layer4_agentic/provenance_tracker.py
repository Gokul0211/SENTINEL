from sentinel.layers.layer2_rag import layer2_get_chunks

def trace_parameters(parameters: dict, conversation_history: list[dict]) -> dict:
    """
    Trace where each parameter value came from.
    Returns a dict mapping param_name -> {"source": source_type, "confidence": float, "details": str}
    """
    provenance = {}
    
    # Extract all user text from history
    user_texts = [turn.get("content", "").lower() for turn in conversation_history if turn.get("role") == "user"]
    user_text_combined = " ".join(user_texts)
    
    # Get all active chunks from L2 to check if params came from RAG
    active_chunks = layer2_get_chunks()
    
    for param_name, param_value in parameters.items():
        val_str = str(param_value).lower()
        
        # 1. Check if it came directly from user input
        if val_str in user_text_combined:
            provenance[param_name] = {
                "source": "EXPLICIT_USER_REQUEST",
                "confidence": 0.95,
                "details": "Found exact match in user history"
            }
            continue
            
        # 2. Check if it came from a RAG chunk
        found_in_rag = False
        for chunk in active_chunks:
            if not chunk.get("quarantined", False) and val_str in chunk["text"].lower():
                trust = chunk["metadata"].get("trust_score", 0.5)
                provenance[param_name] = {
                    "source": "CONTEXT_DERIVED",
                    "confidence": trust,
                    "details": f"Traced to RAG chunk {chunk['chunk_id']} (trust={trust:.2f})"
                }
                found_in_rag = True
                break
                
        if found_in_rag:
            continue
            
        # 3. Uncertain / LLM Hallucinated
        provenance[param_name] = {
            "source": "UNCERTAIN",
            "confidence": 0.1,
            "details": "Could not trace value to user input or RAG context"
        }
        
    return provenance

def determine_authorization(provenance: dict) -> str:
    """Determine overall authorization source based on parameter provenances."""
    sources = [p["source"] for p in provenance.values()]
    
    if not sources:
        return "IMPLICIT_USER_INTENT" # No params
        
    if "UNCERTAIN" in sources:
        return "SUSPICIOUS"
        
    if "CONTEXT_DERIVED" in sources:
        return "CONTEXT_DERIVED"
        
    return "EXPLICIT_USER_REQUEST"
