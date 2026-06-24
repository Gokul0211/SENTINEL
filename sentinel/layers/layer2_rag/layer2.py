from sentinel.core.models import L2Result
from .chunk_store import ingest_chunk, get_all_chunks, quarantine_chunk, retrieve_and_validate, reset_store

async def layer2_ingest(text: str, source: str) -> dict:
    """
    Public interface to ingest a document chunk.
    """
    return await ingest_chunk(text, source)

async def layer2_validate_context(query: str) -> L2Result:
    """
    Retrieve chunks for a query and validate them.
    Returns an L2Result summarizing any threats found in the retrieved context.
    """
    validated_chunks = retrieve_and_validate(query)
    
    max_score = 0.0
    threat_class = "CLEAN"
    reason = "Context validated successfully."
    all_findings = []
    
    for chunk in validated_chunks:
        chunk_score = 0.0
        
        if not chunk["is_valid"]:
            chunk_score = 1.0
            threat_class = "KNOWLEDGE_POISONING"
            reason = f"HMAC validation failed for chunk {chunk['chunk_id']}"
            all_findings.append(reason)
            
        elif chunk["current_density"] > 0.6:
            chunk_score = chunk["current_density"]
            if chunk_score > max_score:
                threat_class = "INSTRUCTIONAL_CHUNK"
                reason = f"High instruction density ({chunk_score:.2f}) in chunk {chunk['chunk_id']}"
            all_findings.append(f"Chunk {chunk['chunk_id']} density: {chunk_score:.2f}")
            
        max_score = max(max_score, chunk_score)
        
    return L2Result(
        score=max_score,
        threat_class=threat_class,
        confidence=0.85 if max_score > 0 else 0.0,
        reason=reason,
        quarantined=False
    ), validated_chunks

def layer2_get_chunks() -> list:
    """Get all active and quarantined chunks."""
    return get_all_chunks()

def layer2_quarantine(chunk_id: str) -> bool:
    """Manually quarantine a chunk."""
    return quarantine_chunk(chunk_id)

def layer2_reset() -> None:
    """Clear all RAG chunk stores. Called on /sentinel/reset."""
    reset_store()
