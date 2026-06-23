import uuid
from .provenance import sign_chunk, verify_chunk
from .instruction_density import calculate_instruction_density
from sentinel.layers.layer1 import layer1_check

# In-memory simple store for hackathon (fallback since ChromaDB failed to compile)
collection = {}
quarantine_store = {}

async def ingest_chunk(text: str, source: str) -> dict:
    """
    Ingest a chunk into the RAG vector store.
    Runs L1 scan, calculates instruction density, assigns trust score, and signs it.
    """
    chunk_id = f"chk_{uuid.uuid4().hex[:8]}"
    
    # 1. Run L1 Scan
    l1_result = await layer1_check(text)
    
    # 2. Calculate instruction density
    density_score = calculate_instruction_density(text)
    
    # 3. Calculate Trust Score
    l1_penalty = l1_result.score
    density_penalty = density_score if density_score > 0.4 else 0.0
    
    trust_score = max(0.0, 1.0 - max(l1_penalty, density_penalty))
    
    # 4. Sign chunk for provenance
    signature = sign_chunk(chunk_id, text)
    
    metadata = {
        "source": source,
        "trust_score": trust_score,
        "instruction_density": density_score,
        "l1_score": l1_result.score,
        "signature": signature
    }
    
    result = {
        "chunk_id": chunk_id,
        "text": text,
        "metadata": metadata,
        "quarantined": False,
        "reason": "Ingested successfully"
    }
    
    # Quarantine low trust chunks
    if trust_score < 0.5:
        quarantine_store[chunk_id] = result
        result["quarantined"] = True
        result["reason"] = f"Quarantined due to low trust score: {trust_score:.2f} (L1: {l1_penalty:.2f}, Density: {density_penalty:.2f})"
        return result
        
    # Add to active collection
    collection[chunk_id] = result
    return result

def get_all_chunks() -> list:
    """Return all active and quarantined chunks for the dashboard."""
    active_chunks = list(collection.values())
    q_chunks = list(quarantine_store.values())
    return active_chunks + q_chunks

def quarantine_chunk(chunk_id: str) -> bool:
    """Manually move a chunk to quarantine."""
    if chunk_id in collection:
        chunk = collection.pop(chunk_id)
        chunk["quarantined"] = True
        chunk["reason"] = "Manually quarantined"
        quarantine_store[chunk_id] = chunk
        return True
    return False
        
def retrieve_and_validate(query: str, top_k: int = 3) -> list:
    """Retrieve chunks for a query and validate their integrity."""
    # Since we dropped ChromaDB, we just return the first few active chunks for the demo
    results = list(collection.values())[:top_k]
    
    validated_chunks = []
    
    for chunk_data in results:
        chunk_id = chunk_data["chunk_id"]
        text = chunk_data["text"]
        metadata = chunk_data["metadata"]
        
        # Verify HMAC signature
        is_valid = verify_chunk(chunk_id, text, metadata.get("signature", ""))
        
        # Re-check instruction density
        density = calculate_instruction_density(text)
        
        findings = []
        if not is_valid:
            findings.append("HMAC signature mismatch - possible tampering")
        if density > 0.6:
            findings.append(f"High instruction density detected: {density:.2f}")
            
        validated_chunks.append({
            "chunk_id": chunk_id,
            "text": text,
            "metadata": metadata,
            "is_valid": is_valid,
            "current_density": density,
            "findings": findings
        })
        
    return validated_chunks
