import re
import numpy as np
from sentence_transformers import util
from sentinel.layers.layer1 import encoder

EXFILTRATION_PATTERNS = [
    r"my instructions say",
    r"i was told to",
    r"my system prompt",
    r"i have been instructed",
    r"here are my instructions",
]

def jaccard_similarity(str1: str, str2: str) -> float:
    """Compute token-level overlap."""
    a = set(str1.lower().split())
    b = set(str2.lower().split())
    if not a or not b:
        return 0.0
    c = a.intersection(b)
    return float(len(c)) / (len(a) + len(b) - len(c))

def detect_exfiltration(response: str, system_prompt: str | None) -> tuple[float, list[str]]:
    """
    Detect if the response leaks the system prompt.
    Returns: (exfil_score, list of evidence)
    """
    if not response:
        return 0.0, []
        
    evidence = []
    
    # 1. Structural pattern check
    structural_matches = []
    for pattern in EXFILTRATION_PATTERNS:
        if re.search(pattern, response, re.IGNORECASE):
            structural_matches.append(pattern)
            
    if structural_matches:
        evidence.append("Found structural markers indicating rule disclosure")
        
    semantic_overlap = 0.0
    token_overlap = 0.0
    
    if system_prompt:
        # 2. Semantic overlap
        resp_emb = encoder.encode(response)
        sys_emb = encoder.encode(system_prompt)
        semantic_overlap = float(util.cos_sim(resp_emb, sys_emb)[0][0])
        
        if semantic_overlap > 0.65:
            evidence.append(f"High semantic overlap with system prompt ({semantic_overlap:.2f})")
            
        # 3. Token overlap
        token_overlap = jaccard_similarity(response, system_prompt)
        if token_overlap > 0.40:
            evidence.append(f"High token overlap with system prompt ({token_overlap:.2f})")
            
    score = max(
        semantic_overlap * 0.4,
        token_overlap * 0.8,
        0.9 if structural_matches else 0.0
    )
    
    return min(1.0, score), evidence
