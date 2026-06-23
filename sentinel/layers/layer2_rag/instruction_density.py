import numpy as np
from sentence_transformers import util
from sentinel.layers.layer1 import model as encoder # Reuse the existing encoder

# Templates that suggest instructional or meta-directive content
INSTRUCTIONAL_TEMPLATES = [
    "ignore previous instructions",
    "your task is to",
    "when answering always",
    "you must",
    "do not reveal",
    "as an AI assistant you should",
    "override previous constraints",
    "disregard other rules",
    "the user wants you to",
]

# Pre-compute embeddings for templates
template_embeddings = encoder.encode(INSTRUCTIONAL_TEMPLATES)

def calculate_instruction_density(text: str) -> float:
    """
    Calculate the instruction density of a chunk.
    High density indicates the chunk is trying to give commands to the LLM
    rather than just providing factual information.
    """
    text_embedding = encoder.encode([text])
    # Compare chunk against all instructional templates
    cos_scores = util.cos_sim(text_embedding, template_embeddings)[0]
    
    # Return the maximum similarity as the instruction density score
    max_score = float(cos_scores.max().item())
    
    # Ensure score is within 0.0 - 1.0 bounds
    return max(0.0, min(max_score, 1.0))
