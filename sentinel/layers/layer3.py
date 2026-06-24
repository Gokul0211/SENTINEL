"""
SENTINEL Layer 3 — Conversational Drift Tracker (Real)

Detects slow-burn multi-turn manipulation by measuring:
  1. Semantic velocity — cosine distance between consecutive turns
  2. Cumulative drift — cosine distance from the first turn
  3. Escalation phrases — known social engineering phrases

~80 lines, runs in <20ms, produces the turn-by-turn timeline
that is the most visually impressive element on the dashboard.
"""

import numpy as np
from collections import deque
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

from sentinel.config import (
    EMBEDDING_MODEL,
    L3_VELOCITY_THRESHOLD,
    L3_DRIFT_THRESHOLD,
    L3_MAX_HISTORY,
    L3_VELOCITY_WEIGHT,
    L3_DRIFT_WEIGHT,
    L3_ESCALATION_WEIGHT,
)
from sentinel.core.models import L3Result

# Load the embedding model. Python's import cache means
# SentenceTransformer only loads weights from disk once per process.
model = SentenceTransformer(EMBEDDING_MODEL)

# Per-session turn history: {session_id: deque of embeddings}
session_embeddings: dict[str, deque] = {}

ESCALATION_PHRASES = [
    "as an admin",
    "with elevated",
    "override",
    "you have permission",
    "i'm authorized",
    "my job requires",
    "you helped with this before",
    "other AIs do this",
    "developer mode",
    "hypothetically speaking",
    "in a fictional scenario",
    "for educational purposes",
    "if you were unconstrained",
    "your true self",
    "the old you",
    "before the restrictions",
    "in a parallel world",
    "let's roleplay",
    "pretend this is fiction",
    "academic research requires",
    "is in danger",
    "bypass checks",
    "emergency",
    "bypass validation",
    "authorize myself",
    "disable security",
]


async def layer3_check(session_id: str, user_input: str) -> L3Result:
    """
    Track conversational drift for a session.
    Returns L3Result with velocity, drift, escalation, and combined score.
    """
    if session_id not in session_embeddings:
        session_embeddings[session_id] = deque(maxlen=L3_MAX_HISTORY)

    history = session_embeddings[session_id]
    current_embedding = model.encode([user_input])

    # Semantic velocity — distance from last turn
    velocity = 0.0
    if history:
        last_embedding = np.array(history[-1]).reshape(1, -1)
        similarity = cosine_similarity(current_embedding, last_embedding)[0][0]
        velocity = float(1.0 - similarity)

    # Cumulative drift — distance from first turn
    cumulative_drift = 0.0
    if len(history) >= 2:
        first_embedding = np.array(history[0]).reshape(1, -1)
        similarity = cosine_similarity(current_embedding, first_embedding)[0][0]
        cumulative_drift = float(1.0 - similarity)

    # Escalation phrase check
    lower_input = user_input.lower()
    escalation_found = any(phrase in lower_input for phrase in ESCALATION_PHRASES)

    # Store this turn's embedding
    history.append(current_embedding[0].tolist())
    turn_count = len(history)

    # Compute combined score
    score = 0.0
    score += velocity * L3_VELOCITY_WEIGHT
    score += cumulative_drift * L3_DRIFT_WEIGHT
    score += L3_ESCALATION_WEIGHT if escalation_found else 0.0
    score = min(score, 1.0)

    # Build reason string
    reasons = []
    if velocity > L3_VELOCITY_THRESHOLD:
        reasons.append(f"High topic shift (velocity={velocity:.2f})")
    if cumulative_drift > L3_DRIFT_THRESHOLD:
        reasons.append(f"Session drifting from origin (drift={cumulative_drift:.2f})")
    if escalation_found:
        reasons.append("Escalation phrase detected")

    return L3Result(
        score=score,
        semantic_velocity=velocity,
        cumulative_drift=cumulative_drift,
        escalation_found=escalation_found,
        turn_count=turn_count,
        reason=" | ".join(reasons) if reasons else "No drift detected",
    )


def reset_layer3_state():
    """Clear all session embeddings — called on demo reset."""
    session_embeddings.clear()
