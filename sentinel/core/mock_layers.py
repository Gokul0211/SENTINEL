"""
SENTINEL Mock Layers — Generates plausible fake scores for L2, L4, L5.

These layers are not implemented in the MVP but emit realistic scores
so the dashboard heatmap looks complete. Scores are capped at 0.45
to ensure mocks never trigger a block decision.
"""

import random
import math

# Per-session mock state for consistent score drift
_mock_state: dict[str, dict] = {}


def mock_layer_score(layer: str, session_id: str) -> float:
    """
    Return a plausible mock score for L2, L4, or L5.

    Scores drift upward slightly as the session continues,
    simulating realistic analyzer behavior. Capped at 0.45
    so mock layers never trigger blocking.
    """
    if session_id not in _mock_state:
        _mock_state[session_id] = {
            "L2": random.uniform(0.05, 0.20),
            "L4": random.uniform(0.05, 0.15),
            "L5": random.uniform(0.03, 0.12),
            "turn_count": 0,
        }

    state = _mock_state[session_id]
    state["turn_count"] += 1

    base = state.get(layer, 0.1)
    # Small random drift each turn
    drift = random.uniform(-0.02, 0.05) * math.log1p(state["turn_count"])
    score = max(0.0, min(base + drift, 0.45))
    state[layer] = score
    return round(score, 3)


def reset_mock_state():
    """Clear all mock state — called on demo reset."""
    _mock_state.clear()
