"""
SENTINEL Threat Intelligence Bus — In-memory event store and WebSocket broadcaster.

Holds all session state, threat events, and live statistics.
Broadcasts to all connected WebSocket clients in real time.
"""

import asyncio
import json
from sentinel.core.models import ThreatEvent, SessionState, Turn, score_to_severity


class ThreatBus:
    """Central in-memory threat intelligence bus."""

    def __init__(self):
        self.sessions: dict[str, SessionState] = {}
        self.events: list[ThreatEvent] = []
        self.clients: set[asyncio.Queue] = set()
        self.stats = {
            "active_sessions": 0,
            "blocked": 0,
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "layer_scores": {"L1": 0.0, "L2": 0.0, "L3": 0.0, "L4": 0.0, "L5": 0.0},
        }

    def get_or_create_session(self, session_id: str) -> SessionState:
        """Get existing session or create a new one."""
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(session_id=session_id)
            self.stats["active_sessions"] = len(self.sessions)
        return self.sessions[session_id]

    async def get_session(self, session_id: str) -> SessionState:
        """Async wrapper for get_or_create_session to support awaiting it."""
        return self.get_or_create_session(session_id)

    async def emit(self, event: ThreatEvent):
        """Process and broadcast a threat event to all connected clients."""
        self.events.append(event)

        # Update session state
        session = self.get_or_create_session(event.session_id)
        session.events.append(event)
        session.overall = max(session.overall, event.threat_score)
        session.risk = score_to_severity(session.overall)

        # Update L1/L3 max scores on session
        if event.layer == "L1":
            session.l1_max = max(session.l1_max, event.threat_score)
        elif event.layer == "L3":
            session.l3_current = event.threat_score

        # Add turn data if present
        if event.turn is not None:
            turn = Turn(
                turn_number=event.turn,
                score=event.threat_score,
                severity=event.severity,
                note=event.note or "",
                layer=event.layer,
            )
            session.turns.append(turn)

        # Update global stats
        if event.action == "BLOCKED":
            self.stats["blocked"] += 1
        if event.severity in self.stats["counts"]:
            self.stats["counts"][event.severity] += 1

        # Update layer max scores
        layer = event.layer
        if layer in self.stats["layer_scores"]:
            self.stats["layer_scores"][layer] = max(
                self.stats["layer_scores"].get(layer, 0.0),
                event.threat_score,
            )

        self.stats["active_sessions"] = len(self.sessions)

        # Broadcast THREAT_EVENT to all WebSocket clients
        event_payload = json.dumps({
            "type": "THREAT_EVENT",
            "payload": event.to_dict(),
        })
        await self._broadcast(event_payload)

        # Broadcast SESSION_UPDATE
        session_payload = json.dumps({
            "type": "SESSION_UPDATE",
            "payload": session.to_dict(),
        })
        await self._broadcast(session_payload)

        # Broadcast STATS_UPDATE
        stats_payload = json.dumps({
            "type": "STATS_UPDATE",
            "payload": self.stats,
        })
        await self._broadcast(stats_payload)

    async def _broadcast(self, message: str):
        """Send a message to all connected WebSocket clients."""
        dead_clients = []
        for q in list(self.clients):
            try:
                await q.put(message)
            except Exception:
                dead_clients.append(q)
        for q in dead_clients:
            self.clients.discard(q)

    def subscribe(self) -> asyncio.Queue:
        """Register a new WebSocket client. Returns a Queue to receive messages."""
        q = asyncio.Queue()
        self.clients.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        """Unregister a WebSocket client."""
        self.clients.discard(q)

    def reset(self):
        """Clear all state — used by Reset button in demo panel."""
        self.sessions.clear()
        self.events.clear()
        self.stats = {
            "active_sessions": 0,
            "blocked": 0,
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "layer_scores": {"L1": 0.0, "L2": 0.0, "L3": 0.0, "L4": 0.0, "L5": 0.0},
        }


# Singleton instance
threat_bus = ThreatBus()
