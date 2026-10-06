import json
import asyncio
from typing import List, Dict, Any, Set
from fastapi import WebSocket
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.models import Notification, SeverityLevel, UserRole


class NotificationHub:
    """
    Central real-time event and WebSocket manager.
    Broadcasts security events, alerts, and live SIEM metrics to connected SOC dashboards.
    """
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcasts JSON payload to all connected SOC analysts and operators."""
        if not self.active_connections:
            return

        payload_str = json.dumps(message, default=str)
        dead_connections = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload_str)
            except Exception:
                dead_connections.append(connection)

        for dead in dead_connections:
            self.active_connections.discard(dead)

    async def emit_security_alert(
        self,
        alert_id: int,
        title: str,
        message: str,
        severity: str,
        threat_type: str,
        atm_id: Any = None,
        account_id: Any = None
    ):
        event = {
            "type": "SECURITY_ALERT",
            "alert_id": alert_id,
            "title": title,
            "message": message,
            "severity": severity,
            "threat_type": threat_type,
            "atm_id": atm_id,
            "account_id": account_id,
            "timestamp": asyncio.get_event_loop().time()
        }
        await self.broadcast(event)


hub = NotificationHub()


async def create_user_notification(
    db: AsyncSession,
    user_id: int,
    title: str,
    message: str,
    severity: SeverityLevel = SeverityLevel.LOW
) -> Notification:
    """Stores persistent user notification for in-app bell notification tray."""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        severity=severity,
        read=False
    )
    db.add(notification)
    await db.flush()
    return notification
