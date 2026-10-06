from typing import List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.db.session import get_db
from app.db.models.models import Notification, User
from app.core.deps import get_current_user
from app.engines.notifier import hub

router = APIRouter(tags=["Real-Time WebSockets & Notifications"])


async def broadcast_soc_event(message: dict):
    """Broadcasts a live security event or status change to connected WebSockets."""
    await hub.broadcast(message)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time WebSocket endpoint for live SOC SIEM event streaming."""
    await hub.connect(websocket)
    try:
        # Welcome handshake
        await websocket.send_json({
            "type": "CONNECTED",
            "message": "Connected to SecureVault SOC Live SIEM Stream",
            "active_clients": len(hub.active_connections)
        })
        while True:
            # Keep-alive ping/pong & incoming subscription messages
            data = await websocket.receive_text()
            if data == "ping" or '"ping"' in data:
                await websocket.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        hub.disconnect(websocket)
    except Exception:
        hub.disconnect(websocket)


@router.get("/notifications")
async def get_user_notifications(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves unread notifications for the current authenticated user."""
    stmt = (
        select(Notification)
        .where(Notification.user_id == current_user.id)
        .order_by(Notification.created_at.desc())
        .limit(20)
    )
    res = await db.execute(stmt)
    notifications = res.scalars().all()
    return notifications


@router.post("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Marks a notification as read."""
    stmt = (
        update(Notification)
        .where(Notification.id == notification_id, Notification.user_id == current_user.id)
        .values(read=True)
    )
    await db.execute(stmt)
    await db.commit()
    return {"status": "SUCCESS"}
