from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.websocket.manager import ws_manager
from app.auth.security import decode_token
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

@router.websocket("/ws/monitor")
async def ws_monitor(websocket: WebSocket, token: str = Query(None)):
    # Validate token
    if token:
        try:
            decode_token(token)
        except Exception:
            await websocket.close(code=4001)
            return
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep alive — client can send ping
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
