from fastapi import WebSocket
from typing import List, Dict
import json, logging, asyncio

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        logger.info(f"WS connected ({len(self.active)} total)")

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws) if hasattr(self.active, 'discard') else None
        if ws in self.active:
            self.active.remove(ws)
        logger.info(f"WS disconnected ({len(self.active)} total)")

    async def broadcast(self, data: dict):
        dead = []
        msg = json.dumps(data, default=str)
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

ws_manager = ConnectionManager()
