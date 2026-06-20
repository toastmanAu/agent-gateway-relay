"""
Connection registry (live WebSocket map) and FCM fallback wake sender.

The relay never holds private keys.  FCM is a data-only nudge — it tells the
phone to open a WebSocket and drain queued intents.  Intent payloads are NOT
included in the FCM message.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from relay.config import settings

logger = logging.getLogger(__name__)

_fcm_ready = False


def _ensure_fcm() -> bool:
    global _fcm_ready
    if _fcm_ready or not settings.fcm_creds:
        return _fcm_ready
    try:
        import firebase_admin
        from firebase_admin import credentials

        firebase_admin.initialize_app(credentials.Certificate(settings.fcm_creds))
        _fcm_ready = True
    except Exception as exc:
        logger.warning("FCM init failed: %s", exc)
    return _fcm_ready


class ConnectionRegistry:
    """Maps device_id → live WebSocket.  Persistent path uses this; FCM is the fallback."""

    def __init__(self) -> None:
        self._conns: dict = {}

    def add(self, device_id: str, ws) -> None:
        self._conns[device_id] = ws

    def remove(self, device_id: str) -> None:
        self._conns.pop(device_id, None)

    def is_connected(self, device_id: str) -> bool:
        return device_id in self._conns

    async def push(self, device_id: str, payload: dict) -> bool:
        ws = self._conns.get(device_id)
        if ws is None:
            return False
        try:
            await ws.send_text(json.dumps(payload))
            return True
        except Exception as exc:
            logger.warning("WS push failed for %s: %s", device_id, exc)
            self.remove(device_id)
            return False


def fcm_wake(device_fcm_token: Optional[str]) -> bool:
    """High-priority data-only nudge: 'connect and drain'.  Carries NO intent contents."""
    if not device_fcm_token or not _ensure_fcm():
        return False
    try:
        from firebase_admin import messaging

        msg = messaging.Message(
            data={"type": "agent_wake"},
            token=device_fcm_token,
            android=messaging.AndroidConfig(priority="high"),
        )
        messaging.send(msg)
        return True
    except Exception as exc:
        logger.warning("FCM send failed: %s", exc)
        return False
