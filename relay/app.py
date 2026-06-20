"""
Agent Gateway Relay — FastAPI application.

Endpoints
---------
POST /pair                  Register / update a paired device.
POST /relay/intent          Agent submits a signed intent.
GET  /relay/intent/{iid}    Poll intent status.
POST /relay/result          Device reports tx outcome.
POST /relay/revoke          Device revokes a biscuit token_id.
WS   /relay/device          Phone WebSocket — drain queue + live push.
GET  /healthz               Health check.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from relay.biscuit_check import precheck
from relay.config import settings
from relay.store import Store
from relay.wake import ConnectionRegistry, fcm_wake

logger = logging.getLogger(__name__)

store = Store(settings.db_path)
registry = ConnectionRegistry()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _intent_id(token_id: str, nonce: str) -> str:
    return hashlib.sha256(f"{token_id}\x00{nonce}".encode()).hexdigest()


def _auth_device(device_token: str) -> str:
    """Resolve plaintext device_token → device_id, or raise 401."""
    dev = store.device_by_token(device_token)
    if not dev:
        raise HTTPException(status_code=401, detail="bad device token")
    return dev["device_id"]


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="Agent Gateway Relay")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class PairReq(BaseModel):
    device_id: str
    root_pub_hex: str
    device_token: str
    fcm_token: str = ""
    # Only required when re-pairing an already-registered device_id.
    # Trust-on-first-use for the initial pairing.
    prev_device_token: Optional[str] = None


class IntentReq(BaseModel):
    device_id: str
    token: str
    op: str
    asset: str
    to: str = ""
    amount: int = 0
    nonce: str
    action: Optional[str] = None
    dao_ref: Optional[str] = None


class ResultReq(BaseModel):
    device_token: str
    intent_id: str
    status: str
    tx_hash: Optional[str] = None
    error: Optional[str] = None


class RevokeReq(BaseModel):
    device_token: str
    token_id: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.post("/pair")
def pair(r: PairReq):
    """Register or update a paired device.  Token is hashed before storage.

    Security model: this relay is intended to bind to the tailnet only
    (network-level restriction is the outer defence).  Within that perimeter,
    trust-on-first-use applies for initial pairing.  Re-pairing an existing
    device_id requires the caller to supply the current device_token via
    prev_device_token so an attacker who only knows the device_id cannot
    rotate the root public key and hijack a device's biscuit authority.
    """
    existing = store.device_root_pub(r.device_id)
    if existing is not None:
        # Device already registered — require proof of the current token.
        if not r.prev_device_token:
            raise HTTPException(status_code=403, detail="prev_device_token required for re-pair")
        dev = store.device_by_token(r.prev_device_token)
        if dev is None or dev["device_id"] != r.device_id:
            raise HTTPException(status_code=403, detail="prev_device_token mismatch")

    token_hash = hashlib.sha256(r.device_token.encode()).hexdigest()
    store.pair_device(r.device_id, r.root_pub_hex, token_hash, r.fcm_token)
    return {"ok": True}


@app.post("/relay/intent")
async def relay_intent(
    r: IntentReq,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
):
    """Agent submits a signed biscuit intent.  Prechecks the token, then queues."""
    root_pub = store.device_root_pub(r.device_id)
    if not root_pub:
        raise HTTPException(status_code=404, detail="unknown device")

    source_ip = (
        (x_forwarded_for or "").split(",")[0].strip()
        or (request.client.host if request.client else "0.0.0.0")
    )
    now = int(time.time())

    pc = precheck(r.token, root_pub, r.op, r.to, source_ip, now)
    if not pc.ok:
        return {"status": "denied", "reason": pc.reason}

    if pc.token_id and store.is_revoked(pc.token_id):
        return {"status": "denied", "reason": "revoked"}

    iid = _intent_id(pc.token_id or r.token, r.nonce)
    payload = {
        "intent_id": iid,
        "token": r.token,
        "op": r.op,
        "asset": r.asset,
        "to": r.to,
        "amount": r.amount,
        "nonce": r.nonce,
        "action": r.action,
        "dao_ref": r.dao_ref,
        "source_ip": source_ip,
    }

    fresh = store.enqueue(iid, r.device_id, r.token, json.dumps(payload), source_ip)

    if fresh:
        woke = await registry.push(r.device_id, {"type": "intent", **payload})
        if not woke:
            fcm_wake(store.device_fcm_token(r.device_id))

    return {"status": "queued", "intent_id": iid}


@app.get("/relay/intent/{iid}")
def intent_status(iid: str):
    """Poll status of a previously submitted intent."""
    row = store.get_intent(iid)
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    return {"status": row["status"], "txHash": row["tx_hash"], "error": row["error"]}


@app.post("/relay/result")
def relay_result(r: ResultReq):
    """Device reports the outcome of executing an intent.

    After authenticating the caller, verify the intent belongs to *their*
    device before accepting the result.  This prevents device A from marking
    device B's intent as 'sent' with a fabricated tx_hash.
    """
    authed_device_id = _auth_device(r.device_token)
    intent = store.get_intent(r.intent_id)
    if intent is None or intent["device_id"] != authed_device_id:
        raise HTTPException(status_code=403, detail="intent does not belong to this device")
    store.set_result(r.intent_id, r.status, r.tx_hash, r.error)
    return {"ok": True}


@app.post("/relay/revoke")
def relay_revoke(r: RevokeReq):
    """Device revokes a biscuit token_id."""
    _auth_device(r.device_token)
    store.revoke(r.token_id)
    return {"ok": True}


@app.websocket("/relay/device")
async def device_ws(ws: WebSocket):
    """Phone WebSocket — authenticate, drain queued intents, accept live pushes."""
    raw_token = ws.headers.get("x-device-token", "")
    dev = store.device_by_token(raw_token)
    if not dev:
        await ws.close(code=4401)
        return

    await ws.accept()
    device_id = dev["device_id"]
    registry.add(device_id, ws)

    try:
        # Drain any intents queued while the device was offline.
        while True:
            nxt = store.next_for_device(device_id)
            if nxt is None:
                break
            await ws.send_text(
                json.dumps({"type": "intent", **json.loads(nxt["intent_json"])})
            )

        # Keep the connection alive; client sends heartbeats / acks.
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        registry.remove(device_id)


@app.get("/healthz")
def healthz():
    return {"ok": True}
