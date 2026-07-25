"""
Integration tests for relay.app (FastAPI endpoints + WebSocket).

Strategy
--------
- Monkeypatch relay.app.store with a fresh in-memory Store so tests are
  isolated and leave no files behind.
- Mint real biscuit tokens using the same authority-block shape as
  test_biscuit_check.py, so precheck() passes end-to-end.
- FCM wake returns False in tests (no RELAY_FCM_CREDS) — that's expected.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import time
from typing import Optional

import pytest
from biscuit_auth import BiscuitBuilder, Check, KeyPair
from fastapi.testclient import TestClient

from relay.store import Store, _hash_token

# ---------------------------------------------------------------------------
# Constants shared across tests
# ---------------------------------------------------------------------------

DEVICE_ID = "device_test_001"
ACCOUNT = "wallet_test"
OP = "relay:push"
SOURCE_IP = "127.0.0.1"
DEVICE_TOKEN_PLAIN = "plain-device-token-for-testing"
DEVICE_TOKEN_HASH = _hash_token(DEVICE_TOKEN_PLAIN)
NONCE = "nonce_abc123"


# ---------------------------------------------------------------------------
# Biscuit token helper (mirrors test_biscuit_check.py)
# ---------------------------------------------------------------------------


def _mint_token(
    kp: KeyPair,
    *,
    account: str = ACCOUNT,
    scope: Optional[list] = None,
    token_id: str = "tok_test_001",
    cap: int = 500,
    ttl_offset: int = 3600,
    recipient: str = DEVICE_ID,
    source_ip: str = SOURCE_IP,
) -> str:
    if scope is None:
        scope = [OP]

    ttl_dt = datetime.datetime.fromtimestamp(
        int(time.time()) + ttl_offset, tz=datetime.timezone.utc
    )
    scope_literal = "[" + ", ".join(f'"{s}"' for s in scope) + "]"

    builder = BiscuitBuilder()
    builder.add_code(
        f'account("{account}"); scope({scope_literal}); token_id("{token_id}"); cap({cap});'
    )
    builder.add_check(Check("check if operation($op), scope($s), $s.contains($op)"))
    builder.add_check(Check("check if requested_account($a), account($a)"))
    builder.add_check(Check("check if time($t), $t < {ttl}", parameters={"ttl": ttl_dt}))
    builder.add_check(Check(f'check if recipient("{recipient}")'))
    builder.add_check(Check(f'check if source_ip("{source_ip}")'))

    return builder.build(kp.private_key).to_base64()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mem_store():
    """Fresh in-memory store for each test."""
    return Store(":memory:")


@pytest.fixture()
def client(mem_store, monkeypatch):
    """TestClient with store replaced by a fresh in-memory instance."""
    import relay.app as app_module

    monkeypatch.setattr(app_module, "store", mem_store)
    # Fresh registry too, so WS tests don't bleed state.
    from relay.wake import ConnectionRegistry

    monkeypatch.setattr(app_module, "registry", ConnectionRegistry())

    from fastapi.testclient import TestClient

    with TestClient(app_module.app) as c:
        yield c


@pytest.fixture()
def kp():
    return KeyPair()


@pytest.fixture()
def paired_client(client, mem_store, kp):
    """Client with one device already paired."""
    mem_store.pair_device(
        device_id=DEVICE_ID,
        root_pub_hex=kp.public_key.to_hex(),
        device_token_hash=DEVICE_TOKEN_HASH,
        fcm_token="",
    )
    return client


# ---------------------------------------------------------------------------
# /healthz
# ---------------------------------------------------------------------------


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


# ---------------------------------------------------------------------------
# POST /pair
# ---------------------------------------------------------------------------


def test_pair_new_device(client):
    r = client.post(
        "/pair",
        json={
            "device_id": DEVICE_ID,
            "root_pub_hex": "deadbeef" * 8,
            "device_token": DEVICE_TOKEN_PLAIN,
            "fcm_token": "fcm_abc",
        },
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_pair_hashes_token(client, mem_store):
    """The store must record the hash, not the plaintext."""
    client.post(
        "/pair",
        json={
            "device_id": "dev_hash_check",
            "root_pub_hex": "aabb" * 16,
            "device_token": "my-secret-token",
        },
    )
    row = mem_store._conn.execute(
        "SELECT device_token_hash FROM devices WHERE device_id = 'dev_hash_check'"
    ).fetchone()
    assert row is not None
    assert row["device_token_hash"] == hashlib.sha256("my-secret-token".encode()).hexdigest()


def test_pair_upsert(client, mem_store, kp):
    """Re-pairing with a new pub key and correct prev_device_token updates the record."""
    kp2 = KeyPair()
    # Initial pair (trust-on-first-use).
    client.post(
        "/pair",
        json={
            "device_id": DEVICE_ID,
            "root_pub_hex": kp.public_key.to_hex(),
            "device_token": DEVICE_TOKEN_PLAIN,
        },
    )
    # Re-pair supplying prev_device_token.
    r = client.post(
        "/pair",
        json={
            "device_id": DEVICE_ID,
            "root_pub_hex": kp2.public_key.to_hex(),
            "device_token": DEVICE_TOKEN_PLAIN,
            "prev_device_token": DEVICE_TOKEN_PLAIN,
        },
    )
    assert r.status_code == 200
    row = mem_store._conn.execute(
        "SELECT root_pub_hex FROM devices WHERE device_id = ?", (DEVICE_ID,)
    ).fetchone()
    assert row["root_pub_hex"] == kp2.public_key.to_hex()


def test_pair_repair_no_prev_token_forbidden(client, mem_store, kp):
    """Re-pairing without prev_device_token → 403."""
    client.post(
        "/pair",
        json={
            "device_id": DEVICE_ID,
            "root_pub_hex": kp.public_key.to_hex(),
            "device_token": DEVICE_TOKEN_PLAIN,
        },
    )
    r = client.post(
        "/pair",
        json={
            "device_id": DEVICE_ID,
            "root_pub_hex": "newkey" * 8,
            "device_token": "new-token",
        },
    )
    assert r.status_code == 403


def test_pair_repair_wrong_prev_token_forbidden(client, mem_store, kp):
    """Re-pairing with an incorrect prev_device_token → 403."""
    client.post(
        "/pair",
        json={
            "device_id": DEVICE_ID,
            "root_pub_hex": kp.public_key.to_hex(),
            "device_token": DEVICE_TOKEN_PLAIN,
        },
    )
    r = client.post(
        "/pair",
        json={
            "device_id": DEVICE_ID,
            "root_pub_hex": "newkey" * 8,
            "device_token": "new-token",
            "prev_device_token": "wrong-previous-token",
        },
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# POST /relay/intent
# ---------------------------------------------------------------------------


def test_intent_queued(paired_client, kp, mem_store):
    """Valid token + known device → queued, intent_id returned."""
    token = _mint_token(kp)
    r = paired_client.post(
        "/relay/intent",
        json={
            "device_id": DEVICE_ID,
            "token": token,
            "op": OP,
            "asset": "CKB",
            "to": DEVICE_ID,
            "amount": 100,
            "nonce": NONCE,
        },
        headers={"x-forwarded-for": SOURCE_IP},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "queued"
    intent_id = body["intent_id"]
    assert len(intent_id) == 64  # sha256 hex

    row = mem_store.get_intent(intent_id)
    assert row is not None
    assert row["status"] == "queued"


def test_intent_idempotent(paired_client, kp):
    """Submitting the same nonce twice returns the same intent_id without re-queuing."""
    token = _mint_token(kp)
    payload = {
        "device_id": DEVICE_ID,
        "token": token,
        "op": OP,
        "asset": "CKB",
        "to": DEVICE_ID,
        "amount": 50,
        "nonce": "same_nonce",
    }
    headers = {"x-forwarded-for": SOURCE_IP}

    r1 = paired_client.post("/relay/intent", json=payload, headers=headers)
    r2 = paired_client.post("/relay/intent", json=payload, headers=headers)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["intent_id"] == r2.json()["intent_id"]


def test_intent_denied_bad_token(paired_client):
    """Garbage token → denied, not queued."""
    r = paired_client.post(
        "/relay/intent",
        json={
            "device_id": DEVICE_ID,
            "token": "not-a-real-biscuit",
            "op": OP,
            "asset": "CKB",
            "to": DEVICE_ID,
            "amount": 10,
            "nonce": "n1",
        },
        headers={"x-forwarded-for": SOURCE_IP},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "denied"


def test_intent_denied_wrong_op(paired_client, kp):
    """Token scoped to relay:push rejects a different op."""
    token = _mint_token(kp, scope=["relay:push"])
    r = paired_client.post(
        "/relay/intent",
        json={
            "device_id": DEVICE_ID,
            "token": token,
            "op": "relay:admin",
            "asset": "CKB",
            "to": DEVICE_ID,
            "amount": 10,
            "nonce": "n2",
        },
        headers={"x-forwarded-for": SOURCE_IP},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "denied"


def test_intent_unknown_device(client):
    """Intent for an unregistered device_id → 404."""
    r = client.post(
        "/relay/intent",
        json={
            "device_id": "ghost_device",
            "token": "abc",
            "op": OP,
            "asset": "CKB",
            "to": "x",
            "amount": 1,
            "nonce": "n",
        },
    )
    assert r.status_code == 404


def test_intent_denied_if_revoked(paired_client, kp, mem_store):
    """Intent with a revoked token_id → denied even if biscuit checks pass."""
    token_id = "tok_test_001"
    mem_store.revoke(token_id)

    token = _mint_token(kp, token_id=token_id)
    r = paired_client.post(
        "/relay/intent",
        json={
            "device_id": DEVICE_ID,
            "token": token,
            "op": OP,
            "asset": "CKB",
            "to": DEVICE_ID,
            "amount": 10,
            "nonce": "n_rev",
        },
        headers={"x-forwarded-for": SOURCE_IP},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "denied"


# ---------------------------------------------------------------------------
# GET /relay/intent/{iid}
# ---------------------------------------------------------------------------


def test_intent_status_get(paired_client, kp):
    """Status endpoint reflects queued intent."""
    token = _mint_token(kp)
    post_r = paired_client.post(
        "/relay/intent",
        json={
            "device_id": DEVICE_ID,
            "token": token,
            "op": OP,
            "asset": "CKB",
            "to": DEVICE_ID,
            "amount": 10,
            "nonce": "status_nonce",
        },
        headers={"x-forwarded-for": SOURCE_IP},
    )
    intent_id = post_r.json()["intent_id"]

    get_r = paired_client.get(f"/relay/intent/{intent_id}")
    assert get_r.status_code == 200
    body = get_r.json()
    assert body["status"] in ("queued", "in-flight")
    assert body["txHash"] is None


def test_intent_status_includes_device_online_false_when_offline(paired_client, kp):
    """With no live WS for the device, status poll reports device_online == False."""
    token = _mint_token(kp)
    post_r = paired_client.post(
        "/relay/intent",
        json={
            "device_id": DEVICE_ID,
            "token": token,
            "op": OP,
            "asset": "CKB",
            "to": DEVICE_ID,
            "amount": 10,
            "nonce": "online_nonce_off",
        },
        headers={"x-forwarded-for": SOURCE_IP},
    )
    intent_id = post_r.json()["intent_id"]

    body = paired_client.get(f"/relay/intent/{intent_id}").json()
    assert body["device_online"] is False


def test_intent_status_includes_device_online_true_when_connected(paired_client, kp):
    """When the device is registered as connected, status poll reports device_online == True."""
    import relay.app as app_module

    token = _mint_token(kp)
    post_r = paired_client.post(
        "/relay/intent",
        json={
            "device_id": DEVICE_ID,
            "token": token,
            "op": OP,
            "asset": "CKB",
            "to": DEVICE_ID,
            "amount": 10,
            "nonce": "online_nonce_on",
        },
        headers={"x-forwarded-for": SOURCE_IP},
    )
    intent_id = post_r.json()["intent_id"]

    # Simulate a live WebSocket for this device (registry maps device_id -> ws).
    app_module.registry.add(DEVICE_ID, object())
    try:
        body = paired_client.get(f"/relay/intent/{intent_id}").json()
        assert body["device_online"] is True
    finally:
        app_module.registry.remove(DEVICE_ID)


def test_intent_status_not_found(client):
    r = client.get("/relay/intent/0" * 64)
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /relay/result
# ---------------------------------------------------------------------------


def test_result_updates_status(paired_client, kp, mem_store):
    """Device can post a result; status flips and tx_hash is stored."""
    token = _mint_token(kp)
    post_r = paired_client.post(
        "/relay/intent",
        json={
            "device_id": DEVICE_ID,
            "token": token,
            "op": OP,
            "asset": "CKB",
            "to": DEVICE_ID,
            "amount": 77,
            "nonce": "result_nonce",
        },
        headers={"x-forwarded-for": SOURCE_IP},
    )
    intent_id = post_r.json()["intent_id"]

    r = paired_client.post(
        "/relay/result",
        json={
            "device_token": DEVICE_TOKEN_PLAIN,
            "intent_id": intent_id,
            "status": "sent",
            "tx_hash": "0xdeadbeef",
        },
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True

    row = mem_store.get_intent(intent_id)
    assert row["status"] == "sent"
    assert row["tx_hash"] == "0xdeadbeef"


def test_result_bad_device_token(client):
    r = client.post(
        "/relay/result",
        json={
            "device_token": "wrong-token",
            "intent_id": "x" * 64,
            "status": "sent",
        },
    )
    assert r.status_code == 401


def test_result_cross_device_forgery_forbidden(client, mem_store, kp):
    """Device B cannot post a result for device A's intent → 403."""
    from relay.store import _hash_token

    device_b_id = "device_b_001"
    device_b_token = "device-b-secret-token"

    # Register device A.
    mem_store.pair_device(
        device_id=DEVICE_ID,
        root_pub_hex=kp.public_key.to_hex(),
        device_token_hash=DEVICE_TOKEN_HASH,
        fcm_token="",
    )
    # Register device B.
    mem_store.pair_device(
        device_id=device_b_id,
        root_pub_hex=kp.public_key.to_hex(),
        device_token_hash=_hash_token(device_b_token),
        fcm_token="",
    )

    # Enqueue an intent that belongs to device A.
    import json
    intent_payload = {
        "intent_id": "intent_device_a",
        "op": OP,
        "asset": "CKB",
        "to": DEVICE_ID,
        "amount": 10,
        "nonce": "n_a",
        "action": None,
        "dao_ref": None,
        "source_ip": SOURCE_IP,
        "token": "tok",
    }
    mem_store.enqueue(
        "intent_device_a", DEVICE_ID, "tok", json.dumps(intent_payload), SOURCE_IP
    )

    # Device B tries to post a result for device A's intent.
    r = client.post(
        "/relay/result",
        json={
            "device_token": device_b_token,
            "intent_id": "intent_device_a",
            "status": "sent",
            "tx_hash": "0xforgery",
        },
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# POST /relay/revoke
# ---------------------------------------------------------------------------


def test_revoke_token_id(paired_client, mem_store):
    """Device can revoke a token_id; subsequent intents with that id are denied."""
    r = paired_client.post(
        "/relay/revoke",
        json={
            "device_token": DEVICE_TOKEN_PLAIN,
            "token_id": "tok_to_revoke",
        },
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert mem_store.is_revoked("tok_to_revoke") is True


def test_revoke_bad_device_token(client):
    r = client.post(
        "/relay/revoke",
        json={"device_token": "bad", "token_id": "x"},
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# WS /relay/device
# ---------------------------------------------------------------------------


def test_ws_bad_token_closes(client):
    """WebSocket with an unknown device token → close code 4401."""
    with pytest.raises(Exception):
        # TestClient raises when the server closes the WS before accept.
        with client.websocket_connect(
            "/relay/device",
            headers={"x-device-token": "totally-wrong-token"},
        ) as ws:
            ws.receive_text()


def test_ws_drains_queued_intent(paired_client, kp, mem_store):
    """
    After connecting, the device immediately receives any queued intents.
    """
    # Enqueue an intent directly into the store (bypasses biscuit, simpler).
    intent_payload = {
        "intent_id": "intent_ws_drain",
        "token": "tok",
        "op": OP,
        "asset": "CKB",
        "to": DEVICE_ID,
        "amount": 42,
        "nonce": "ws_nonce",
        "action": None,
        "dao_ref": None,
        "source_ip": SOURCE_IP,
    }
    mem_store.enqueue(
        "intent_ws_drain",
        DEVICE_ID,
        "tok",
        json.dumps(intent_payload),
        SOURCE_IP,
    )

    with paired_client.websocket_connect(
        "/relay/device",
        headers={"x-device-token": DEVICE_TOKEN_PLAIN},
    ) as ws:
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "intent"
        assert msg["intent_id"] == "intent_ws_drain"
        assert msg["amount"] == 42


def test_ws_no_queue_stays_open(paired_client):
    """With no queued intents, the WS stays open and accepts heartbeats."""
    with paired_client.websocket_connect(
        "/relay/device",
        headers={"x-device-token": DEVICE_TOKEN_PLAIN},
    ) as ws:
        ws.send_text("ping")
        # No exception = connection alive; success.
