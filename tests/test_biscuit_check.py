"""
Tests for relay.biscuit_check.precheck.

Tokens are minted with biscuit-python using the same authority-block fact +
check shape that the wyltek-wallet Rust code emits:

  Facts (authority):
    account("wallet_abc")
    scope(["relay:push"])
    token_id("tok_001")
    cap(100)

  Checks (authority):
    check if operation($op), scope($s), $s.contains($op)   // scope guard
    check if requested_account($a), account($a)             // account binding
    check if time($t), $t < <ttl>                           // TTL
    check if recipient("<device>")                          // allow_to
    check if source_ip("<ip>")                              // allow_ip

The relay's precheck() supplies ambient facts for operation/recipient/source_ip
and derives requested_account from account via a rule, so all five checks fire.
"""

import datetime
import time

import pytest
from biscuit_auth import (
    BiscuitBuilder,
    Check,
    KeyPair,
)

from relay.biscuit_check import PrecheckResult, precheck

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DEVICE = "device_xyz"
ACCOUNT = "wallet_abc"
OP = "relay:push"
SOURCE_IP = "192.168.1.10"


def _keypair():
    return KeyPair()


def _pub_hex(kp: KeyPair) -> str:
    return kp.public_key.to_hex()


def _mint_token(
    kp: KeyPair,
    *,
    account: str = ACCOUNT,
    scope: list = None,
    token_id: str = "tok_001",
    cap: int = 100,
    ttl_offset: int = 3600,
    recipient: str = DEVICE,
    source_ip: str = SOURCE_IP,
) -> str:
    """Build a token with the wallet's authority block shape."""
    if scope is None:
        scope = [OP]

    ttl_dt = datetime.datetime.fromtimestamp(
        int(time.time()) + ttl_offset, tz=datetime.timezone.utc
    )

    # Datalog list literal e.g. ["relay:push"]
    scope_literal = "[" + ", ".join(f'"{s}"' for s in scope) + "]"

    builder = BiscuitBuilder()
    builder.add_code(
        f'account("{account}"); scope({scope_literal}); token_id("{token_id}"); cap({cap});'
    )

    # scope check: operation must be in scope list
    builder.add_check(
        Check("check if operation($op), scope($s), $s.contains($op)")
    )
    # account binding
    builder.add_check(
        Check("check if requested_account($a), account($a)")
    )
    # TTL
    builder.add_check(
        Check("check if time($t), $t < {ttl}", parameters={"ttl": ttl_dt})
    )
    # allow_to
    builder.add_check(Check(f'check if recipient("{recipient}")'))
    # allow_ip
    builder.add_check(Check(f'check if source_ip("{source_ip}")'))

    return builder.build(kp.private_key).to_base64()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_valid_token_ok():
    """Valid token with correct op, recipient, IP, and future TTL → ok."""
    kp = _keypair()
    token = _mint_token(kp)
    result = precheck(
        token=token,
        root_pub_hex=_pub_hex(kp),
        op=OP,
        recipient=DEVICE,
        source_ip=SOURCE_IP,
        now_unix=int(time.time()),
    )
    assert result.ok is True
    assert result.token_id == "tok_001"
    assert result.reason is None


def test_wrong_op_denied():
    """Token scoped to ['relay:push'] should reject a different operation."""
    kp = _keypair()
    # Token only grants relay:push
    token = _mint_token(kp, scope=["relay:push"])
    result = precheck(
        token=token,
        root_pub_hex=_pub_hex(kp),
        op="relay:admin",   # not in scope
        recipient=DEVICE,
        source_ip=SOURCE_IP,
        now_unix=int(time.time()),
    )
    assert result.ok is False
    assert result.reason is not None and "denied" in result.reason


def test_expired_ttl_denied():
    """Token whose TTL is in the past should be rejected."""
    kp = _keypair()
    # ttl_offset = -10 → expired 10 seconds ago
    token = _mint_token(kp, ttl_offset=-10)
    result = precheck(
        token=token,
        root_pub_hex=_pub_hex(kp),
        op=OP,
        recipient=DEVICE,
        source_ip=SOURCE_IP,
        now_unix=int(time.time()),
    )
    assert result.ok is False
    assert result.reason is not None and "denied" in result.reason


def test_tampered_token_denied():
    """A token verified against the wrong public key must be rejected."""
    kp_real = _keypair()
    kp_wrong = _keypair()  # different keypair → wrong root key
    token = _mint_token(kp_real)
    result = precheck(
        token=token,
        root_pub_hex=_pub_hex(kp_wrong),   # wrong public key
        op=OP,
        recipient=DEVICE,
        source_ip=SOURCE_IP,
        now_unix=int(time.time()),
    )
    assert result.ok is False
    assert result.reason is not None and "parse" in result.reason


def test_wrong_recipient_denied():
    """Token locked to device_xyz should reject a different recipient."""
    kp = _keypair()
    token = _mint_token(kp, recipient="device_xyz")
    result = precheck(
        token=token,
        root_pub_hex=_pub_hex(kp),
        op=OP,
        recipient="device_other",  # wrong recipient
        source_ip=SOURCE_IP,
        now_unix=int(time.time()),
    )
    assert result.ok is False
    assert result.reason is not None and "denied" in result.reason


def test_wrong_source_ip_denied():
    """Token locked to SOURCE_IP should reject a different caller IP."""
    kp = _keypair()
    token = _mint_token(kp, source_ip=SOURCE_IP)
    result = precheck(
        token=token,
        root_pub_hex=_pub_hex(kp),
        op=OP,
        recipient=DEVICE,
        source_ip="10.0.0.99",  # wrong IP
        now_unix=int(time.time()),
    )
    assert result.ok is False
    assert result.reason is not None and "denied" in result.reason


def test_garbage_token_denied():
    """Completely invalid base64 input should return a parse error."""
    kp = _keypair()
    result = precheck(
        token="not-a-valid-biscuit-token!!!",
        root_pub_hex=_pub_hex(kp),
        op=OP,
        recipient=DEVICE,
        source_ip=SOURCE_IP,
        now_unix=int(time.time()),
    )
    assert result.ok is False
    assert result.reason is not None and "parse" in result.reason
