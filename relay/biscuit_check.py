"""
Public biscuit pre-validation for the Agent Gateway Relay.

Advisory only — the wallet device re-checks authoritatively with its own
authorizer.  This module never touches a private key.

API notes (biscuit-python 0.3.2):
  - PublicKey.from_hex(hex_str) — works directly, no Algorithm arg needed.
  - Biscuit.from_base64(b64, pk) — parses and verifies root signature.
  - Authorizer() is a mutable builder; add_token(biscuit) loads the token.
  - add_code(datalog_str) accepts multi-statement datalog including rules.
  - add_fact(Fact('name({p})', parameters={'p': value})) for typed values.
  - Datetime parameters are passed as datetime objects (RFC3339 under the hood).
  - add_policy(Policy('allow if true')) grants a catch-all allow.
  - authorize() raises AuthorizationError if any check fails.
  - query(Rule('head($x) <- body($x)')) returns a list of Fact objects;
    Fact.terms is a list of Python scalars (str, int, datetime, list, …).
  - No AuthorizerBuilder in 0.3.2 — the mutable Authorizer replaces it.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Optional

from biscuit_auth import Authorizer, Biscuit, Fact, Policy, PublicKey, Rule


@dataclass
class PrecheckResult:
    ok: bool
    token_id: Optional[str] = None
    reason: Optional[str] = None


def precheck(
    token: str,
    root_pub_hex: str,
    op: str,
    recipient: str,
    source_ip: str,
    now_unix: int,
) -> PrecheckResult:
    """Public, advisory pre-validation.  The device re-checks authoritatively.

    Args:
        token:        URL-safe base64 biscuit token string.
        root_pub_hex: Hex-encoded 32-byte Ed25519 root public key.
        op:           Operation name being requested (e.g. "relay:push").
        recipient:    Target device identifier.
        source_ip:    Caller's source IP address.
        now_unix:     Current Unix timestamp (seconds) — used for TTL check.

    Returns:
        PrecheckResult with ok=True and token_id on success, or ok=False and
        reason on any failure.
    """
    # --- 1. Parse and verify root signature ----------------------------------
    try:
        pk = PublicKey.from_hex(root_pub_hex)
        b = Biscuit.from_base64(token, pk)
    except Exception as exc:
        return PrecheckResult(False, reason=f"parse: {exc}")

    # --- 2. Build authorizer with ambient facts and run checks ---------------
    try:
        now_dt = datetime.datetime.fromtimestamp(now_unix, tz=datetime.timezone.utc)

        az = Authorizer()
        az.add_token(b)

        # Ambient facts the token's checks reference (mirrors the device authorizer).
        # Use add_code for multi-statement datalog including the account rule.
        az.add_code(
            f'operation("{op}"); recipient("{recipient}"); source_ip("{source_ip}");'
            f" requested_account($a) <- account($a);"
        )

        # time() ambient fact — biscuit-python requires a datetime object as
        # the parameter value (converts to RFC3339 internally).
        az.add_fact(Fact("time({t})", parameters={"t": now_dt}))

        az.add_policy(Policy("allow if true"))
        az.authorize()  # raises AuthorizationError if any check or policy fails

    except Exception as exc:
        return PrecheckResult(False, reason=f"denied: {exc}")

    # --- 3. Extract token_id for dedup/revocation ----------------------------
    token_id: Optional[str] = None
    try:
        facts = az.query(Rule("id($id) <- token_id($id)"))
        if facts:
            token_id = str(facts[0].terms[0])
    except Exception:
        pass  # token_id is optional; absence is non-fatal

    return PrecheckResult(True, token_id=token_id)
