"""
Tests for relay.store.Store.

All tests use an in-memory SQLite database (:memory:) so they run fast and
leave no files behind.
"""

import hashlib

import pytest

from relay.store import Store, _hash_token


@pytest.fixture()
def store(tmp_path):
    """Fresh in-memory store for each test."""
    return Store(":memory:")


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


def test_pair_and_lookup_by_token(store):
    """pair_device then device_by_token returns the device row."""
    plaintext_token = "supersecrettoken"
    token_hash = _hash_token(plaintext_token)

    store.pair_device(
        device_id="dev_1",
        root_pub_hex="deadbeef",
        device_token_hash=token_hash,
        fcm_token="fcm_abc",
    )

    row = store.device_by_token(plaintext_token)
    assert row is not None
    assert row["device_id"] == "dev_1"
    assert row["root_pub_hex"] == "deadbeef"
    assert row["fcm_token"] == "fcm_abc"


def test_plaintext_token_not_stored(store):
    """The store must never persist the plaintext token."""
    plaintext_token = "mysecrettoken42"
    token_hash = _hash_token(plaintext_token)

    store.pair_device(
        device_id="dev_2",
        root_pub_hex="cafebabe",
        device_token_hash=token_hash,
    )

    # Fetch the raw row directly and verify only the hash is present.
    row = store._conn.execute(
        "SELECT * FROM devices WHERE device_id = 'dev_2'"
    ).fetchone()
    assert row is not None

    stored_hash = row["device_token_hash"]
    # Stored value must equal the sha256 hex digest …
    assert stored_hash == hashlib.sha256(plaintext_token.encode()).hexdigest()
    # … and must NOT equal the plaintext.
    assert stored_hash != plaintext_token


def test_device_by_token_unknown(store):
    """device_by_token returns None for an unknown token."""
    assert store.device_by_token("no-such-token") is None


def test_device_root_pub(store):
    store.pair_device("dev_3", "pubkey_hex", _hash_token("tok"))
    assert store.device_root_pub("dev_3") == "pubkey_hex"
    assert store.device_root_pub("nonexistent") is None


def test_device_fcm_token(store):
    store.pair_device("dev_4", "pub", _hash_token("tok2"), fcm_token="fcm_xyz")
    assert store.device_fcm_token("dev_4") == "fcm_xyz"
    assert store.device_fcm_token("nonexistent") is None


# ---------------------------------------------------------------------------
# Intents
# ---------------------------------------------------------------------------


def test_enqueue_and_get(store):
    store.pair_device("dev_a", "pub", _hash_token("t"))
    result = store.enqueue("intent_1", "dev_a", "tok", '{"op":"push"}', "1.2.3.4")
    assert result is True

    row = store.get_intent("intent_1")
    assert row is not None
    assert row["status"] == "queued"
    assert row["device_id"] == "dev_a"


def test_enqueue_dedup_same_intent_id(store):
    """Second enqueue with the same intent_id must return False."""
    store.pair_device("dev_b", "pub", _hash_token("t"))
    first = store.enqueue("intent_dup", "dev_b", "tok", "{}", "1.1.1.1")
    second = store.enqueue("intent_dup", "dev_b", "tok", "{}", "1.1.1.1")
    assert first is True
    assert second is False


def test_next_for_device_returns_oldest_and_marks_inflight(store):
    """next_for_device yields oldest queued intent and marks it in-flight."""
    store.pair_device("dev_c", "pub", _hash_token("t"))
    store.enqueue("old_intent", "dev_c", "tok", '{"seq":1}', "10.0.0.1")
    store.enqueue("new_intent", "dev_c", "tok", '{"seq":2}', "10.0.0.1")

    first = store.next_for_device("dev_c")
    assert first is not None
    assert first["intent_id"] == "old_intent"

    # The same intent must NOT be returned again.
    second = store.next_for_device("dev_c")
    assert second is not None
    assert second["intent_id"] == "new_intent"

    # Both are now in-flight; no more queued.
    third = store.next_for_device("dev_c")
    assert third is None


def test_next_for_device_marks_inflight_immediately(store):
    """After next_for_device, the returned row's status is in-flight."""
    store.pair_device("dev_d", "pub", _hash_token("t"))
    store.enqueue("intent_x", "dev_d", "tok", "{}", "127.0.0.1")

    store.next_for_device("dev_d")

    row = store.get_intent("intent_x")
    assert row["status"] == "in-flight"


def test_set_result_updates_intent(store):
    """set_result changes status, tx_hash, and error on the row."""
    store.pair_device("dev_e", "pub", _hash_token("t"))
    store.enqueue("intent_r", "dev_e", "tok", "{}", "0.0.0.0")
    store.next_for_device("dev_e")

    store.set_result("intent_r", "done", "0xdeadbeef", None)

    row = store.get_intent("intent_r")
    assert row["status"] == "done"
    assert row["tx_hash"] == "0xdeadbeef"
    assert row["error"] is None


def test_set_result_error_path(store):
    store.pair_device("dev_f", "pub", _hash_token("t"))
    store.enqueue("intent_err", "dev_f", "tok", "{}", "0.0.0.0")
    store.next_for_device("dev_f")

    store.set_result("intent_err", "failed", None, "timeout")

    row = store.get_intent("intent_err")
    assert row["status"] == "failed"
    assert row["error"] == "timeout"
    assert row["tx_hash"] is None


# ---------------------------------------------------------------------------
# Revocations
# ---------------------------------------------------------------------------


def test_revoke_and_is_revoked(store):
    assert store.is_revoked("tok_rev") is False
    store.revoke("tok_rev")
    assert store.is_revoked("tok_rev") is True


def test_revoke_idempotent(store):
    """Revoking the same token twice must not raise."""
    store.revoke("tok_idem")
    store.revoke("tok_idem")
    assert store.is_revoked("tok_idem") is True


# ---------------------------------------------------------------------------
# Advisory ledger
# ---------------------------------------------------------------------------


def test_advisory_cumulative_sums_amounts(store):
    store.record_spend("tok_spend", "CKB", 100)
    store.record_spend("tok_spend", "CKB", 250)
    store.record_spend("tok_spend", "CKB", 50)

    assert store.advisory_cumulative("tok_spend", "CKB") == 400


def test_advisory_cumulative_zero_for_unknown(store):
    assert store.advisory_cumulative("unknown_tok", "CKB") == 0


def test_advisory_cumulative_asset_isolation(store):
    """Different assets are tracked independently."""
    store.record_spend("tok_multi", "CKB", 500)
    store.record_spend("tok_multi", "RUSD", 200)

    assert store.advisory_cumulative("tok_multi", "CKB") == 500
    assert store.advisory_cumulative("tok_multi", "RUSD") == 200
