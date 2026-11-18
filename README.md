# Agent Gateway Relay

A keyless relay between AI agents (or a POS terminal) and a phone wallet on **Nervos CKB**. Agents submit spending *intents* authorised by a [Biscuit](https://www.biscuitsec.org/) token. The relay pre-checks the token and queues the intent. It then delivers the intent to the paired phone over a WebSocket, or wakes the phone with a data-only FCM push. The phone makes the final decision and signs the transaction.

**The relay holds no private keys.** Its token check is advisory: the wallet device runs its own authorizer again before it signs anything. If the relay is compromised, an attacker can delay or drop intents but cannot spend funds.

This is the relay half of the Agent Gateway in [wyltek-wallet](https://github.com/toastmanAu/wyltek-wallet).

## How it works

```
 agent / POS ──POST /relay/intent──► relay ──WebSocket push──► phone wallet
                                       │  (or FCM "agent_wake" if offline)   │
                                       │                                     ├─ re-checks biscuit
                                       │◄──────── POST /relay/result ────────┤   signs + broadcasts
 agent / POS ◄─GET /relay/intent/{id}──┘                                     │
```

1. **Pair.** The phone registers its `device_id`, its Biscuit root public key, a device token (stored only as a SHA-256 hash) and an optional FCM token. The first pairing is trust-on-first-use. Re-pairing an existing device requires the current device token.
2. **Submit.** The agent posts a Biscuit token plus `op`, `asset`, `to`, `amount` and `nonce`. The relay verifies the root signature and runs the token's Datalog checks against facts it supplies: operation, recipient, source IP and time. It then rejects revoked token IDs.
3. **Deliver.** The intent ID is `sha256(token_id ‖ nonce)`, so a resubmitted intent is deduplicated rather than queued twice. A fresh intent goes out over the phone's WebSocket if one is open. Otherwise the relay sends a high-priority FCM message that carries **no intent contents**, only a request to connect. The phone then drains its queue.
4. **Report.** The phone posts the outcome (`tx_hash` or `error`). The relay accepts a result only from the device that owns the intent.

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/pair` | Register or re-pair a device |
| `POST` | `/relay/intent` | Agent submits a Biscuit-authorised intent |
| `GET` | `/relay/intent/{id}` | Poll status, `txHash`, `error`, `device_online` |
| `POST` | `/relay/result` | Device reports the outcome (device-token auth) |
| `POST` | `/relay/revoke` | Device revokes a Biscuit `token_id` |
| `WS` | `/relay/device` | Phone connection (`x-device-token` header): drains the queue, then receives live pushes |
| `GET` | `/healthz` | Health check |

State lives in SQLite: devices, intents, revocations, and an advisory spend ledger.

## Run

Requires Python 3.10+.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn relay.app:app --host 127.0.0.1 --port 9991
pytest            # store, app and biscuit pre-check tests
```

Configuration is through environment variables:

| Variable | Default | Notes |
|---|---|---|
| `RELAY_HOST` | `127.0.0.1` | Bind to a private/tailnet address, never a public one |
| `RELAY_PORT` | `9991` | |
| `RELAY_DB` | `~/agent-gateway-relay/relay.sqlite` | |
| `RELAY_FCM_CREDS` | *(empty)* | Path to a Firebase Admin JSON key. When empty, FCM wake is off and only WebSocket delivery works. |

A systemd unit is in [`deploy/agent-relay.service`](deploy/agent-relay.service). Do not commit the FCM credentials file.

## Security model and limits

- **Network perimeter first.** The relay is meant to bind to a tailnet only. Pairing is trust-on-first-use inside that perimeter, so it should not be reachable from the internet.
- **Advisory checks only.** The token pre-check and spend ledger let the relay drop obviously bad intents early. The phone's authorizer is the real authority.
- **Single process for presence.** The WebSocket registry lives in process memory. With more than one worker, `device_online` and live push only see connections held by the worker that handles the request. Intents still reach the phone through the queue or FCM, but run one worker if `device_online` must be exact. The shipped unit uses `--workers 2`.

## Status

Experimental. Built alongside the wyltek-wallet Agent Gateway, with unit tests for the store, API routes and Biscuit pre-check. It has not had a security audit.

## License

[MIT](LICENSE)
