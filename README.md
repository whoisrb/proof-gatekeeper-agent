# Proof Gatekeeper Agent

An agent endpoint for the **Proof Gatekeeper** track of the zkVerify Agent Games.
It receives signed payment-approval tasks from the platform, verifies every field
of the request, and answers APPROVE or REJECT with a signed response.

## How it decides

Every task is checked in a fixed order, and any doubt fails closed (REJECT):

1. `VK_SUBSTITUTION` — the proof verification key must equal the registered key.
2. `PROOF_REUSED` — a proof transaction that was already accepted once is burned.
3. `THRESHOLD_MISMATCH` — the public balance must meet the stated minimum.
4. `EXPIRED_CONDITION` — the current block must not pass the expiry block.
5. `RECIPIENT_MISMATCH` — the transfer recipient must match the condition recipient.
6. `AMOUNT_OVERFLOW` — the amount must not exceed the maximum transfer.

Amounts are compared with BigInt so values above 2^53 stay exact. Hex values are
compared case-insensitively. A proof transaction is added to the seen-set only
when a task carrying it is approved.

## Protocol

- The platform POSTs JSON tasks to the endpoint path (default `/agent`).
- Requests are authenticated with an HMAC-SHA256 signature over the raw body
  (`x-agent-games-signature`), keyed by the secret issued in the dashboard.
- Responses are signed the same way. Preflight tasks
  (`agent-games.preflight.v1`) are answered with `{ ok: true, protocolVersion: "v1" }`.
- `task_id` is treated as an idempotency key.

## Run it

```sh
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET from the dashboard
node server.js
```

No runtime dependencies beyond Node itself for the decision endpoint.
`proof.js` builds the optional Groth16 decision proof when circuit input
mappings are configured; without them the agent answers decisions only.

## Tests

```sh
node test.js
```

18 checks: one fixture per trap variety, boundary cases (balance equal to the
minimum, current block equal to expiry, amount equal to the cap), proof reuse
in both directions, bad signature rejection, practice mode, and large-amount
precision.
