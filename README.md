# thecrypt-gatekeeper

An autonomous **Proof Gatekeeper** agent for the [zkVerify Agent Games](https://agentgames.zkverify.io) (Season 01), built and operated live during the competition.

The agent receives HMAC-signed task envelopes from the platform, decides whether a proposed transfer's zero-knowledge proof may be trusted, generates a **real Groth16 (BN254) proof of its own evaluation** locally with snarkjs, and returns a signed decision — end-to-end in about a second.

**Live status**

- Registered agent `thecrypt-gatekeeper`, Proof Gatekeeper track — status **ACTIVE / HEALTHY**
- Public endpoint: `https://thecrypt-gatekeeper.serveousercontent.com/task`
- Groth16 proving live since 2026-11-15; a practice task the same day was scored **CORRECT DECISION** with the platform marking our proof **VERIFIED**
- Round 03 (15 Nov 2026): every competition task the agent answered was scored a correct decision (40.0 points, rank #27 at last check)

## How it works

### Protocol (v1)

1. The platform POSTs a signed task envelope to `/task`. The signature (`x-agent-games-signature`, HMAC-SHA256 hex over the **raw** request body) is verified **before** the body is parsed — bad signature → `401`.
2. Preflight probes (`agent-games.preflight.v1`) are answered with the exact body `{"ok":true,"protocolVersion":"v1"}`, signed like every response.
3. `task_id` is an idempotency key: platform retries return the cached, byte-identical signed response.
4. Every response is signed with the same HMAC header over the raw response body.

### Decision engine — `src/gatekeeper.js`

Each Gatekeeper task is checked against the seven documented conditions, in a safe order (VK → reuse → threshold → expiry → recipient → amount):

| Outcome | reason_code |
|---|---|
| All checks pass | `APPROVE` / `VALID_CONDITION` |
| Proof VK ≠ registered VK | `REJECT` / `VK_SUBSTITUTION` |
| `proof_tx` seen before (persistent seen-set) | `REJECT` / `PROOF_REUSED` |
| Balance below the condition minimum | `REJECT` / `THRESHOLD_MISMATCH` |
| Condition expired at the current block | `REJECT` / `EXPIRED_CONDITION` |
| Recipient ≠ condition recipient | `REJECT` / `RECIPIENT_MISMATCH` |
| Amount above the transfer cap | `REJECT` / `AMOUNT_OVERFLOW` |

### Proving — `src/prove.js`

For every decided task the agent proves its own evaluation in the official `gatekeeper` circuit (Groth16/BN254, via `snarkjs.groth16.fullProve`):

- 13 circuit inputs mapped from the task envelope (`minimum`, `publicBalance`, `amount`, `maxTransfer`, block numbers, recipient fields, VK hashes, `taskId`, `salt`, and `decision` where `1 = APPROVE`, `0 = REJECT`). The circuit itself asserts `decision == computed validity`, so a wrong decision is unprovable by construction.
- The proof is attached as **top-level** `proof` + `public_signals` fields next to `decision`, `reason_code`, and the echoed `proof_tx`.
- Proving takes ~1 s locally — far inside the platform's 60 s deadline. It is **fail-closed**: any proving error or timeout falls back to a proof-less decision response rather than risking the decision points.

## Architecture

Zero-budget, self-healing hosting, built for a 10-hour nightly round window (17:30–03:30 WIB) where a sleeping endpoint forfeits tasks:

- **Service**: dependency-light Node.js (≥20) on `localhost:8787` — no framework, `snarkjs` is the only runtime dependency.
- **Tunnel**: a *reserved* [serveo](https://serveo.net) subdomain (`thecrypt-gatekeeper.serveousercontent.com`, permanent) via SSH on port 443 through an HTTP CONNECT proxy, so reconnects never change the registered URL.
- **Tunnel supervisor**: polls local + public `/health` every 20 s; a dead forward is killed and reconnected in seconds.
- **Guard job**: an external check every 15 minutes runs full endpoint + preflight verification and restarts the stack once if it finds it down.

## Run it

Prerequisites: Node.js ≥ 20, and the official Gatekeeper circuit artifacts (`gatekeeper.wasm`, `gatekeeper_final.zkey`) from the Agent Games build resources, placed in `../circuits/` (or point `CIRCUITS_DIR` at them).

```bash
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET — issued once by
                       # the platform at agent registration; keep it local
npm install
npm start              # node src/server.js, listens on $PORT
npm run smoke          # self-test with a dummy secret (health, 401, decision, idempotency)
```

Endpoints: `GET /health` → `{status:"ok",...}`; `POST /task` → signed task endpoint.

## Layout

| File | Role |
|---|---|
| `src/server.js` | HTTP service, signature verification, routing, idempotency cache, response signing |
| `src/gatekeeper.js` | The 7-condition decision engine |
| `src/prove.js` | Circuit input mapping + Groth16 proving (snarkjs) |
| `src/hmac.js` | HMAC-SHA256 sign/verify helpers (timing-safe) |
| `src/seen.js` | Persistent seen-set for `proof_tx` reuse detection |
| `test/smoke.mjs` | Local self-test with a throwaway secret |

## Security notes

- The platform HMAC secret exists **only** in `.env` (gitignored) or the process environment. It is never logged, never committed, and never appears in any response — only its HMAC output does.
- This service holds **no wallet keys and cannot move funds**. It only evaluates proofs and signs decisions.
- Everything fails closed: bad signature → 401, unknown task type → 400, malformed input → REJECT, proving failure → proof-less decision, never a guessed approval.

---

Built for zkVerify Agent Games Season 01 — Proof Gatekeeper track, and submitted to the Wildcard track as a working example of an autonomous transaction guard.
