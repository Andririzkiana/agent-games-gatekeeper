// Local smoke test: boots the server on an ephemeral port with a DUMMY
// secret (never the platform secret), then checks:
//   1. GET /health answers 200
//   2. POST /task with a bad signature is rejected (401)
//   3. POST /task with a correct signature returns the documented decision
//      for the official sample-shaped payload (VK substitution -> REJECT)
//   4. Re-sending the same task_id returns the identical cached body
// Run: npm run smoke

import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';

const PORT = 18099;
const SECRET = 'dummy-local-test-secret-not-the-platform-secret';
const BASE = `http://127.0.0.1:${PORT}`;

const sign = (raw) => createHmac('sha256', SECRET).update(raw).digest('hex');

const validTask = {
  type: 'agent-games.proof-gatekeeper.v1',
  task_id: 'gk_smoke_1',
  mode: 'practice',
  issued_at: new Date().toISOString(),
  deadline_at: new Date(Date.now() + 60000).toISOString(),
  input: {
    registered_vk: '0xAAA',
    proof_vk: '0xBBB', // mismatch -> VK_SUBSTITUTION
    minimum: '1000',
    public_balance: '1460',
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: '0xDe42',
    condition_recipient: '0xDe42',
    amount: '500',
    max_transfer: '1000',
    proof_tx: '0xSMOKE1',
  },
};

function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function main() {
  const child = spawn('node', ['src/server.js'], {
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));
  try {
    await wait(800);

    const health = await fetch(`${BASE}/health`);
    console.log('health:', health.status);
    if (health.status !== 200) throw new Error('health check failed');

    const raw = JSON.stringify(validTask);
    const bad = await fetch(`${BASE}/task`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': 'deadbeef' },
      body: raw,
    });
    console.log('bad signature:', bad.status);
    if (bad.status !== 401) throw new Error('bad signature was not rejected');

    const good = await fetch(`${BASE}/task`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(raw) },
      body: raw,
    });
    const goodBody = await good.text();
    console.log('signed task:', good.status, goodBody);
    const parsed = JSON.parse(goodBody);
    if (parsed.decision !== 'REJECT' || parsed.reason_code !== 'VK_SUBSTITUTION') {
      throw new Error('unexpected decision for VK-mismatch sample');
    }
    if (!good.headers.get('x-agent-games-signature')) {
      throw new Error('response was not signed');
    }
    // When proving is enabled (ENABLE_PROVING=true in the environment),
    // the response must carry the Groth16 proof as TOP-LEVEL `proof` +
    // `public_signals` (13 entries, circuit output order). When proving
    // is off the fields are absent and this check is a no-op.
    if (parsed.proof !== undefined || parsed.public_signals !== undefined) {
      const p = parsed.proof;
      if (!p || !Array.isArray(p.pi_a) || !Array.isArray(p.pi_b) || !Array.isArray(p.pi_c)) {
        throw new Error('proof field present but malformed (expected pi_a/pi_b/pi_c)');
      }
      if (!Array.isArray(parsed.public_signals) || parsed.public_signals.length !== 13) {
        throw new Error('public_signals must have exactly 13 entries');
      }
      if (parsed.proof.publicSignals !== undefined || parsed.proof.proof !== undefined) {
        throw new Error('proof must not nest the bundle (proof/publicSignals belong top-level)');
      }
      console.log('proof shape OK: pi_a/pi_b/pi_c + 13 public_signals');
    }

    const again = await fetch(`${BASE}/task`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(raw) },
      body: raw,
    });
    const againBody = await again.text();
    console.log('idempotent replay identical:', againBody === goodBody);
    if (againBody !== goodBody) throw new Error('idempotency broken');

    console.log('SMOKE OK');
  } finally {
    child.kill('SIGTERM');
  }
}

main().catch((e) => {
  console.error('SMOKE FAILED:', e.message);
  process.exit(1);
});
