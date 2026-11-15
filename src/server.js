import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { sign, verify } from './hmac.js';
import { decide } from './gatekeeper.js';
import { SeenSet } from './seen.js';
import { generateGatekeeperProof, verifyProofOnChain } from './prove.js';

// Agent Games agent endpoint.
// - Platform POSTs HMAC-signed task envelopes to TASK_PATH.
// - We verify x-agent-games-signature over the raw body BEFORE parsing.
// - We answer with a signed JSON response (same header over the raw body).
// - task_id is an idempotency key: retries get the identical cached response.
// - The HMAC secret comes from the environment only. It is never logged.

const PORT = Number(process.env.PORT || 8080);
const TASK_PATH = process.env.TASK_PATH || '/task';
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const ENABLE_PROVING = process.env.ENABLE_PROVING === 'true';
const ONCHAIN_CHECK = process.env.ONCHAIN_CHECK || 'off';
const BUDGET_MS = Number(process.env.RESPONSE_BUDGET_MS || 50000);

const here = dirname(fileURLToPath(import.meta.url));
const seenSet = new SeenSet(join(here, '..', 'data', 'seen-proof-tx.txt'));
const responseCache = new Map(); // task_id -> { body, signature }

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function sendJson(res, status, obj, { signed = false } = {}) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (signed && SECRET) headers['x-agent-games-signature'] = sign(SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
  return body;
}

// Diagnostic logging for rejected/probe requests. Logs header NAMES and
// the signature header's presence/length only — never the secret and
// never a signature value. Bodies are capped; a task body carries no
// secret material.
function logRejection(req, raw, reason) {
  const sig = req.headers['x-agent-games-signature'];
  log(
    'rejected:', reason,
    '| method', req.method,
    '| path', req.url,
    '| content-type', req.headers['content-type'] || '(none)',
    '| headers', Object.keys(req.headers).join(','),
    '| sig', sig ? `present(${String(sig).length} chars)` : 'absent',
    '| body', raw.length, 'bytes:', raw.toString('utf8').slice(0, 4096)
  );
}

// A signed preflight/ping probe may carry an empty or plain-token body
// instead of a JSON envelope.
function isPingBody(raw) {
  const t = raw.toString('utf8').trim().toLowerCase();
  return t === '' || t === 'ping' || t === 'preflight' || t === 'health' || t === 'healthcheck';
}

// The platform's signed preflight is an agent-level probe, NOT a scored
// Gatekeeper task. Its exact envelope and required response are pinned by
// the /build starter prompt (see buildPreflightResponse below); it is
// recognised explicitly by shape and acked. Signature verification still
// applies before this runs, and the Gatekeeper decision validation below
// is untouched.
function isPreflight(task) {
  if (typeof task.type === 'string' && /preflight|ping/i.test(task.type)) return true;
  if (task.mode === 'preflight') return true;
  if (task.preflight === true) return true;
  return false;
}

// --- Protocol-v1 preflight response --------------------------------------
// RESOLVED from the official /build starter prompt (COPY PROMPT — the
// authoritative spec for this platform): the platform's preflight request
// is
//   {"type":"agent-games.preflight.v1","agent_id":"agt_...",
//    "issued_at":"<...>","nonce":"abc123"}
// and the REQUIRED response is exactly
//   {"ok": true, "protocolVersion": "v1"}
// signed with x-agent-games-signature over the raw response body (the
// standard response path in this server applies that header). The body
// is a fixed literal — byte-identical for every preflight, no echoes, no
// extra fields. An earlier inferred envelope (protocol:"v1", status,
// echoed nonce, in-body signature) was rejected by the dashboard
// validator with "The endpoint must return signed protocol-v1 JSON";
// the missing piece was the exact `protocolVersion` field. Confirmed
// against a captured platform preflight (logs/agent.log,
// 2026-11-14T20:15:23Z): its request signature verified with our secret,
// so only the response body was wrong.
function buildPreflightResponse() {
  return { ok: true, protocolVersion: 'v1' };
}

async function handleGatekeeper(task) {
  const started = Date.now();
  const { reason_code, decision } = await decide(task.input, {
    seenSet,
    verifyOnChain: ONCHAIN_CHECK === 'on' ? verifyProofOnChain : null,
  });
  const response = { decision, reason_code, proof_tx: task.input?.proof_tx };

  if (ENABLE_PROVING) {
    // Attach our own Groth16 proof as TOP-LEVEL fields, per the /build
    // starter prompt: { decision, reason_code, proof, public_signals,
    // proof_tx }. An earlier wiring nested {proof, publicSignals} under a
    // single `proof` field — the platform expects them separate. If
    // proving would blow the response budget, send the decision without
    // it: a missing proof costs -2, a timeout also costs -2 but forfeits
    // the decision points too.
    const remaining = BUDGET_MS - (Date.now() - started);
    try {
      const proofBundle = await Promise.race([
        generateGatekeeperProof(task, response),
        new Promise((_, rej) =>
          setTimeout(() => rej(new Error('proving budget exceeded')), Math.max(remaining, 0))
        ),
      ]);
      response.proof = proofBundle.proof;
      response.public_signals = proofBundle.publicSignals;
    } catch (err) {
      log('proving skipped:', err.message);
    }
  }
  return response;
}

// Steal the VFY turn handler — STUB. The tournament paired on 13 Nov and
// entries are locked (see PLAN.md); this exists only so a stray delivery is
// answered deliberately instead of crashing. A missing/invalid response is
// scored by the platform as HOLD.
function handleStealTurn(/* task */) {
  return { action: 'HOLD', _stub: true };
}

const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');

  // Health check: the platform health-checks the endpoint before events.
  // Its exact path/method are not in the public docs — answer on /health
  // and on the root path.
  if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/')) {
    return sendJson(res, 200, { status: 'ok', service: 'agent-games-agent', time: new Date().toISOString() });
  }

  if (req.method !== 'POST' || url.pathname !== TASK_PATH) {
    if (req.method === 'POST') log('miss: POST', url.pathname, '-> 404 (task path is ' + TASK_PATH + ')');
    return sendJson(res, 404, { error: 'not_found' });
  }

  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    const headerSig = req.headers['x-agent-games-signature'];

    // Capture EVERY task request verbatim, accepted or not, BEFORE
    // verification. Task bodies carry no secret material; the signature
    // VALUE is never logged, only its presence/length. This is what lets
    // us read the platform's exact preflight envelope (and anything else
    // it sends) straight from logs/agent.log after a dashboard attempt.
    log(
      'request:', req.method, url.pathname,
      '| content-type', req.headers['content-type'] || '(none)',
      '| headers', Object.keys(req.headers).join(','),
      '| sig', headerSig ? `present(${String(headerSig).length} chars)` : 'absent',
      '| body', raw.length, 'bytes:', raw.toString('utf8').slice(0, 8192)
    );

    // 1) Verify the signature over the RAW body before any parsing.
    if (!verify(SECRET, raw, headerSig)) {
      logRejection(req, raw, 'bad_signature');
      return sendJson(res, 401, { error: 'invalid_signature' }, { signed: true });
    }

    let task;
    try {
      task = JSON.parse(raw.toString('utf8'));
    } catch {
      // A signed ping/preflight probe may carry an empty or plain-token
      // body instead of JSON. Answer it; anything else stays a 400.
      if (isPingBody(raw)) {
        log('preflight ack (non-JSON signed body,', raw.length, 'bytes)');
        return sendJson(res, 200, buildPreflightResponse(), { signed: true });
      }
      logRejection(req, raw, 'invalid_json');
      return sendJson(res, 400, { error: 'invalid_json' }, { signed: true });
    }

    if (!task || typeof task !== 'object' || Array.isArray(task)) {
      logRejection(req, raw, 'invalid_envelope');
      return sendJson(res, 400, { error: 'invalid_envelope' }, { signed: true });
    }

    // 2) Idempotency: same task_id -> identical response.
    const taskId = task.task_id || task.id || null;
    if (taskId && responseCache.has(taskId)) {
      const cached = responseCache.get(taskId);
      res.writeHead(200, {
        'content-type': 'application/json',
        'x-agent-games-signature': cached.signature,
      });
      return res.end(cached.body);
    }

    // 3) Route by envelope type.
    let response;
    try {
      if (isPreflight(task)) {
        // Agent-level signed preflight probe: reply with the exact
        // protocol-v1 body from the /build spec. Not a scored task —
        // no decision is fabricated.
        log('preflight ack for', taskId || '(no id)');
        response = buildPreflightResponse();
      } else if (typeof task.type === 'string' && task.type.startsWith('agent-games.proof-gatekeeper')) {
        response = await handleGatekeeper(task);
      } else if (typeof task.type === 'string' && task.type.includes('steal')) {
        response = { ...handleStealTurn(task), matchId: task.matchId ?? task.input?.matchId, turn: task.turn ?? task.input?.turn };
      } else {
        // Fail closed on anything we do not understand.
        logRejection(req, raw, 'unknown_task_type');
        return sendJson(res, 400, { error: 'unknown_task_type' }, { signed: true });
      }
    } catch (err) {
      log('handler error:', err);
      return sendJson(res, 500, { error: 'internal_error' }, { signed: true });
    }

    const body = JSON.stringify(response);
    const signature = SECRET ? sign(SECRET, body) : '';
    if (taskId) responseCache.set(taskId, { body, signature });
    res.writeHead(200, {
      'content-type': 'application/json',
      ...(signature ? { 'x-agent-games-signature': signature } : {}),
    });
    res.end(body);
    log('answered', taskId || '(no id)', response.decision || response.action || 'ok',
      '| response body:', body.slice(0, 2048));
  });
});

server.listen(PORT, () => {
  log(`agent-games agent listening on :${PORT} (task path ${TASK_PATH})`);
  if (!SECRET) log('WARNING: AGENT_GAMES_HMAC_SECRET is not set — all signed requests will be rejected.');
  log(`proving: ${ENABLE_PROVING ? 'enabled' : 'disabled'}, on-chain check: ${ONCHAIN_CHECK}, seen proof_tx: ${seenSet.size}`);
});
