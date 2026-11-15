import { groth16 } from 'snarkjs';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Local Groth16 proof generation with the OFFICIAL platform circuits
// (downloaded from https://agentgames.zkverify.io/circuits/, hashes served
// by /api/circuit-info):
//   gatekeeper: vkHash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
//   vfyPolicy:  vkHash 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
//
// Circuit input-signal schema — RESOLVED 2026-11-15 by probing the
// production gatekeeper.wasm (FNV-hash input-name oracle + witness
// inspection; see PLAN.md "Proving — input schema (resolved)":
//   13 scalar inputs: minimum, recipient, amount, publicBalance,
//   expiryBlock, currentBlock, conditionRecipient, maxTransfer, decision,
//   salt, registeredVkHash, proofVkHash, taskId.
//   decision: 1 = APPROVE, 0 = REJECT (circuit asserts decision == the
//   validity it computes from the task fields; a wrong decision makes
//   witness generation throw — proving then fails closed to proof-less).
//   salt: private blinding input, folded into public signal 0 (a hash
//   commitment over salt+taskId only). No salt is published by the
//   platform; we use fixed '0' (deterministic; the proof still verifies
//   — see PLAN.md for the residual uncertainty on the platform's
//   taskId/salt expectations).
//   Public signals (13, circuit output order — this is the order snarkjs
//   returns and the platform expects):
//     [0] hash commitment (salt+taskId), [1] proofVkHash, [2] registeredVkHash,
//     [3] minimum, [4] publicBalance, [5] expiryBlock, [6] currentBlock,
//     [7] recipient, [8] conditionRecipient, [9] amount, [10] maxTransfer,
//     [11] decision, [12] taskId.
//   Hex fields (vk hashes, addresses) are plain BigInt field elements;
//   values >= the BN128 scalar-field prime are reduced mod prime by the
//   witness calculator automatically (vkHash 0x6b79... > prime).
//   Comparison strictness in the circuit (verified by boundary probes):
//   balance >= minimum (non-strict), amount <= maxTransfer (non-strict),
//   currentBlock < expiryBlock (STRICT — equality rejects). The decision
//   engine (gatekeeper.js) allows current == expiry; on that rare
//   boundary an APPROVE is correct but unprovable, so proving fails
//   closed to a proof-less response (decision still sent, +12 kept).

const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const here = dirname(fileURLToPath(import.meta.url));

function resolveCircuitsDir() {
  const configured = process.env.CIRCUITS_DIR || '../circuits';
  const fromCwd = resolve(process.cwd(), configured);
  if (existsSync(join(fromCwd, 'gatekeeper.wasm'))) return fromCwd;
  // Fallback: relative to this file (agent/src -> agent-games/circuits).
  const fromFile = resolve(here, '..', '..', 'circuits');
  if (existsSync(join(fromFile, 'gatekeeper.wasm'))) return fromFile;
  return fromCwd; // let fullProve raise the real "file not found" error
}

const CIRCUITS_DIR = resolveCircuitsDir();

// Parse a task field into a decimal string for the circuit. Accepts hex
// ("0x..."), decimal strings, and JSON numbers. Throws on missing/invalid.
function toFieldDecimal(value, name) {
  if (value === undefined || value === null || value === '') {
    throw new Error(`missing circuit input: ${name}`);
  }
  try {
    return BigInt(value).toString();
  } catch {
    throw new Error(`invalid circuit input ${name}: ${JSON.stringify(value)}`);
  }
}

// Encode the envelope task_id string to a field element.
// Real tasks look like "task_R03_5359dc50-dfed-1481-13ad-a42edcffc1f3"
// (prefix + UUID); practice tasks like "verify_1794686877751".
// The UUID portion is 128 bits, fits the field, and is used directly so
// the taskId public signal preserves the task's identity (anti-replay).
// Anything else falls back to a deterministic SHA-256 digest mod prime.
export function encodeTaskId(taskId) {
  if (taskId === undefined || taskId === null || taskId === '') {
    throw new Error('missing task_id for circuit input taskId');
  }
  const s = String(taskId);
  const uuid = s.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i);
  if (uuid) return BigInt('0x' + uuid[1].replace(/-/g, '')).toString();
  const digits = s.match(/(\d+)$/);
  if (digits && /^[\w-]*\d+$/.test(s) && !/^0x/i.test(s)) return BigInt(digits[1]).toString();
  if (/^0x[0-9a-f]+$/i.test(s)) return BigInt(s).toString();
  if (/^\d+$/.test(s)) return BigInt(s).toString();
  const digest = createHash('sha256').update(s, 'utf8').digest('hex');
  return (BigInt('0x' + digest) % FIELD_PRIME).toString();
}

export function buildCircuitInputs(task, decisionObj) {
  const input = task?.input;
  if (!input || typeof input !== 'object') {
    throw new Error('missing task.input for circuit inputs');
  }
  const decision = decisionObj?.decision;
  if (decision !== 'APPROVE' && decision !== 'REJECT') {
    throw new Error(`unknown decision for circuit input: ${JSON.stringify(decision)}`);
  }
  return {
    registeredVkHash: toFieldDecimal(input.registered_vk, 'registered_vk'),
    proofVkHash: toFieldDecimal(input.proof_vk, 'proof_vk'),
    minimum: toFieldDecimal(input.minimum, 'minimum'),
    publicBalance: toFieldDecimal(input.public_balance, 'public_balance'),
    expiryBlock: toFieldDecimal(input.expiry_block, 'expiry_block'),
    currentBlock: toFieldDecimal(input.current_block, 'current_block'),
    recipient: toFieldDecimal(input.recipient, 'recipient'),
    conditionRecipient: toFieldDecimal(input.condition_recipient, 'condition_recipient'),
    amount: toFieldDecimal(input.amount, 'amount'),
    maxTransfer: toFieldDecimal(input.max_transfer, 'max_transfer'),
    decision: decision === 'APPROVE' ? '1' : '0',
    salt: '0',
    taskId: encodeTaskId(task.task_id ?? task.id),
  };
}

export async function generateProof(circuitName, inputs) {
  const wasm = join(CIRCUITS_DIR, `${circuitName}.wasm`);
  const zkey = join(CIRCUITS_DIR, `${circuitName}_final.zkey`);
  const { proof, publicSignals } = await groth16.fullProve(inputs, wasm, zkey);
  return { proof, publicSignals };
}

export async function generateGatekeeperProof(task, decisionObj) {
  const t0 = Date.now();
  const inputs = buildCircuitInputs(task, decisionObj);
  const { proof, publicSignals } = await generateProof('gatekeeper', inputs);
  const provingMs = Date.now() - t0;
  // Log the proving time + public signals (no secret material; the proof
  // itself is public evidence). Lets us audit what the platform received
  // if a proof is ever rejected.
  console.log(
    new Date().toISOString(),
    `proving ok in ${provingMs}ms decision=${decisionObj?.decision} task=${task?.task_id} ` +
      `publicSignals=${JSON.stringify(publicSignals)}`
  );
  return { proof, publicSignals, provingMs };
}

// Placeholder for the on-chain proof_tx lookup (build checklist step 02).
// Real wiring options, per the Build guide §03:
//   - Kurier REST API (needs a mainnet API key — external signup, user action)
//   - zkVerifyJS (Volta session; the docs mention a funded account)
// Until one is chosen and configured this returns 'unknown', which the
// decision engine treats as non-blocking (see ONCHAIN_CHECK in .env.example).
export async function verifyProofOnChain(/* proofTx, proofVk */) {
  return 'unknown';
}
