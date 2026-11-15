// Proof Gatekeeper decision engine.
// Implements the seven documented conditions from the official event page
// (agentgames.zkverify.io/events/proof-gatekeeper). The published trap
// distribution sums to 100%, i.e. exactly one condition per task; the check
// order below follows the official "Agent build checklist" where sensible.
//
// All comparisons use the task's own fields. Numeric fields arrive as
// strings in the sample payload, so compare with BigInt.

function bi(v) {
  try {
    return BigInt(v);
  } catch {
    return null;
  }
}

function addrEq(a, b) {
  return (
    typeof a === 'string' &&
    typeof b === 'string' &&
    a.toLowerCase() === b.toLowerCase()
  );
}

/**
 * @param {object} input  task.input from the signed envelope
 * @param {object} ctx    { seenSet, verifyOnChain } — verifyOnChain(proof_tx, proof_vk)
 *                        may return true/false/'unknown'. 'unknown' (the default
 *                        while ONCHAIN_CHECK=off) does not block the decision.
 * @returns {{decision: string, reason_code: string}}
 */
export async function decide(input, ctx) {
  const reject = (reason_code) => ({ decision: 'REJECT', reason_code });

  if (!input || typeof input !== 'object') return reject('MALFORMED_INPUT');

  // 1) VK_SUBSTITUTION — proof verifies under a different VK than registered.
  if (!addrEq(input.proof_vk, input.registered_vk) && input.proof_vk !== input.registered_vk) {
    return reject('VK_SUBSTITUTION');
  }

  // 2) PROOF_REUSED — this proof reference was already accepted/seen before.
  if (input.proof_tx && ctx.seenSet.has(input.proof_tx)) {
    return reject('PROOF_REUSED');
  }

  // 3) THRESHOLD_MISMATCH — disclosed public balance below required minimum.
  const bal = bi(input.public_balance);
  const min = bi(input.minimum);
  if (bal !== null && min !== null && bal < min) {
    return reject('THRESHOLD_MISMATCH');
  }

  // 4) EXPIRED_CONDITION — current block height past the condition expiry.
  const cur = bi(input.current_block);
  const exp = bi(input.expiry_block);
  if (cur !== null && exp !== null && cur > exp) {
    return reject('EXPIRED_CONDITION');
  }

  // 5) RECIPIENT_MISMATCH — proof recipient != condition recipient.
  if (!addrEq(input.recipient, input.condition_recipient)) {
    return reject('RECIPIENT_MISMATCH');
  }

  // 6) AMOUNT_OVERFLOW — requested amount above the single-transfer cap.
  const amt = bi(input.amount);
  const cap = bi(input.max_transfer);
  if (amt !== null && cap !== null && amt > cap) {
    return reject('AMOUNT_OVERFLOW');
  }

  // 7) On-chain confirmation (build checklist step 02): the referenced proof
  //    must actually be on-chain/verified on zkVerify. Wiring depends on the
  //    chosen path (Kurier API key or zkVerifyJS session) — see prove.js and
  //    PLAN.md. The docs do NOT publish a reason_code for "proof not found
  //    on-chain"; if the check is enabled and returns false we fail closed
  //    with the placeholder code below. PLACEHOLDER — confirm in practice.
  if (ctx.verifyOnChain) {
    const ok = await ctx.verifyOnChain(input.proof_tx, input.proof_vk);
    if (ok === false) return reject('PROOF_NOT_VERIFIED'); // PLACEHOLDER code
  }

  // Record the reference as seen only after it survived the reuse check.
  if (input.proof_tx) ctx.seenSet.add(input.proof_tx);

  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}
