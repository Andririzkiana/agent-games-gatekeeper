import { createHmac, timingSafeEqual } from 'node:crypto';

// The platform signs every request with the header `x-agent-games-signature`
// (HMAC over the RAW body, secret issued at agent registration — Rules 1.3),
// and expects every response signed the same way (Build guide §04).
// Digest/encoding are NOT stated in the public docs text: they are config
// (defaults sha256/hex) and must be confirmed via signed preflight / practice.

const ALGORITHM = process.env.HMAC_ALGORITHM || 'sha256';
const ENCODING = process.env.HMAC_ENCODING || 'hex';

export function sign(secret, rawBody) {
  return createHmac(ALGORITHM, secret).update(rawBody).digest(ENCODING);
}

export function verify(secret, rawBody, headerValue) {
  if (!secret || !headerValue || typeof headerValue !== 'string') return false;
  const expected = sign(secret, rawBody);
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(headerValue, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
