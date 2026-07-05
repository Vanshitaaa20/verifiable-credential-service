// Verification requests aren't persisted anywhere (verify is a pure,
// stateless check — see verifier.routes.ts), so this in-memory counter is
// the only record of them. It resets on process restart; fine for the
// dashboard's "since last deploy" framing, not meant as durable analytics.
let verificationRequestCount = 0;

export function recordVerificationRequest(): void {
  verificationRequestCount += 1;
}

export function getVerificationRequestCount(): number {
  return verificationRequestCount;
}
