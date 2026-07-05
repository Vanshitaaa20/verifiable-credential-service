import { describe, it, expect } from 'vitest';
import { generateDidKey } from '../../src/did/generateDid.js';
import { issueCredential } from '../../src/issuer/issueCredential.js';
import { verifyCredential } from '../../src/verifier/verifyCredential.js';

async function issueTestCredential() {
  const issuer = await generateDidKey();
  const holder = await generateDidKey();
  const { document } = await issueCredential({
    issuerDid: issuer.did,
    issuerVerificationMethodId: issuer.verificationMethodId,
    issuerPublicKeyMultibase: issuer.publicKeyMultibase,
    issuerPrivateKeyMultibase: issuer.privateKeyMultibase,
    holderDid: holder.did,
    type: [],
    claims: {},
  });
  return { issuer, holder, document };
}

describe('Phase 2: verifyCredential', () => {
  it('happy path: a validly signed credential verifies', async () => {
    const { document } = await issueTestCredential();

    const result = await verifyCredential(document);

    expect(result.valid).toBe(true);
    // No credentialStatus on this credential -> status check treats it as
    // not applicable/"unrevocable" rather than failing (see Phase 3 notes).
    expect(result.checks).toEqual({ schema: true, signature: true, status: true });
    expect(result.errors).toEqual([]);
  });

  it('tamper test: mutating a claim after signing fails the signature check specifically', async () => {
    const { document } = await issueTestCredential();

    const tampered = {
      ...document,
      credentialSubject: {
        ...(document.credentialSubject as object),
        id: 'did:key:z6MkSomeoneElseEntirely',
      },
    };

    const result = await verifyCredential(tampered);

    expect(result.valid).toBe(false);
    expect(result.checks.schema).toBe(true);
    expect(result.checks.signature).toBe(false);
    expect(result.errors.join(' ')).toMatch(/signature/i);
  });

  it('bad context test: an unknown @context fails schema check before any signature work', async () => {
    const { document } = await issueTestCredential();

    const badContext = {
      ...document,
      '@context': ['https://example.com/not-a-real-context'],
    };

    const result = await verifyCredential(badContext);

    expect(result.valid).toBe(false);
    expect(result.checks.schema).toBe(false);
    // Signature check must not have run at all — it should report exactly
    // the same false-by-default value it started with, not a real attempt.
    expect(result.checks.signature).toBe(false);
    expect(result.errors.some((e) => e.includes('@context'))).toBe(true);
  });

  it('malformed context test: a non-array/non-string @context is rejected structurally', async () => {
    const { document } = await issueTestCredential();

    const malformed = {
      ...document,
      '@context': { not: 'a valid context shape' },
    };

    const result = await verifyCredential(malformed);

    expect(result.valid).toBe(false);
    expect(result.checks.schema).toBe(false);
  });

  it('unknown-issuer test: a credential from a DID we never generated still resolves and verifies (did:key is self-certifying)', async () => {
    // Simulates a VC presented by a totally independent issuer this service
    // has no record of — did:key needs no registry, so resolution and
    // signature verification both succeed on their own. Whether that
    // "unknown issuer" should be trusted is a separate policy decision this
    // project's scope doesn't implement — see the trust-model note in
    // verifyCredential.ts.
    const { document } = await issueTestCredential();

    const result = await verifyCredential(document);

    expect(result.checks.signature).toBe(true);
    expect(result.valid).toBe(true);
  });
});
