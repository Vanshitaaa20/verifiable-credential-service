import { describe, it, expect } from 'vitest';
import * as vc from '@digitalbazaar/vc';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { generateDidKey } from '../../src/did/generateDid.js';
import { issueCredential } from '../../src/issuer/issueCredential.js';
import { createDocumentLoader } from '../../src/did/resolver.js';

describe('Phase 1: did:key generation + VC issuance', () => {
  it('generates a resolvable did:key identity', async () => {
    const issuer = await generateDidKey();
    expect(issuer.did.startsWith('did:key:z6Mk')).toBe(true);
    expect(issuer.verificationMethodId.startsWith(issuer.did)).toBe(true);
    expect(issuer.privateKeyMultibase).toBeTruthy();
  });

  it('issues a credential that verifies against the issuer DID', async () => {
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

    expect(document.issuer).toBe(issuer.did);
    expect((document.proof as { type: string }).type).toBe('Ed25519Signature2020');

    // Sanity check the signature is genuinely valid, not just present.
    // The dedicated Verifier service (schema + revocation checks) is Phase 2 —
    // this only proves Phase 1's crypto round-trips correctly.
    const result = await vc.verifyCredential({
      credential: document,
      suite: new Ed25519Signature2020(),
      documentLoader: createDocumentLoader(issuer.did),
    });

    expect(result.verified).toBe(true);
  });

  it('fails verification if the credential payload is tampered with', async () => {
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

    const tampered = {
      ...document,
      credentialSubject: { ...(document.credentialSubject as object), id: 'did:key:tampered' },
    };

    const result = await vc.verifyCredential({
      credential: tampered,
      suite: new Ed25519Signature2020(),
      documentLoader: createDocumentLoader(issuer.did),
    });

    expect(result.verified).toBe(false);
  });
});
