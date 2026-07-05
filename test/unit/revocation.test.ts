import { describe, it, expect } from 'vitest';
import { generateDidKey } from '../../src/did/generateDid.js';
import { issueCredential } from '../../src/issuer/issueCredential.js';
import { verifyCredential } from '../../src/verifier/verifyCredential.js';
import type { StatusListResolver } from '../../src/verifier/checkCredentialStatus.js';
import {
  getOrCreateStatusList,
  allocateStatusListIndex,
  buildCredentialStatusEntry,
  revokeByStatusListIndex,
  isRevoked,
  buildSignedStatusListCredential,
} from '../../src/revocation/statusListService.js';
import { createInMemoryStatusListRepo } from '../helpers/inMemoryStatusListRepo.js';

const BASE_URL = 'http://localhost:3000';

async function setup() {
  const repo = createInMemoryStatusListRepo();
  const issuer = await generateDidKey();
  const holder = await generateDidKey();
  const statusList = await getOrCreateStatusList(repo, issuer.did);

  // Mirrors verifier.routes.ts's in-process resolver, backed by the
  // in-memory repo instead of Prisma.
  const resolveStatusListCredential: StatusListResolver = async (url) => {
    const prefix = `${BASE_URL}/api/status-lists/`;
    if (!url.startsWith(prefix)) return null;
    const record = await repo.findById(url.slice(prefix.length));
    if (!record) return null;
    return buildSignedStatusListCredential(record, issuer, BASE_URL);
  };

  async function issue() {
    const index = await allocateStatusListIndex(repo, statusList.id);
    const credentialStatus = buildCredentialStatusEntry({
      statusListId: statusList.id,
      index,
      baseUrl: BASE_URL,
    });
    const { document } = await issueCredential({
      issuerDid: issuer.did,
      issuerVerificationMethodId: issuer.verificationMethodId,
      issuerPublicKeyMultibase: issuer.publicKeyMultibase,
      issuerPrivateKeyMultibase: issuer.privateKeyMultibase,
      holderDid: holder.did,
      type: [],
      claims: {},
      credentialStatus,
    });
    return { document, index };
  }

  return { repo, issuer, holder, statusList, resolveStatusListCredential, issue };
}

describe('Phase 3: StatusList2021 revocation', () => {
  it('a freshly issued credential is not revoked', async () => {
    const { issue, resolveStatusListCredential } = await setup();
    const { document } = await issue();

    const result = await verifyCredential(document, resolveStatusListCredential);

    expect(result.checks).toEqual({ schema: true, signature: true, status: true });
    expect(result.valid).toBe(true);
  });

  it('revoking flips the status check to false while schema/signature stay independent', async () => {
    const { repo, statusList, issue, resolveStatusListCredential } = await setup();
    const { document, index } = await issue();

    await revokeByStatusListIndex(repo, statusList.id, index);

    const result = await verifyCredential(document, resolveStatusListCredential);

    expect(result.checks.schema).toBe(true);
    expect(result.checks.signature).toBe(true);
    expect(result.checks.status).toBe(false);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('revoking one credential does not affect another on the same status list (bit-level isolation)', async () => {
    const { repo, statusList, issue, resolveStatusListCredential } = await setup();
    const credentialA = await issue();
    const credentialB = await issue();

    expect(credentialA.index).not.toBe(credentialB.index);

    await revokeByStatusListIndex(repo, statusList.id, credentialA.index);

    const resultA = await verifyCredential(credentialA.document, resolveStatusListCredential);
    const resultB = await verifyCredential(credentialB.document, resolveStatusListCredential);

    expect(resultA.checks.status).toBe(false);
    expect(resultB.checks.status).toBe(true);
    expect(resultB.valid).toBe(true);

    expect(await isRevoked(repo, statusList.id, credentialA.index)).toBe(true);
    expect(await isRevoked(repo, statusList.id, credentialB.index)).toBe(false);
  });

  it('a credential with no credentialStatus at all is treated as unrevocable (status check passes)', async () => {
    // credentialStatus is optional per the VC spec, and Phase 1/2 both
    // issue and verify bare VerifiableCredentials with no status tracking.
    // "Not revocable" must stay distinguishable from "revoked" — otherwise
    // this check would silently break every non-revocable credential type.
    const { issuer, holder, resolveStatusListCredential } = await setup();

    const { document } = await issueCredential({
      issuerDid: issuer.did,
      issuerVerificationMethodId: issuer.verificationMethodId,
      issuerPublicKeyMultibase: issuer.publicKeyMultibase,
      issuerPrivateKeyMultibase: issuer.privateKeyMultibase,
      holderDid: holder.did,
      type: [],
      claims: {},
      // no credentialStatus
    });

    const result = await verifyCredential(document, resolveStatusListCredential);

    expect(result.checks).toEqual({ schema: true, signature: true, status: true });
    expect(result.valid).toBe(true);
  });

  it('a credential with a malformed statusListIndex fails the status check closed', async () => {
    // Unlike total absence, a credentialStatus that IS present but broken
    // (garbage index, missing required fields) is either tampered with or
    // buggy — this must not be treated as "valid," or checking status
    // would be meaningless whenever the declaration itself is untrustworthy.
    const { issuer, holder, statusList, resolveStatusListCredential } = await setup();

    const { document } = await issueCredential({
      issuerDid: issuer.did,
      issuerVerificationMethodId: issuer.verificationMethodId,
      issuerPublicKeyMultibase: issuer.publicKeyMultibase,
      issuerPrivateKeyMultibase: issuer.privateKeyMultibase,
      holderDid: holder.did,
      type: [],
      claims: {},
      credentialStatus: {
        id: `${BASE_URL}/api/status-lists/${statusList.id}#not-a-number`,
        type: 'StatusList2021Entry',
        statusPurpose: 'revocation',
        statusListIndex: 'not-a-number',
        statusListCredential: `${BASE_URL}/api/status-lists/${statusList.id}`,
      },
    });

    const result = await verifyCredential(document, resolveStatusListCredential);

    expect(result.checks.schema).toBe(true);
    expect(result.checks.signature).toBe(true);
    expect(result.checks.status).toBe(false);
    expect(result.valid).toBe(false);
  });
});
