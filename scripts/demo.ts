// Runnable, narrated walkthrough of the full VC lifecycle: issue a
// credential, verify it, revoke it, verify again. Uses an in-memory status
// list store (same helper the test suite uses) rather than Postgres, so
// this runs anywhere with zero setup — no DATABASE_URL required. See
// README's Phase 4 section for why "real or test DB" includes this.
import { generateDidKey } from '../src/did/generateDid.js';
import { issueCredential } from '../src/issuer/issueCredential.js';
import { verifyCredential, type VerifyResult } from '../src/verifier/verifyCredential.js';
import type { StatusListResolver } from '../src/verifier/checkCredentialStatus.js';
import {
  getOrCreateStatusList,
  allocateStatusListIndex,
  buildCredentialStatusEntry,
  revokeByStatusListIndex,
  buildSignedStatusListCredential,
} from '../src/revocation/statusListService.js';
import { createInMemoryStatusListRepo } from '../test/helpers/inMemoryStatusListRepo.js';

const BASE_URL = 'http://localhost:3000';

function printChecks(result: VerifyResult) {
  console.log(`    valid: ${result.valid}`);
  console.log(
    `    checks: schema=${result.checks.schema}  signature=${result.checks.signature}  status=${result.checks.status}`,
  );
  if (result.errors.length > 0) {
    console.log(`    errors: ${result.errors.join('; ')}`);
  }
}

async function main() {
  console.log('=== Verifiable Credential lifecycle demo (did:key + StatusList2021) ===\n');

  process.stdout.write('Step 1: Generating issuer DID... ');
  const issuer = await generateDidKey();
  console.log(`✓ ${issuer.did}`);

  process.stdout.write('Step 2: Generating holder DID... ');
  const holder = await generateDidKey();
  console.log(`✓ ${holder.did}`);

  const repo = createInMemoryStatusListRepo();
  const resolveStatusListCredential: StatusListResolver = async (url) => {
    const prefix = `${BASE_URL}/api/status-lists/`;
    if (!url.startsWith(prefix)) return null;
    const record = await repo.findById(url.slice(prefix.length));
    if (!record) return null;
    return buildSignedStatusListCredential(record, issuer, BASE_URL);
  };

  process.stdout.write('Step 3: Issuing a credential from issuer to holder... ');
  const statusList = await getOrCreateStatusList(repo, issuer.did);
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
  console.log(`✓ ${document.id} (statusListIndex=${index})`);

  console.log('\nStep 4: Verifying the freshly issued credential...');
  const firstResult = await verifyCredential(document, resolveStatusListCredential);
  printChecks(firstResult);

  process.stdout.write('\nStep 5: Revoking the credential... ');
  await revokeByStatusListIndex(repo, statusList.id, index);
  console.log('✓ done');

  console.log('\nStep 6: Verifying again after revocation...');
  const secondResult = await verifyCredential(document, resolveStatusListCredential);
  printChecks(secondResult);
  console.log('    (schema + signature are unaffected by revocation — only status flips)');

  console.log('\n=== Demo complete ===');
}

main().catch((err) => {
  console.error('\nDemo failed:', err);
  process.exitCode = 1;
});
