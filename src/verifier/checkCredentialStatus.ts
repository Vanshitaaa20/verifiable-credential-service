import { checkStatus } from '@digitalbazaar/vc-status-list';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { createDocumentLoader } from '../did/resolver.js';

export interface StatusCheckResult {
  valid: boolean;
  errors: string[];
}

// Given a `credentialStatus.statusListCredential` URL, return the signed
// StatusList2021Credential document it refers to, or null if unresolvable.
// In this service the "real" implementation (verifier.routes.ts) resolves
// this in-process against Prisma instead of making an HTTP round trip to
// its own GET /api/status-lists/:id route — same shortcut Phase 1 took for
// resolving did:key locally instead of over a network. An external verifier
// without DB access would genuinely fetch the URL over HTTP and land on
// that route, which serves the identical signed JSON.
export type StatusListResolver = (
  statusListCredentialUrl: string,
) => Promise<Record<string, unknown> | null>;

// Two distinct failure surfaces, handled deliberately differently (see
// README's Phase 3 write-up):
//
// - credentialStatus entirely ABSENT: treated as "unrevocable/always
//   valid" for the status check. credentialStatus is optional per the VC
//   spec — a credential type that never opted into revocation tracking has
//   nothing to check, and Phase 1/2 both issue and verify bare
//   VerifiableCredentials with no status tracking at all. Failing those
//   closed would make "not revocable" indistinguishable from "revoked."
// - credentialStatus PRESENT but malformed (wrong shape, missing/garbage
//   statusListIndex, etc.): fails closed. A credential that declares it
//   participates in revocation tracking but does so with a broken
//   declaration is either tampered with or buggy — silently treating that
//   as "valid" would undermine the entire point of checking status at all.
export async function checkCredentialStatus(
  credential: Record<string, unknown>,
  resolveStatusListCredential: StatusListResolver,
): Promise<StatusCheckResult> {
  const credentialStatus = credential.credentialStatus;
  if (credentialStatus === undefined || credentialStatus === null) {
    return { valid: true, errors: [] };
  }
  if (typeof credentialStatus !== 'object') {
    return { valid: false, errors: ['credentialStatus is present but malformed'] };
  }

  const issuerDid = credential.issuer as string;
  const didAndContextLoader = createDocumentLoader(issuerDid);
  const documentLoader = async (url: string) => {
    const statusListDoc = await resolveStatusListCredential(url);
    if (statusListDoc) {
      return { document: statusListDoc, documentUrl: url };
    }
    return didAndContextLoader(url);
  };

  const result = await checkStatus({
    credential,
    documentLoader,
    suite: new Ed25519Signature2020(),
  });

  if (result.verified) {
    return { valid: true, errors: [] };
  }

  const message =
    result.error instanceof Error ? result.error.message : 'credential status indicates revocation';
  return { valid: false, errors: [message] };
}
