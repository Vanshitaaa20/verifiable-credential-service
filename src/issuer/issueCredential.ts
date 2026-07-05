import * as vc from '@digitalbazaar/vc';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { constants as statusListConstants } from '@digitalbazaar/vc-status-list-context';
import { createDocumentLoader } from '../did/resolver.js';
import { randomUUID } from 'node:crypto';

export interface CredentialStatusEntry {
  id: string;
  type: 'StatusList2021Entry';
  statusPurpose: string;
  statusListIndex: string;
  statusListCredential: string;
}

// NOTE: `type` entries and `claims` keys beyond the base VC context
// (https://www.w3.org/2018/credentials/v1) must be backed by a JSON-LD
// @context that defines them, or verification fails under jsonld-signatures'
// safe-mode expansion ("Safe mode validation error" — an undefined term has
// no absolute IRI to canonicalize). Phase 1 only issues bare
// VerifiableCredentials; adding real credential types/claims (Phase 2+)
// means authoring and locally bundling a matching context, the same way
// contexts.ts bundles the base contexts instead of fetching them over HTTP.
export interface IssueCredentialInput {
  issuerDid: string;
  issuerVerificationMethodId: string;
  issuerPublicKeyMultibase: string;
  issuerPrivateKeyMultibase: string;
  holderDid: string;
  type: string[];
  claims: Record<string, unknown>;
  // Optional: a credential with no credentialStatus is treated by
  // verifyCredential as unrevocable/always-valid on the status check, not
  // as failing it (see checkCredentialStatus.ts). The issuer.routes.ts HTTP
  // route always attaches one; omitting it here is for credential types
  // that genuinely never participate in revocation tracking.
  credentialStatus?: CredentialStatusEntry;
}

export interface IssuedCredential {
  credentialId: string;
  document: Record<string, unknown>;
}

export async function issueCredential(input: IssueCredentialInput): Promise<IssuedCredential> {
  const signingKey = await Ed25519VerificationKey2020.from({
    id: input.issuerVerificationMethodId,
    controller: input.issuerDid,
    publicKeyMultibase: input.issuerPublicKeyMultibase,
    privateKeyMultibase: input.issuerPrivateKeyMultibase,
  });

  const suite = new Ed25519Signature2020({ key: signingKey });
  const documentLoader = createDocumentLoader(input.issuerDid);

  const credentialId = `urn:uuid:${randomUUID()}`;

  // A credentialStatus of type StatusList2021Entry is itself a term defined
  // by the StatusList2021 context — same safe-mode rule as any other custom
  // type/claim (see note above), so it must be added to @context whenever
  // credentialStatus is present.
  const contexts: string[] = ['https://www.w3.org/2018/credentials/v1'];
  if (input.credentialStatus) {
    contexts.push(statusListConstants.CONTEXT_URL_V1);
  }

  const credential = {
    '@context': contexts,
    id: credentialId,
    type: ['VerifiableCredential', ...input.type],
    issuer: input.issuerDid,
    issuanceDate: new Date().toISOString(),
    ...(input.credentialStatus ? { credentialStatus: input.credentialStatus } : {}),
    credentialSubject: {
      id: input.holderDid,
      ...input.claims,
    },
  };

  const signed = await vc.issue({ credential, suite, documentLoader });

  return { credentialId, document: signed as Record<string, unknown> };
}
