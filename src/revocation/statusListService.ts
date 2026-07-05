import { createList, decodeList, createCredential } from '@digitalbazaar/vc-status-list';
import * as vc from '@digitalbazaar/vc';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { createDocumentLoader } from '../did/resolver.js';
import type { StatusListRepo, StatusListRecord } from './statusListRepo.js';

// The StatusList2021 spec recommends a minimum list size of 131,072 entries
// so the "anonymity set" a revocation event reveals membership in is large
// enough that a verifier can't infer much about which small issuance batch
// a credential came from just by knowing its index. We use a much smaller
// size so tests and demo runs stay fast — a deliberate deviation from the
// spec's privacy recommendation for this project's scope, not an oversight.
export const STATUS_LIST_SIZE = 16384;
export const DEFAULT_PURPOSE = 'revocation';

export interface IssuerKeyMaterial {
  did: string;
  verificationMethodId: string;
  publicKeyMultibase: string;
  privateKeyMultibase: string;
}

export async function getOrCreateStatusList(
  repo: StatusListRepo,
  issuerDid: string,
  purpose: string = DEFAULT_PURPOSE,
): Promise<StatusListRecord> {
  const existing = await repo.findByIssuerAndPurpose(issuerDid, purpose);
  if (existing) return existing;

  const list = await createList({ length: STATUS_LIST_SIZE });
  const encodedList = await list.encode();
  return repo.create({ issuerDid, purpose, encodedList, nextIndex: 0 });
}

// Read-then-write, NOT atomic. Two concurrent issuances against the same
// status list could read the same nextIndex and collide. Acceptable for a
// single-process demo; a production issuer would allocate indexes with a
// DB-level atomic increment (e.g. `UPDATE ... SET next_index = next_index +
// 1 RETURNING next_index` in one statement) or a row lock, not a
// read-modify-write round trip from application code. List growth is also
// unhandled: once nextIndex reaches STATUS_LIST_SIZE this throws rather than
// rolling over to a second list — a real issuer would provision a new
// StatusList (new row, new purpose suffix or index) when one fills up.
export async function allocateStatusListIndex(
  repo: StatusListRepo,
  statusListId: string,
): Promise<number> {
  const record = await repo.findById(statusListId);
  if (!record) throw new Error(`Status list ${statusListId} not found`);
  if (record.nextIndex >= STATUS_LIST_SIZE) {
    throw new Error(
      `Status list ${statusListId} is full (capacity ${STATUS_LIST_SIZE}); ` +
        'provisioning a new list is not implemented in this demo.',
    );
  }
  const index = record.nextIndex;
  await repo.update(statusListId, { nextIndex: index + 1 });
  return index;
}

export function buildCredentialStatusEntry(input: {
  statusListId: string;
  index: number;
  baseUrl: string;
  purpose?: string;
}) {
  const statusListCredentialUrl = `${input.baseUrl}/api/status-lists/${input.statusListId}`;
  return {
    id: `${statusListCredentialUrl}#${input.index}`,
    type: 'StatusList2021Entry' as const,
    statusPurpose: input.purpose ?? DEFAULT_PURPOSE,
    statusListIndex: String(input.index),
    statusListCredential: statusListCredentialUrl,
  };
}

export async function revokeByStatusListIndex(
  repo: StatusListRepo,
  statusListId: string,
  index: number,
): Promise<void> {
  const record = await repo.findById(statusListId);
  if (!record) throw new Error(`Status list ${statusListId} not found`);
  const list = await decodeList({ encodedList: record.encodedList });
  list.setStatus(index, true);
  const encodedList = await list.encode();
  await repo.update(statusListId, { encodedList });
}

export async function isRevoked(
  repo: StatusListRepo,
  statusListId: string,
  index: number,
): Promise<boolean> {
  const record = await repo.findById(statusListId);
  if (!record) throw new Error(`Status list ${statusListId} not found`);
  const list = await decodeList({ encodedList: record.encodedList });
  return list.getStatus(index);
}

// Builds and signs the StatusList2021Credential document for a given
// record, fresh on every call from the single source of truth
// (`record.encodedList`) rather than caching a previously-signed copy — so
// the issuer side of this service is never the source of staleness. Whether
// a *verifier* caches what it fetches from here is a separate question
// (see README's Phase 3 trade-off).
export async function buildSignedStatusListCredential(
  record: StatusListRecord,
  issuerKey: IssuerKeyMaterial,
  baseUrl: string,
): Promise<Record<string, unknown>> {
  const list = await decodeList({ encodedList: record.encodedList });
  const id = `${baseUrl}/api/status-lists/${record.id}`;
  const unsigned = await createCredential({ id, list, statusPurpose: record.purpose });
  unsigned.issuer = issuerKey.did;
  unsigned.issuanceDate = new Date().toISOString();

  const signingKey = await Ed25519VerificationKey2020.from({
    id: issuerKey.verificationMethodId,
    controller: issuerKey.did,
    publicKeyMultibase: issuerKey.publicKeyMultibase,
    privateKeyMultibase: issuerKey.privateKeyMultibase,
  });
  const suite = new Ed25519Signature2020({ key: signingKey });
  const documentLoader = createDocumentLoader(issuerKey.did);

  return (await vc.issue({ credential: unsigned, suite, documentLoader })) as Record<string, unknown>;
}
