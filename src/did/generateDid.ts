import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { didKeyDriver } from './keyDriver.js';

export interface GeneratedDid {
  did: string;
  verificationMethodId: string;
  publicKeyMultibase: string;
  // Keep the raw signing key around: fromKeyPair()'s returned DID Document
  // and its keyPairs map both have private key material stripped out (a DID
  // Document must never carry private keys), so the caller must persist this
  // separately if it wants to sign anything later.
  privateKeyMultibase: string;
}

export async function generateDidKey(): Promise<GeneratedDid> {
  const verificationKeyPair = await Ed25519VerificationKey2020.generate();
  const { didDocument } = await didKeyDriver.fromKeyPair({ verificationKeyPair });

  const verificationMethodId = didDocument.assertionMethod[0] as string;
  const exported = await verificationKeyPair.export({
    publicKey: true,
    privateKey: true,
  });

  return {
    did: didDocument.id,
    verificationMethodId,
    publicKeyMultibase: exported.publicKeyMultibase as string,
    privateKeyMultibase: exported.privateKeyMultibase as string,
  };
}
