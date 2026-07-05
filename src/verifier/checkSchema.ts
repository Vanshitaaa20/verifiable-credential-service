import { getStaticContext } from '../did/contexts.js';

const BASE_VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1';

export interface SchemaCheckResult {
  valid: boolean;
  errors: string[];
}

// Deliberately does NOT call into jsonld/jsonld-signatures: this is a plain
// structural + context-membership check, so a bad @context is rejected
// before any canonicalization or signature work runs. It also never
// resolves a context over the network — every context URL must already be
// in our local static map (see did/contexts.ts) or the credential is
// rejected outright. This mirrors Phase 1's stance that context resolution
// should never depend on w3.org/w3id.org staying up.
export function checkCredentialSchema(credential: unknown): SchemaCheckResult {
  const errors: string[] = [];

  if (typeof credential !== 'object' || credential === null) {
    return { valid: false, errors: ['credential must be a JSON object'] };
  }
  const cred = credential as Record<string, unknown>;

  const context = cred['@context'];
  const contexts = Array.isArray(context) ? context : typeof context === 'string' ? [context] : null;

  if (!contexts) {
    errors.push('@context must be a string or array of strings');
  } else {
    if (contexts[0] !== BASE_VC_CONTEXT) {
      errors.push(`first @context entry must be "${BASE_VC_CONTEXT}"`);
    }
    for (const ctx of contexts) {
      if (typeof ctx !== 'string') {
        errors.push('inline @context objects are not supported — only known context URLs');
        continue;
      }
      if (!getStaticContext(ctx)) {
        errors.push(`unknown or unsupported @context URL: "${ctx}"`);
      }
    }
  }

  const type = cred.type;
  if (!Array.isArray(type) || !type.includes('VerifiableCredential')) {
    errors.push('type must be an array including "VerifiableCredential"');
  }

  if (typeof cred.issuer !== 'string' || !cred.issuer.startsWith('did:key:')) {
    errors.push('issuer must be a did:key DID string');
  }

  if (typeof cred.proof !== 'object' || cred.proof === null) {
    errors.push('missing proof');
  }

  return { valid: errors.length === 0, errors };
}
