import * as vc from '@digitalbazaar/vc';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { createDocumentLoader } from '../did/resolver.js';
import { checkCredentialSchema } from './checkSchema.js';
import { checkCredentialStatus, type StatusListResolver } from './checkCredentialStatus.js';

export interface VerifyResult {
  valid: boolean;
  checks: {
    schema: boolean;
    signature: boolean;
    status: boolean;
  };
  errors: string[];
}

// verifyCredential itself stays DB-agnostic, same as Phase 1/2 — it takes a
// resolver function rather than reaching into Prisma directly. The HTTP
// route wires up the real (Prisma-backed) resolver; tests wire up one
// backed by an in-memory status list. If no resolver is supplied, every
// status check fails closed (see checkCredentialStatus.ts).
const alwaysUnresolvable: StatusListResolver = async () => null;

// Trust model note: did:key is self-certifying — resolving it only proves
// "whoever holds this DID's private key signed this," not "this issuer is
// who/what they claim to be." There is no registry to check the DID against.
// For this project's scope (demonstrating VC mechanics, not building an
// issuer-trust framework) resolvability + valid signature IS the full trust
// check — an "unknown issuer" is not a distinct failure mode here. A real
// deployment would add an explicit issuer allowlist/trust registry on top of
// this, most likely keyed by did:web domains rather than did:key.
export async function verifyCredential(
  credential: unknown,
  resolveStatusListCredential: StatusListResolver = alwaysUnresolvable,
): Promise<VerifyResult> {
  const schemaResult = checkCredentialSchema(credential);

  // Schema/context problems are rejected before any signature work — an
  // unknown or malformed @context means we can't safely canonicalize the
  // document at all, so there's nothing meaningful to check a signature
  // against yet.
  if (!schemaResult.valid) {
    return {
      valid: false,
      checks: { schema: false, signature: false, status: false },
      errors: schemaResult.errors,
    };
  }

  const cred = credential as Record<string, unknown>;
  const issuerDid = cred.issuer as string;
  const documentLoader = createDocumentLoader(issuerDid);

  const errors: string[] = [];
  let signatureValid = false;

  try {
    const result = await vc.verifyCredential({
      credential: cred,
      suite: new Ed25519Signature2020(),
      documentLoader,
      // Gotcha: @digitalbazaar/vc's verifyCredential refuses to verify any
      // credential carrying a `credentialStatus` unless it's given a
      // checkStatus callback — otherwise it throws "A checkStatus function
      // must be given to verify credentials with credentialStatus," which
      // surfaces here as an unexplained signature failure. We no-op it
      // deliberately: this step verifies ONLY the signature, and Phase 3's
      // checkCredentialStatus() runs as its own explicit step afterward —
      // conflating the two would make the granular checks.signature /
      // checks.status split meaningless.
      checkStatus: async () => ({ verified: true }),
    });
    signatureValid = result.verified === true;
    if (!signatureValid) {
      errors.push(...extractErrorMessages(result.error));
    }
  } catch (err) {
    errors.push(err instanceof Error ? err.message : String(err));
  }

  // Status is checked only once schema + signature both pass — no point
  // asking "has this been revoked" about a credential whose signature we
  // can't even trust yet.
  if (!signatureValid) {
    return {
      valid: false,
      checks: { schema: true, signature: false, status: false },
      errors,
    };
  }

  const statusResult = await checkCredentialStatus(cred, resolveStatusListCredential);
  errors.push(...statusResult.errors);

  return {
    valid: statusResult.valid,
    checks: { schema: true, signature: true, status: statusResult.valid },
    errors,
  };
}

function extractErrorMessages(error: unknown): string[] {
  if (!error) return ['signature verification failed'];
  const err = error as { message?: string; errors?: Array<{ message?: string }> };
  if (Array.isArray(err.errors) && err.errors.length > 0) {
    return err.errors.map((e) => e.message ?? 'unknown verification error');
  }
  return [err.message ?? 'unknown verification error'];
}
