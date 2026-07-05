import { contexts as credentialsContexts } from '@digitalbazaar/credentials-context';
import ed25519Ctx from 'ed25519-signature-2020-context';
import { contexts as statusListContexts } from '@digitalbazaar/vc-status-list-context';

// jsonld-signatures needs to fetch several JSON-LD contexts (the base VC
// context, the ed25519-2020 security suite context, the StatusList2021
// context used by credentialStatus/StatusList2021Credential) during
// canonicalization. The digitalbazaar packages ship these locally instead of
// resolving them over the network at w3.org/w3id.org, which would make
// issuance/verification depend on those hosts staying up. We build one
// static map and serve every context from it via a custom documentLoader —
// any @context URL not in this map is rejected, not fetched (see Phase 2's
// checkSchema.ts).
const STATIC_CONTEXTS = new Map<string, unknown>();
for (const [url, doc] of credentialsContexts as Map<string, unknown>) {
  STATIC_CONTEXTS.set(url, doc);
}
STATIC_CONTEXTS.set(ed25519Ctx.CONTEXT_URL, ed25519Ctx.CONTEXT);
for (const [url, doc] of statusListContexts as Map<string, unknown>) {
  STATIC_CONTEXTS.set(url, doc);
}

export function getStaticContext(url: string): unknown | undefined {
  return STATIC_CONTEXTS.get(url);
}
