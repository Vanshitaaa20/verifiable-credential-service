import { didKeyDriver } from './keyDriver.js';
import { getStaticContext } from './contexts.js';

export interface DocumentLoaderResult {
  document: unknown;
  documentUrl: string;
}

// jsonld-signatures calls this for every URL it needs to dereference during
// signing/verification: the issuer's DID (to find the public key) and any
// JSON-LD @context URLs used by the credential and proof.
export function createDocumentLoader(rootDid: string) {
  return async function documentLoader(url: string): Promise<DocumentLoaderResult> {
    if (url === rootDid || url.startsWith(`${rootDid}#`)) {
      const document = await didKeyDriver.get({ url });
      return { document, documentUrl: url };
    }

    const staticContext = getStaticContext(url);
    if (staticContext) {
      return { document: staticContext, documentUrl: url };
    }

    throw new Error(`Document loader unable to load URL "${url}"`);
  };
}

export async function resolveDidKey(did: string) {
  return didKeyDriver.get({ did });
}
