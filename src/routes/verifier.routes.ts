import { Router } from 'express';
import { verifyCredential } from '../verifier/verifyCredential.js';
import type { StatusListResolver } from '../verifier/checkCredentialStatus.js';
import { prismaStatusListRepo } from '../revocation/prismaStatusListRepo.js';
import { buildSignedStatusListCredential } from '../revocation/statusListService.js';
import { getDidKeyByDid } from '../did/didService.js';
import { BASE_URL } from '../config/baseUrl.js';

export const verifierRouter = Router();

// In-process shortcut: given the statusListCredential URL embedded in a
// credentialStatus entry, resolve it directly against Prisma instead of
// making an HTTP round trip to our own GET /api/status-lists/:id. An
// external verifier without DB access would genuinely fetch that URL.
const resolveStatusListCredential: StatusListResolver = async (url) => {
  const prefix = `${BASE_URL}/api/status-lists/`;
  if (!url.startsWith(prefix)) return null;
  const id = url.slice(prefix.length);

  const record = await prismaStatusListRepo.findById(id);
  if (!record) return null;

  const issuer = await getDidKeyByDid(record.issuerDid);
  return buildSignedStatusListCredential(record, issuer, BASE_URL);
};

// Deliberately does NOT validate req.body before calling verifyCredential:
// unlike every other route, this endpoint's entire job is to explain *why*
// a credential is invalid, not to reject malformed input up front. A
// missing/garbled body is just another way to fail the schema check, and
// comes back as a normal 200 with `checks.schema: false` and a message —
// not a 400. checkCredentialSchema (called internally) already handles
// non-object/garbage input safely.
verifierRouter.post('/credentials/verify', async (req, res) => {
  const result = await verifyCredential(req.body, resolveStatusListCredential);
  res.status(200).json(result);
});
