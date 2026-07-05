import { Router } from 'express';
import { revokeCredential } from '../revocation/revocationService.js';
import { prismaStatusListRepo } from '../revocation/prismaStatusListRepo.js';
import { buildSignedStatusListCredential } from '../revocation/statusListService.js';
import { getDidKeyByDid } from '../did/didService.js';
import { BASE_URL } from '../config/baseUrl.js';
import { requireUuidParam } from '../validation.js';
import { NotFoundError } from '../errors.js';

export const revocationRouter = Router();

revocationRouter.post('/credentials/:id/revoke', async (req, res) => {
  const id = requireUuidParam(req.params, 'id');
  await revokeCredential(id);
  res.json({ revoked: true });
});

// The "public, cacheable" half of StatusList2021: any verifier — ours or an
// external one — can GET this and get back a freshly-signed
// StatusList2021Credential built from the current encodedList. Nothing here
// is served from a cache; see README for what that means for a real deployment.
revocationRouter.get('/status-lists/:id', async (req, res) => {
  const id = requireUuidParam(req.params, 'id');
  const record = await prismaStatusListRepo.findById(id);
  if (!record) {
    throw new NotFoundError(`Status list "${id}" not found`, { id });
  }
  const issuer = await getDidKeyByDid(record.issuerDid);
  const credential = await buildSignedStatusListCredential(record, issuer, BASE_URL);
  res.json(credential);
});
