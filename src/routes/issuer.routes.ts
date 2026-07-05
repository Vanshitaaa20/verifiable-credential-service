import { Router } from 'express';
import type { Prisma } from '@prisma/client';
import { createAndStoreDidKey, getDidKeyByDid } from '../did/didService.js';
import { issueCredential } from '../issuer/issueCredential.js';
import { prisma } from '../db/prisma.js';
import { prismaStatusListRepo } from '../revocation/prismaStatusListRepo.js';
import {
  getOrCreateStatusList,
  allocateStatusListIndex,
  buildCredentialStatusEntry,
} from '../revocation/statusListService.js';
import { BASE_URL } from '../config/baseUrl.js';
import { requireDidKey, optionalStringArray, optionalPlainObject } from '../validation.js';

export const issuerRouter = Router();

// Register a new DID (used to create either an issuer or a holder identity).
issuerRouter.post('/dids', async (_req, res) => {
  const didKey = await createAndStoreDidKey();
  res.status(201).json({
    did: didKey.did,
    verificationMethodId: didKey.verificationMethodId,
    publicKeyMultibase: didKey.publicKeyMultibase,
  });
});

issuerRouter.post('/credentials', async (req, res) => {
  const issuerDid = requireDidKey(req.body, 'issuerDid');
  const holderDid = requireDidKey(req.body, 'holderDid');
  const type = optionalStringArray(req.body, 'type');
  const claims = optionalPlainObject(req.body, 'claims');

  const issuer = await getDidKeyByDid(issuerDid);

  const statusList = await getOrCreateStatusList(prismaStatusListRepo, issuer.did);
  const statusListIndex = await allocateStatusListIndex(prismaStatusListRepo, statusList.id);
  const credentialStatus = buildCredentialStatusEntry({
    statusListId: statusList.id,
    index: statusListIndex,
    baseUrl: BASE_URL,
  });

  const { credentialId, document } = await issueCredential({
    issuerDid: issuer.did,
    issuerVerificationMethodId: issuer.verificationMethodId,
    issuerPublicKeyMultibase: issuer.publicKeyMultibase,
    issuerPrivateKeyMultibase: issuer.privateKeyMultibase,
    holderDid,
    type,
    claims,
    credentialStatus,
  });

  const holder = await prisma.didKey.findUnique({ where: { did: holderDid } });

  const stored = await prisma.credential.create({
    data: {
      credentialId,
      issuerId: issuer.id,
      holderId: holder?.id,
      type: document.type as string[],
      payload: document as unknown as Prisma.InputJsonValue,
      statusListId: statusList.id,
      statusListIndex,
    },
  });

  res.status(201).json({ id: stored.id, credential: document });
});
