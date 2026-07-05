import { Router } from 'express';
import { prisma } from '../db/prisma.js';
import { getVerificationRequestCount } from '../metrics.js';

export const statsRouter = Router();

// Backs the dashboard on the landing page. Read-only aggregate counts —
// no auth, nothing sensitive (no key material, no credential payloads).
statsRouter.get('/stats', async (_req, res) => {
  const [didsRegistered, credentialsIssued, credentialsRevoked] = await Promise.all([
    prisma.didKey.count(),
    prisma.credential.count(),
    prisma.credential.count({ where: { status: 'revoked' } }),
  ]);

  res.json({
    didsRegistered,
    credentialsIssued,
    credentialsRevoked,
    verificationRequests: getVerificationRequestCount(),
  });
});
