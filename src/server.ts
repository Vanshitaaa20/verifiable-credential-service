import path from 'node:path';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { Prisma } from '@prisma/client';
import { issuerRouter } from './routes/issuer.routes.js';
import { verifierRouter } from './routes/verifier.routes.js';
import { revocationRouter } from './routes/revocation.routes.js';
import { statsRouter } from './routes/stats.routes.js';
import { ApiError } from './errors.js';

const app = express();
app.use(express.json());

// `public/` lives at the repo root next to `dist/`, not under `src/`, so it
// isn't touched by the TS build — resolve it relative to cwd (npm start /
// the Render startCommand both run from the repo root).
app.use(express.static(path.join(process.cwd(), 'public')));

app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.use('/api', issuerRouter);
app.use('/api', verifierRouter);
app.use('/api', revocationRouter);
app.use('/api', statsRouter);

app.use((_req, res) => {
  res.status(404).json({ error: 'not found', details: null });
});

// Single place all route errors funnel through — every response uses the
// same { error, details } shape regardless of which route or layer threw.
// Express 5 forwards rejected promises from async route handlers here
// automatically; no manual try/catch or asyncHandler wrapper needed per route.
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof ApiError) {
    res.status(err.statusCode).json({ error: err.message, details: err.details });
    return;
  }
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2025') {
    res.status(404).json({ error: 'resource not found', details: null });
    return;
  }
  console.error(err);
  res.status(500).json({ error: 'internal server error', details: null });
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  console.log(`vc-service listening on :${port}`);
});
