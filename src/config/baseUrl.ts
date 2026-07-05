// Used to build the "public" statusListCredential URL embedded in
// credentialStatus entries and served by GET /api/status-lists/:id.
export const BASE_URL = process.env.BASE_URL ?? `http://localhost:${process.env.PORT ?? 3000}`;
