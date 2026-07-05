# Verifiable Credential Issuance & Verification Service

A single, well-tested Node/TypeScript service demonstrating DID/VC/SSI
mechanics end to end: `did:key` identity, W3C Verifiable Credential issuance,
verification (schema + signature + revocation status), and StatusList2021
revocation. Built in four phases, each shippable and tested on its own.

**Status: all 4 phases complete. 18 tests passing across 4 suites.**

```
npm install
npm test          # 18 tests, no DB required
npm run demo      # narrated issue → verify → revoke → verify-again walkthrough
```

## Architecture

```
                 ┌──────────────────────────────────────────────┐
                 │                 Express app                   │
                 │            (src/server.ts + routes)           │
                 └──────────────────────────────────────────────┘
                   │              │                  │
        POST /dids │   POST /credentials   POST /credentials/verify
                   │   POST /credentials/:id/revoke   GET /status-lists/:id
                   ▼              ▼                  ▼
        ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐
        │  did/        │  │  issuer/     │  │  verifier/              │
        │  generateDid │  │  issueCredential│ verifyCredential        │
        │  resolver    │  │  (sign VC)   │  │   ├─ checkSchema        │
        │  contexts    │  │              │  │   ├─ (vc.verifyCredential)│
        │ (did:key,    │  │              │  │   └─ checkCredentialStatus│
        │  local JSON-LD│  └──────────────┘  └────────────────────────┘
        │  contexts)   │         │                    │
        └─────────────┘         │                    │
                   │             ▼                    ▼
                   │   ┌────────────────────────────────────┐
                   │   │  revocation/                        │
                   │   │  statusListService (bit-level logic)│
                   │   │  statusListRepo (interface)         │
                   │   │   ├─ prismaStatusListRepo (prod)     │
                   │   │   └─ inMemoryStatusListRepo (tests)  │
                   │   └────────────────────────────────────┘
                   │                    │
                   ▼                    ▼
        ┌──────────────────────────────────────────────┐
        │        Prisma / Postgres (or Supabase)         │
        │   DidKey · Credential · StatusList              │
        └──────────────────────────────────────────────┘
```

Every crypto/business-logic module (`did/`, `issuer/`, `verifier/`,
`revocation/statusListService.ts`) is DB-agnostic and unit-tested directly;
only the thin route/service layer touches Prisma. That split is what let
Phases 1–3 stay fully tested without ever needing a live Postgres instance
in this environment (see [Setup](#setup)).

## Design decisions (the interview talking points)

**1. `did:key` over `did:web`.** `did:key` is self-certifying — the DID is
derived directly from the public key, so there's zero resolution
infrastructure: no hosting, no DNS, no registry. The cost is that identity
and key are the same bit of data: if the key is compromised or needs
rotation, there is no rotation — you mint an entirely new DID. `did:web`
decouples identity (a domain) from key material (a hosted `did.json`),
enabling rotation, but moves the trust root to DNS + HTTPS PKI, where a
domain lapse or takeover becomes an identity takeover. This service uses
`did:key` for both issuer and holder because the goal is demonstrating VC
mechanics, not running identity infrastructure — `did:web` is the
production-realistic choice for an org that needs rotation and long-lived
public identity.

**2. Closed-world JSON-LD contexts.** Every `@context` URL a credential can
reference must already exist in a hand-curated local map
(`did/contexts.ts`) — nothing is fetched dynamically over the network. This
means verification never depends on `w3.org`/`w3id.org` staying up, and
blocks a real attack vector where a malicious context redefines a term
(e.g. `proofValue`) mid-canonicalization to smuggle a bad signature past
verification. The cost: zero extensibility without a code change — adding
any new credential type or claim vocabulary means shipping a new context
file first. That's closed-world (safety, no supply-chain-style dependency
on arbitrary remote JSON) chosen deliberately over open-world (accept any
W3C-conformant credential from anywhere).

**3. Trust = resolvability + valid signature, nothing more.** `did:key`
being self-certifying means resolving it only proves "whoever holds this
DID's private key signed this" — never "this issuer is who they claim to
be, and we trust them." There's no registry to check an issuer DID against,
so "unknown issuer" is not a distinct failure mode in this project; a real
deployment would add an explicit issuer allowlist/trust registry on top,
which is also where `did:web` (domain-bound identity) starts to matter more
than `did:key`.

**4. StatusList2021 caching/staleness is a policy gap by design, not an
oversight.** This issuer always signs the StatusList2021Credential fresh
from the current encoded bitstring on every fetch — the issuer side is
never stale. But the entire point of StatusList2021 is that the list is
"public and cacheable" so thousands of credentials' status can be checked
without a per-credential lookup — and the moment a verifier caches what it
fetched, there's a window between an actual revocation and the verifier
noticing it. The spec has no `max-age`/freshness field; it pushes the
freshness-vs-load trade-off entirely onto ordinary HTTP caching semantics
(`Cache-Control`/`ETag`), meaning every verifier integration has to decide
for itself how stale is acceptable — a payment-authorization credential
might need to check on every use, a low-stakes one might tolerate an
hour-old cached list. There is no universally correct answer, and the spec
doesn't pretend otherwise.

## What I'd do differently in production

- **Private keys are stored in plaintext in Postgres** (`DidKey.privateKeyMultibase`).
  Fine for a demo; a real issuer would use a KMS/HSM and never let the
  application process hold raw signing key material.
- **No issuer trust registry.** As above — resolvability currently *is* the
  full trust check. Production needs an explicit allowlist of trusted
  issuer DIDs (or a `did:web` migration) before "verified" should be
  read as "trustworthy."
- **StatusList index allocation is racy.** `allocateStatusListIndex` is a
  read-then-write, not atomic — concurrent issuances against the same list
  could collide. Production needs a DB-level atomic increment or row lock.
- **No list-growth strategy.** Once a StatusList fills
  (`nextIndex >= STATUS_LIST_SIZE`), issuance just throws. A real issuer
  needs to provision a new list transparently.
- **`STATUS_LIST_SIZE` is 16,384, not the spec-recommended ≥131,072** — kept
  small deliberately so tests/demos run fast, at the cost of the anonymity
  set StatusList2021 is designed to provide.
- **No verifier-side caching policy implemented** (see trade-off #4 above)
  — this service always fetches/signs fresh; a real verifier deployment
  would need to pick and implement an actual freshness policy.
- **No rate limiting, auth, or audit logging** on the HTTP API — this is a
  reference implementation of the VC mechanics, not a hardened multi-tenant
  service.

## Phase-by-phase implementation notes

### Phase 1 — `did:key` generation + VC issuance
- `did/generateDid.ts` generates an Ed25519 keypair and derives a `did:key`.
- `did/resolver.ts` + `did/contexts.ts` resolve DIDs and JSON-LD contexts
  entirely locally (no network calls).
- `issuer/issueCredential.ts` builds and signs a VC with `Ed25519Signature2020`.
- Gotchas hit: (a) `@digitalbazaar/vc`'s bundled document loader doesn't
  include every context jsonld-signatures needs (e.g. the ed25519-2020
  security context) — fixed by bundling contexts locally; (b)
  `didKeyDriver.fromKeyPair()`'s returned DID Document and `keyPairs` map
  both strip private key material by design — the original generated
  keypair is what you persist and sign with; (c) `vc.verifyCredential` runs
  JSON-LD "safe mode," so any `type`/claim not defined by a context fails
  with a terse error — Phase 1 only issues bare `VerifiableCredential`s.

### Phase 2 — Verifier service
- `verifier/checkSchema.ts`: pure structural + context-membership check,
  runs and can fail *before* any canonicalization or signature work.
- `verifier/verifyCredential.ts`: orchestrates schema → signature, returns
  `{ valid, checks, errors }` (granular, not a boolean).
- `POST /api/credentials/verify`.

### Phase 3 — StatusList2021 revocation
- Reuses `@digitalbazaar/vc-status-list` (the reference implementation) for
  bitstring encode/decode rather than hand-rolling gzip/bitstring logic.
- `revocation/statusListService.ts`: pure bit-level logic (allocate index,
  revoke, check bit, build+sign the StatusList2021Credential).
- `revocation/statusListRepo.ts`: the one repository-interface abstraction
  in this codebase (everywhere else calls Prisma directly) — specifically
  so bit-manipulation correctness (isolation between credentials, index
  allocation) can be unit tested via an in-memory fake, without a live
  Postgres in this environment.
- Gotcha: `@digitalbazaar/vc`'s `verifyCredential` refuses to verify any
  credential carrying `credentialStatus` unless given a `checkStatus`
  callback — surfaces as an inexplicable signature failure. Fixed with a
  deliberate no-op there; Phase 3's status check runs as its own step.
- Design call: missing `credentialStatus` → treated as unrevocable/always
  valid (spec-compliant optionality; Phase 1/2 both issue non-revocable
  bare credentials). A **present but malformed** `credentialStatus` (e.g.
  garbage `statusListIndex`) fails closed — a broken revocation declaration
  is either tampered with or buggy and must not be silently treated as valid.
- `POST /api/credentials/:id/revoke`, `GET /api/status-lists/:id`.

### Phase 4 — API polish + demo
- Consistent error shape across every route: `{ error, details }`, via one
  `ApiError` hierarchy (`src/errors.ts`) and a single Express error-handling
  middleware — `ValidationError` → 400 (malformed request, rejected before
  business logic), `NotFoundError` → 404, `UnprocessableError` → 422
  (well-formed request, operation can't be carried out, e.g. revoking a
  credential with no status-list entry).
- `POST /api/credentials/verify` is the one deliberate exception to
  "validate before business logic": its entire job is explaining *why* a
  credential is invalid, so a malformed body comes back as a normal 200
  with `checks.schema: false`, not a 400.
- Express 5 forwards rejected promises from async route handlers to error
  middleware natively — confirmed with a standalone smoke test before
  relying on it, so no `asyncHandler` wrapper boilerplate was needed per route.
- `scripts/demo.ts`: narrated issue → verify → revoke → verify-again
  walkthrough. Uses the in-memory status list repo (same one the test suite
  uses) instead of Postgres, so it runs with zero setup — no
  `DATABASE_URL` required. Run with `npm run demo`.

## Setup

```bash
npm install
cp .env.example .env   # fill in a real Postgres/Supabase DATABASE_URL
npm run prisma:generate
npm run prisma:migrate
npm run dev             # http://localhost:3000
npm test                # 18 tests — no DB needed, all pure/in-memory
npm run demo             # narrated lifecycle walkthrough — no DB needed
```

## API

- `POST /api/dids` — generate and persist a new `did:key` identity (used for
  both issuers and holders).
- `POST /api/credentials` — issue a signed VC from `issuerDid` to `holderDid`.
- `POST /api/credentials/verify` — verify a VC JSON body; returns
  `{ valid, checks: { schema, signature, status }, errors }`.
- `POST /api/credentials/:id/revoke` — flip the credential's status-list bit.
- `GET /api/status-lists/:id` — fetch the signed StatusList2021Credential.

All error responses share one shape: `{ error: string, details: unknown }`.

## Why `@digitalbazaar/vc` + `Ed25519Signature2020` over `did-jwt-vc`

Before committing to the JSON-LD/Linked-Data-Proofs stack, a standalone
spike validated the full issue→verify round trip end-to-end. It took three
fixes (see Phase 1 notes above) but no fundamental blockers, so the
`did-jwt-vc`/JWT-VC fallback was never needed. The JSON-LD suite is the W3C
VC Working Group's reference implementation and forces genuine engagement
with JSON-LD canonicalization — a detail worth being able to speak to
directly in a DID/VC-focused interview, and the reason it was worth the
extra setup cost over the simpler JWT-VC alternative.
