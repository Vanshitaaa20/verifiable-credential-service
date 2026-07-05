// A small repository interface in front of the StatusList table. This
// project otherwise talks to Prisma directly from service modules (see
// did/didService.ts) — the one exception is here, because status-list bit
// manipulation is the part of Phase 3 that most needs real unit tests
// (bit-level isolation between credentials, race-condition-prone index
// allocation), and there's no live Postgres in this environment to test
// against. The interface lets tests swap in an in-memory fake
// (test/helpers/inMemoryStatusListRepo.ts) while production code uses
// prismaStatusListRepo.ts — both satisfy the same contract.
export interface StatusListRecord {
  id: string;
  issuerDid: string;
  purpose: string;
  encodedList: string;
  nextIndex: number;
}

export interface StatusListRepo {
  findByIssuerAndPurpose(issuerDid: string, purpose: string): Promise<StatusListRecord | null>;
  findById(id: string): Promise<StatusListRecord | null>;
  create(data: Omit<StatusListRecord, 'id'>): Promise<StatusListRecord>;
  update(
    id: string,
    patch: Partial<Pick<StatusListRecord, 'encodedList' | 'nextIndex'>>,
  ): Promise<StatusListRecord>;
}
