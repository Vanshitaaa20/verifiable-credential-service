import { randomUUID } from 'node:crypto';
import type { StatusListRepo, StatusListRecord } from '../../src/revocation/statusListRepo.js';

// Test-only stand-in for prismaStatusListRepo — see the comment on
// StatusListRepo for why this interface exists at all (no live Postgres in
// this environment to test the bit-manipulation logic against).
export function createInMemoryStatusListRepo(): StatusListRepo {
  const byId = new Map<string, StatusListRecord>();

  return {
    async findByIssuerAndPurpose(issuerDid, purpose) {
      for (const record of byId.values()) {
        if (record.issuerDid === issuerDid && record.purpose === purpose) return record;
      }
      return null;
    },
    async findById(id) {
      return byId.get(id) ?? null;
    },
    async create(data) {
      const record: StatusListRecord = { id: randomUUID(), ...data };
      byId.set(record.id, record);
      return record;
    },
    async update(id, patch) {
      const existing = byId.get(id);
      if (!existing) throw new Error(`Status list ${id} not found`);
      const updated = { ...existing, ...patch };
      byId.set(id, updated);
      return updated;
    },
  };
}
