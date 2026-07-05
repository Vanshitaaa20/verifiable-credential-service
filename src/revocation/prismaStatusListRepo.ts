import { prisma } from '../db/prisma.js';
import type { StatusListRepo } from './statusListRepo.js';

export const prismaStatusListRepo: StatusListRepo = {
  async findByIssuerAndPurpose(issuerDid, purpose) {
    return prisma.statusList.findUnique({
      where: { issuerDid_purpose: { issuerDid, purpose } },
    });
  },

  async findById(id) {
    return prisma.statusList.findUnique({ where: { id } });
  },

  async create(data) {
    return prisma.statusList.create({ data });
  },

  async update(id, patch) {
    return prisma.statusList.update({ where: { id }, data: patch });
  },
};
