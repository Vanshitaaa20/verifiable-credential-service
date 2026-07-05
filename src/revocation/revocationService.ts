import { prisma } from '../db/prisma.js';
import { prismaStatusListRepo } from './prismaStatusListRepo.js';
import { revokeByStatusListIndex } from './statusListService.js';
import { NotFoundError, UnprocessableError } from '../errors.js';

export async function revokeCredential(credentialId: string): Promise<void> {
  const credential = await prisma.credential.findUnique({ where: { id: credentialId } });
  if (!credential) {
    throw new NotFoundError(`Credential "${credentialId}" not found`, { credentialId });
  }

  if (credential.statusListId == null || credential.statusListIndex == null) {
    throw new UnprocessableError(
      `Credential "${credentialId}" has no status list entry and cannot be revoked`,
      { credentialId },
    );
  }

  await revokeByStatusListIndex(prismaStatusListRepo, credential.statusListId, credential.statusListIndex);
  await prisma.credential.update({ where: { id: credentialId }, data: { status: 'revoked' } });
}
