-- AlterTable
ALTER TABLE "User" ADD COLUMN     "force2FA" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "lastLoginAt" TIMESTAMP(3);
