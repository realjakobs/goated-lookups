-- AlterTable
ALTER TABLE "MARxRequest" ADD COLUMN     "clientId" TEXT,
ADD COLUMN     "clientIdAuthTag" TEXT,
ADD COLUMN     "clientIdIv" TEXT,
ADD COLUMN     "clientIdType" TEXT,
ADD COLUMN     "clientIdentifier" TEXT,
ADD COLUMN     "clientIdentifierAuthTag" TEXT,
ADD COLUMN     "clientIdentifierIv" TEXT,
ADD COLUMN     "clientIdentifierType" TEXT;
