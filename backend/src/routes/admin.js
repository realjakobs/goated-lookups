'use strict';

const crypto = require('crypto');
const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate } = require('../middleware/auth');
const { requireRole } = require('../middleware/requireRole');
const { getIo } = require('../lib/socketio');
const { encrypt, decrypt } = require('../lib/crypto');

const INVITE_EXPIRY_HOURS = 48;

const router = express.Router();
router.use(authenticate, requireRole('ADMIN'));

// POST /api/admin/invites
router.post('/invites', async (req, res, next) => {
  try {
    const { id: adminId } = req.user;
    const plainToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(plainToken).digest('hex');
    const expiresAt = new Date(Date.now() + INVITE_EXPIRY_HOURS * 60 * 60 * 1000);

    await prisma.invite.create({
      data: { tokenHash, createdById: adminId, expiresAt },
    });

    await prisma.auditLog.create({
      data: {
        userId: adminId,
        action: 'INVITE_CREATED',
        details: { expiresAt },
        ipAddress: req.ip,
      },
    });

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    res.status(201).json({ inviteUrl: `${frontendUrl}/register/${plainToken}` });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/users
router.get('/users', async (req, res, next) => {
  try {
    const users = await prisma.user.findMany({
      where: { role: 'AGENT' },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        isActive: true,
        createdAt: true,
        failedLoginAttempts: true,
        lockedUntil: true,
      },
      orderBy: { createdAt: 'desc' },
    });
    res.json(users);
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/users/:id/deactivate
router.post('/users/:id/deactivate', async (req, res, next) => {
  try {
    const { id: adminId } = req.user;
    const { id } = req.params;

    // Verify target is an AGENT — admins cannot deactivate other admins
    const target = await prisma.user.findUnique({
      where: { id },
      select: { id: true, email: true, role: true },
    });
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.role !== 'AGENT') {
      return res.status(403).json({ error: 'Only agent accounts can be deactivated through this interface.' });
    }

    const user = await prisma.user.update({
      where: { id },
      data: { isActive: false },
      select: { id: true, email: true, isActive: true },
    });

    await prisma.refreshToken.updateMany({
      where: { userId: id, revokedAt: null },
      data: { revokedAt: new Date() },
    });

    await prisma.auditLog.create({
      data: {
        userId: adminId,
        action: 'USER_DEACTIVATED',
        details: { targetUserId: id, email: user.email },
        ipAddress: req.ip,
      },
    });

    res.json(user);
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/users/:id/activate
router.post('/users/:id/activate', async (req, res, next) => {
  try {
    const { id: adminId } = req.user;
    const { id } = req.params;

    const user = await prisma.user.update({
      where: { id },
      data: { isActive: true, failedLoginAttempts: 0, lockedUntil: null },
      select: { id: true, email: true, isActive: true },
    });

    await prisma.auditLog.create({
      data: {
        userId: adminId,
        action: 'USER_ACTIVATED',
        details: { targetUserId: id, email: user.email },
        ipAddress: req.ip,
      },
    });

    res.json(user);
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/queue
router.get('/queue', async (req, res, next) => {
  try {
    const { id: adminId } = req.user;

    const requests = await prisma.mARxRequest.findMany({
      where: { status: 'PENDING' },
      include: {
        agent: { select: { id: true, email: true, firstName: true, lastName: true } },
      },
      orderBy: { createdAt: 'asc' },
    });

    await prisma.auditLog.create({
      data: {
        userId: adminId,
        action: 'ADMIN_QUEUE_VIEWED',
        details: { requestCount: requests.length },
        ipAddress: req.ip,
      },
    });

    res.json(requests.map(r => ({ ...decryptRequestFields(r), agent: r.agent })));
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/claim/:requestId
// Admin claims a pending request — joins the conversation the agent already started.
router.post('/claim/:requestId', async (req, res, next) => {
  try {
    const { id: adminId } = req.user;
    const { requestId } = req.params;

    const request = await prisma.mARxRequest.findUnique({ where: { id: requestId } });

    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.status !== 'PENDING') {
      return res.status(409).json({ error: `Request is already ${request.status}` });
    }
    if (!request.conversationId) {
      return res.status(409).json({ error: 'No conversation attached to this request' });
    }

    const updatedRequest = await prisma.$transaction(async (tx) => {
      // Add admin to the existing conversation (upsert handles duplicates)
      await tx.conversationParticipant.upsert({
        where: {
          userId_conversationId: {
            userId: adminId,
            conversationId: request.conversationId,
          },
        },
        create: { userId: adminId, conversationId: request.conversationId },
        update: {},
      });

      return tx.mARxRequest.update({
        where: { id: requestId },
        data: { status: 'CLAIMED', claimedById: adminId, claimedAt: new Date() },
      });
    });

    await prisma.auditLog.create({
      data: {
        userId: adminId,
        action: 'REQUEST_CLAIMED',
        details: { requestId, conversationId: request.conversationId, agentId: request.agentId },
        ipAddress: req.ip,
      },
    });

    const io = getIo();
    if (io) {
      io.notifyRequestClaimed(requestId, request.conversationId);
      io.notifyAgentRequestClaimed(request.agentId, request.conversationId);
    }

    const conversation = await prisma.conversation.findUnique({
      where: { id: request.conversationId },
    });

    res.json({ conversation, request: updatedRequest });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/resolve/:requestId
router.post('/resolve/:requestId', async (req, res, next) => {
  try {
    const { id: adminId } = req.user;
    const { requestId } = req.params;

    const request = await prisma.mARxRequest.findUnique({ where: { id: requestId } });

    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.status !== 'CLAIMED') {
      return res.status(409).json({ error: `Cannot resolve a request with status ${request.status}` });
    }

    const updated = await prisma.mARxRequest.update({
      where: { id: requestId },
      data: { status: 'RESOLVED', resolvedAt: new Date() },
    });

    // Remove admin from the conversation so it no longer appears in their sidebar
    if (request.conversationId) {
      await prisma.conversationParticipant.deleteMany({
        where: { userId: adminId, conversationId: request.conversationId },
      });
    }

    await prisma.auditLog.create({
      data: {
        userId: adminId,
        action: 'REQUEST_RESOLVED',
        details: { requestId, conversationId: request.conversationId },
        ipAddress: req.ip,
      },
    });

    res.json(updated);
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// Agent router — any authenticated user
// ---------------------------------------------------------------------------
const agentRouter = express.Router();
agentRouter.use(authenticate);

// POST /api/admin/request
// Creates a MARx request AND a conversation immediately so the agent can
// send information before an admin claims it.
agentRouter.post('/request', async (req, res, next) => {
  try {
    const { id: agentId } = req.user;
    const { clientIdentifierType, clientIdentifier, clientIdType, clientId } = req.body;

    // --- Validate PHI inputs ---
    if (!['NAME', 'DOB'].includes(clientIdentifierType)) {
      return res.status(400).json({ error: 'clientIdentifierType must be NAME or DOB' });
    }
    if (!clientIdentifier || typeof clientIdentifier !== 'string' || !clientIdentifier.trim()) {
      return res.status(400).json({ error: 'Client name or date of birth is required' });
    }
    if (!['SSN', 'MBI'].includes(clientIdType)) {
      return res.status(400).json({ error: 'clientIdType must be SSN or MBI' });
    }
    if (!clientId || typeof clientId !== 'string' || !clientId.trim()) {
      return res.status(400).json({ error: 'SSN or MBI is required' });
    }

    // SSN: strip non-digits and enforce exactly 9 digits
    let normalizedId = clientId.trim();
    if (clientIdType === 'SSN') {
      normalizedId = normalizedId.replace(/\D/g, '');
      if (normalizedId.length !== 9) {
        return res.status(400).json({ error: 'SSN must be exactly 9 digits' });
      }
    }

    // --- Encrypt PHI ---
    const encIdentifier = encrypt(clientIdentifier.trim());
    const encId = encrypt(normalizedId);

    const [marxRequest, conversation] = await prisma.$transaction(async (tx) => {
      const conv = await tx.conversation.create({ data: {} });

      await tx.conversationParticipant.create({
        data: { userId: agentId, conversationId: conv.id },
      });

      const mReq = await tx.mARxRequest.create({
        data: {
          agentId,
          conversationId: conv.id,
          clientIdentifierType,
          clientIdentifier:        encIdentifier.encryptedContent,
          clientIdentifierIv:      encIdentifier.iv,
          clientIdentifierAuthTag: encIdentifier.authTag,
          clientIdType,
          clientId:        encId.encryptedContent,
          clientIdIv:      encId.iv,
          clientIdAuthTag: encId.authTag,
        },
      });

      return [mReq, conv];
    });

    await prisma.auditLog.create({
      data: {
        userId: agentId,
        action: 'MARX_REQUEST_SUBMITTED',
        details: {
          requestId: marxRequest.id,
          conversationId: conversation.id,
          clientIdType,
          clientIdentifierType,
        },
        ipAddress: req.ip,
      },
    });

    const agent = await prisma.user.findUnique({
      where: { id: agentId },
      select: { id: true, email: true, firstName: true, lastName: true },
    });

    const decryptedRequest = decryptRequestFields(marxRequest);
    getIo()?.notifyNewRequest({ ...decryptedRequest, agent });

    res.status(201).json({ ...decryptedRequest, conversation });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/my-requests
agentRouter.get('/my-requests', async (req, res, next) => {
  try {
    const { id: agentId } = req.user;

    const requests = await prisma.mARxRequest.findMany({
      where: { agentId },
      include: { conversation: { select: { id: true } } },
      orderBy: { createdAt: 'desc' },
    });

    res.json(requests.map(decryptRequestFields));
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Returns a safe object with PHI decrypted and raw encrypted fields stripped. */
function decryptRequestFields(req) {
  return {
    id: req.id,
    agentId: req.agentId,
    conversationId: req.conversationId,
    status: req.status,
    claimedById: req.claimedById,
    claimedAt: req.claimedAt,
    resolvedAt: req.resolvedAt,
    createdAt: req.createdAt,
    updatedAt: req.updatedAt,
    clientIdentifierType: req.clientIdentifierType,
    clientIdentifier: req.clientIdentifier
      ? decrypt({ encryptedContent: req.clientIdentifier, iv: req.clientIdentifierIv, authTag: req.clientIdentifierAuthTag })
      : null,
    clientIdType: req.clientIdType,
    clientId: req.clientId
      ? decrypt({ encryptedContent: req.clientId, iv: req.clientIdIv, authTag: req.clientIdAuthTag })
      : null,
  };
}

module.exports = { adminRouter: router, agentRouter };
