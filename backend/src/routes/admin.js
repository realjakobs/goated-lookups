'use strict';

const crypto = require('crypto');
const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate } = require('../middleware/auth');
const { requireRole } = require('../middleware/requireRole');

const INVITE_EXPIRY_HOURS = 48;

const router = express.Router();

// All admin routes require authentication + ADMIN role
router.use(authenticate, requireRole('ADMIN'));

// POST /api/admin/invites
// Admin generates a single-use invite link for a new agent.
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
// Returns all agent accounts with status info.
router.get('/users', async (req, res, next) => {
  try {
    const users = await prisma.user.findMany({
      where: { role: 'AGENT' },
      select: {
        id: true,
        email: true,
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

    const user = await prisma.user.update({
      where: { id },
      data: { isActive: false },
      select: { id: true, email: true, isActive: true },
    });

    // Revoke all active refresh tokens so they're kicked out immediately
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
// Returns all PENDING MARx requests.
router.get('/queue', async (req, res, next) => {
  try {
    const requests = await prisma.mARxRequest.findMany({
      where: { status: 'PENDING' },
      include: {
        agent: { select: { id: true, email: true } },
      },
      orderBy: { createdAt: 'asc' },
    });
    res.json(requests);
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/queue/submit
// Agent submits a new MARx lookup request.
// (Re-exported here for clarity; agents can also hit this directly.)
// Accessible by any authenticated user (not just admins) — so we remove
// the ADMIN middleware for this specific route by splitting it out.
// See note below — this route is handled in a separate router below.

// POST /api/admin/claim/:requestId
// Admin claims a pending request and creates a Conversation.
router.post('/claim/:requestId', async (req, res, next) => {
  try {
    const { id: adminId } = req.user;
    const { requestId } = req.params;

    const request = await prisma.mARxRequest.findUnique({
      where: { id: requestId },
    });

    if (!request) {
      return res.status(404).json({ error: 'Request not found' });
    }
    if (request.status !== 'PENDING') {
      return res.status(409).json({ error: `Request is already ${request.status}` });
    }

    // Create conversation and claim atomically
    const [conversation, updatedRequest] = await prisma.$transaction(async (tx) => {
      const conv = await tx.conversation.create({ data: {} });

      // Add agent and admin as participants
      await tx.conversationParticipant.createMany({
        data: [
          { userId: request.agentId, conversationId: conv.id },
          { userId: adminId, conversationId: conv.id },
        ],
      });

      const updated = await tx.mARxRequest.update({
        where: { id: requestId },
        data: {
          status: 'CLAIMED',
          claimedById: adminId,
          claimedAt: new Date(),
          conversationId: conv.id,
        },
      });

      return [conv, updated];
    });

    await prisma.auditLog.create({
      data: {
        userId: adminId,
        action: 'REQUEST_CLAIMED',
        details: { requestId, conversationId: conversation.id, agentId: request.agentId },
        ipAddress: req.ip,
      },
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

    if (!request) {
      return res.status(404).json({ error: 'Request not found' });
    }
    if (request.status !== 'CLAIMED') {
      return res.status(409).json({ error: `Cannot resolve a request with status ${request.status}` });
    }

    const updated = await prisma.mARxRequest.update({
      where: { id: requestId },
      data: { status: 'RESOLVED', resolvedAt: new Date() },
    });

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
// Agent: submit MARx request (any authenticated user)
// This is a separate router so it doesn't require the ADMIN role.
// ---------------------------------------------------------------------------
const agentRouter = express.Router();
agentRouter.use(authenticate);

// POST /api/admin/request
agentRouter.post('/request', async (req, res, next) => {
  try {
    const { id: agentId } = req.user;

    const marxRequest = await prisma.mARxRequest.create({
      data: { agentId },
    });

    await prisma.auditLog.create({
      data: {
        userId: agentId,
        action: 'MARX_REQUEST_SUBMITTED',
        details: { requestId: marxRequest.id },
        ipAddress: req.ip,
      },
    });

    res.status(201).json(marxRequest);
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/my-requests — agent views their own requests
agentRouter.get('/my-requests', async (req, res, next) => {
  try {
    const { id: agentId } = req.user;

    const requests = await prisma.mARxRequest.findMany({
      where: { agentId },
      include: { conversation: { select: { id: true } } },
      orderBy: { createdAt: 'desc' },
    });

    res.json(requests);
  } catch (err) {
    next(err);
  }
});

// Mount agent sub-router BEFORE the ADMIN-gated router so /request and
// /my-requests are reachable without the ADMIN role.
module.exports = { adminRouter: router, agentRouter };
