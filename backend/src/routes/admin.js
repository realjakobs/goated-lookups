'use strict';

const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate } = require('../middleware/auth');
const { requireRole } = require('../middleware/requireRole');

const router = express.Router();

// All admin routes require authentication + ADMIN role
router.use(authenticate, requireRole('ADMIN'));

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
