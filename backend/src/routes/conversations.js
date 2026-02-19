'use strict';

const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

// All conversation routes require authentication
router.use(authenticate);

// GET /api/conversations
// Returns conversations the current user participates in.
// Agents only see their own; admins see all.
router.get('/', async (req, res, next) => {
  try {
    const { id: userId, role } = req.user;

    const where = role === 'ADMIN'
      ? {}
      : {
          participants: {
            some: { userId },
          },
        };

    const conversations = await prisma.conversation.findMany({
      where,
      include: {
        participants: { include: { user: { select: { id: true, email: true, role: true, firstName: true, lastName: true } } } },
        marxRequest: { select: { id: true, status: true } },
        messages: {
          orderBy: { createdAt: 'desc' },
          take: 1,
          select: { id: true, createdAt: true, senderId: true },
        },
      },
      orderBy: { updatedAt: 'desc' },
    });

    res.json(conversations);
  } catch (err) {
    next(err);
  }
});

// GET /api/conversations/:id
router.get('/:id', async (req, res, next) => {
  try {
    const { id: userId, role } = req.user;
    const { id } = req.params;

    const conversation = await prisma.conversation.findUnique({
      where: { id },
      include: {
        participants: { include: { user: { select: { id: true, email: true, role: true, firstName: true, lastName: true } } } },
        marxRequest: true,
      },
    });

    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found' });
    }

    // Agents must be a participant
    const isMember = conversation.participants.some(p => p.userId === userId);
    if (role !== 'ADMIN' && !isMember) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(conversation);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
