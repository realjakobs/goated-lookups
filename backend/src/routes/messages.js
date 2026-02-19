'use strict';

const express = require('express');
const { z } = require('zod');
const prisma = require('../lib/prisma');
const { authenticate } = require('../middleware/auth');
const { encrypt, decrypt } = require('../lib/crypto');

const messageSchema = z.object({
  content: z.string().min(1, 'Message cannot be empty').max(10000, 'Message too long'),
});

const router = express.Router();

router.use(authenticate);

// GET /api/messages/:conversationId
// Returns decrypted messages for a conversation the user is a participant of.
router.get('/:conversationId', async (req, res, next) => {
  try {
    const { id: userId, role } = req.user;
    const { conversationId } = req.params;

    await assertParticipant(userId, role, conversationId, res);
    if (res.headersSent) return;

    const messages = await prisma.message.findMany({
      where: { conversationId },
      orderBy: { createdAt: 'asc' },
      include: { sender: { select: { id: true, email: true, role: true } } },
    });

    const decrypted = messages.map(m => ({
      id: m.id,
      conversationId: m.conversationId,
      sender: m.sender,
      content: decrypt({ encryptedContent: m.encryptedContent, iv: m.iv, authTag: m.authTag }),
      createdAt: m.createdAt,
    }));

    await prisma.auditLog.create({
      data: {
        userId,
        action: 'MESSAGES_VIEWED',
        details: { conversationId, messageCount: messages.length },
        ipAddress: req.ip,
      },
    });

    res.json(decrypted);
  } catch (err) {
    next(err);
  }
});

// POST /api/messages/:conversationId
// Sends an encrypted message.
router.post('/:conversationId', async (req, res, next) => {
  try {
    const { id: userId, role } = req.user;
    const { conversationId } = req.params;
    const result = messageSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({ error: result.error.issues[0].message });
    }
    const { content } = result.data;

    await assertParticipant(userId, role, conversationId, res);
    if (res.headersSent) return;

    const { encryptedContent, iv, authTag } = encrypt(content.trim());

    const message = await prisma.message.create({
      data: {
        conversationId,
        senderId: userId,
        encryptedContent,
        iv,
        authTag,
      },
      include: { sender: { select: { id: true, email: true, role: true } } },
    });

    await prisma.auditLog.create({
      data: {
        userId,
        action: 'MESSAGE_SENT',
        details: { conversationId, messageId: message.id },
        ipAddress: req.ip,
      },
    });

    // Update conversation's updatedAt for sorting
    await prisma.conversation.update({
      where: { id: conversationId },
      data: { updatedAt: new Date() },
    });

    res.status(201).json({
      id: message.id,
      conversationId: message.conversationId,
      sender: message.sender,
      content: content.trim(), // return plaintext to sender
      createdAt: message.createdAt,
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function assertParticipant(userId, role, conversationId, res) {
  if (role === 'ADMIN') return; // admins bypass participant check

  const participant = await prisma.conversationParticipant.findUnique({
    where: {
      userId_conversationId: { userId, conversationId },
    },
  });

  if (!participant) {
    res.status(403).json({ error: 'Access denied' });
  }
}

module.exports = router;
