'use strict';

const express = require('express');
const multer = require('multer');
const { z } = require('zod');
const prisma = require('../lib/prisma');
const { authenticate } = require('../middleware/auth');
const { encrypt, decrypt } = require('../lib/crypto');
const { getIo } = require('../lib/socketio');

const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'image/heif'];
const MAX_FILE_SIZE = 4 * 1024 * 1024; // 4 MB

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (_req, file, cb) => {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  },
});

const contentSchema = z.object({
  content: z.string().max(10000, 'Message too long').optional().default(''),
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
      include: { sender: { select: { id: true, email: true, role: true, firstName: true, lastName: true } } },
    });

    const decrypted = messages.map(m => {
      const out = {
        id: m.id,
        conversationId: m.conversationId,
        sender: m.sender,
        content: decrypt({ encryptedContent: m.encryptedContent, iv: m.iv, authTag: m.authTag }),
        createdAt: m.createdAt,
      };
      if (m.imageData && m.imageIv && m.imageAuthTag && m.imageMimeType) {
        const rawBase64 = decrypt({ encryptedContent: m.imageData, iv: m.imageIv, authTag: m.imageAuthTag });
        out.imageDataUrl = `data:${m.imageMimeType};base64,${rawBase64}`;
      }
      return out;
    });

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
// Sends an encrypted message (text and/or image).
router.post('/:conversationId', upload.single('image'), async (req, res, next) => {
  try {
    const { id: userId, role } = req.user;
    const { conversationId } = req.params;

    const result = contentSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({ error: result.error.issues[0].message });
    }
    const { content } = result.data;
    const trimmedContent = content.trim();

    if (!trimmedContent && !req.file) {
      return res.status(400).json({ error: 'Message must have text or an image' });
    }

    await assertParticipant(userId, role, conversationId, res);
    if (res.headersSent) return;

    const { encryptedContent, iv, authTag } = encrypt(trimmedContent);

    const messageData = {
      conversationId,
      senderId: userId,
      encryptedContent,
      iv,
      authTag,
    };

    let imageDataUrl = null;
    if (req.file) {
      const rawBase64 = req.file.buffer.toString('base64');
      const enc = encrypt(rawBase64);
      messageData.imageData = enc.encryptedContent;
      messageData.imageIv = enc.iv;
      messageData.imageAuthTag = enc.authTag;
      messageData.imageMimeType = req.file.mimetype;
      imageDataUrl = `data:${req.file.mimetype};base64,${rawBase64}`;
    }

    const message = await prisma.message.create({
      data: messageData,
      include: { sender: { select: { id: true, email: true, role: true, firstName: true, lastName: true } } },
    });

    await prisma.auditLog.create({
      data: {
        userId,
        action: 'MESSAGE_SENT',
        details: { conversationId, messageId: message.id, hasImage: !!req.file },
        ipAddress: req.ip,
      },
    });

    await prisma.conversation.update({
      where: { id: conversationId },
      data: { updatedAt: new Date() },
    });

    const outgoing = {
      id: message.id,
      conversationId: message.conversationId,
      sender: message.sender,
      content: trimmedContent,
      imageDataUrl,
      createdAt: message.createdAt,
    };

    // Notify everyone else in the conversation room
    getIo()?.notifyNewMessage(conversationId, outgoing);

    res.status(201).json(outgoing);
  } catch (err) {
    // multer file size / type errors
    if (err.message === 'Only image files are allowed') {
      return res.status(400).json({ error: 'Only image files are allowed' });
    }
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'Image must be under 4 MB' });
    }
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
