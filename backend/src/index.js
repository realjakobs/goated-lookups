'use strict';

require('dotenv').config({ path: require('path').resolve(__dirname, '..', '.env') });
const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const authRoutes = require('./routes/auth');
const messagesRoutes = require('./routes/messages');
const conversationsRoutes = require('./routes/conversations');
const { adminRouter, agentRouter } = require('./routes/admin');
const initSocket = require('./socket');
const prisma = require('./lib/prisma');
const { setIo } = require('./lib/socketio');

const app = express();
const httpServer = http.createServer(app);

// Trust one level of proxy (Render, nginx, etc.) so req.ip resolves to the
// real client IP from X-Forwarded-For instead of the proxy's IP.
// Without this, all users share the same rate-limit bucket.
app.set('trust proxy', 1);

// ---------------------------------------------------------------------------
// Security middleware
// ---------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: ["'self'", 'https:', 'wss:'],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
    },
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));
app.use(express.json());

// General rate limit — 100 requests per minute per IP across all API routes
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' },
});

// Strict rate limit for login/register — 10 attempts per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait 15 minutes and try again.' },
});

app.use('/api', generalLimiter);
app.use('/api/auth', authLimiter);

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.use('/api/auth', authRoutes);
app.use('/api/messages', messagesRoutes);
app.use('/api/conversations', conversationsRoutes);
// Agent-accessible endpoints (submit request, view own requests)
app.use('/api/admin', agentRouter);
// Admin-only endpoints (queue, claim, resolve)
app.use('/api/admin', adminRouter);

// Health check (unauthenticated — for load balancer probes)
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ---------------------------------------------------------------------------
// Central error handler
// ---------------------------------------------------------------------------
app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  if (status >= 500) {
    // Log full details server-side but never expose internals to client
    console.error('[error]', err);
    return res.status(status).json({ error: 'Internal server error' });
  }
  // 4xx errors are safe to relay (validation messages, not-found, etc.)
  res.status(status).json({ error: err.message || 'Bad request' });
});

// ---------------------------------------------------------------------------
// Socket.io
// ---------------------------------------------------------------------------
const io = new Server(httpServer, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
  },
});
initSocket(io);
setIo(io); // make io accessible to route handlers

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 4000;
httpServer.listen(PORT, () => {
  console.log(`[server] listening on port ${PORT}`);
});

// ---------------------------------------------------------------------------
// Message expiry — delete messages older than 30 minutes every 60 seconds
// ---------------------------------------------------------------------------
const MESSAGE_TTL_MS = 30 * 60 * 1000;

async function expireMessages() {
  try {
    const cutoff = new Date(Date.now() - MESSAGE_TTL_MS);
    const expired = await prisma.message.findMany({
      where: { createdAt: { lt: cutoff } },
      select: { id: true, conversationId: true },
    });

    if (expired.length === 0) return;

    const byConversation = {};
    for (const msg of expired) {
      if (!byConversation[msg.conversationId]) byConversation[msg.conversationId] = [];
      byConversation[msg.conversationId].push(msg.id);
    }

    await prisma.message.deleteMany({ where: { createdAt: { lt: cutoff } } });
    console.log(`[expiry] deleted ${expired.length} message(s)`);

    for (const [conversationId, messageIds] of Object.entries(byConversation)) {
      io.notifyMessagesExpired(conversationId, messageIds);
    }
  } catch (err) {
    console.error('[expiry] error:', err);
  }
}

setInterval(expireMessages, 60 * 1000);

// ---------------------------------------------------------------------------
// Ticket expiry — delete full conversation tree 30 minutes after resolution,
// or 30 minutes after last status update for PENDING/CLAIMED tickets.
// ---------------------------------------------------------------------------
const TICKET_TTL_MS = 30 * 60 * 1000;

async function expireTickets() {
  try {
    const cutoff = new Date(Date.now() - TICKET_TTL_MS);

    const expired = await prisma.mARxRequest.findMany({
      where: {
        OR: [
          { status: 'RESOLVED', resolvedAt: { lt: cutoff } },
          { status: { in: ['PENDING', 'CLAIMED'] }, updatedAt: { lt: cutoff } },
        ],
      },
      select: { id: true, conversationId: true, status: true, agentId: true, claimedById: true },
    });

    if (expired.length === 0) return;

    for (const req of expired) {
      const convId = req.conversationId;
      try {
        await prisma.$transaction(async (tx) => {
          if (convId) {
            await tx.message.deleteMany({ where: { conversationId: convId } });
            await tx.conversationParticipant.deleteMany({ where: { conversationId: convId } });
          }
          await tx.mARxRequest.delete({ where: { id: req.id } });
          if (convId) {
            await tx.conversation.delete({ where: { id: convId } });
          }
        });

        console.log(`[expiry] deleted ticket ${req.id} (status=${req.status})`);

        // Notify anyone in the conversation room
        if (convId) {
          io.to(`conversation:${convId}`).emit('conversation-expired', { conversationId: convId });
        }
        // Notify agent directly in case they aren't viewing this conversation
        if (req.agentId && convId) {
          io.to(`user:${req.agentId}`).emit('conversation-expired', { conversationId: convId });
        }
        // Notify the claiming admin directly for CLAIMED tickets
        if (req.claimedById && convId) {
          io.to(`user:${req.claimedById}`).emit('conversation-expired', { conversationId: convId });
        }
        // Remove PENDING items from the admin queue display
        if (req.status === 'PENDING') {
          io.to('admin-queue').emit('queue-item-expired', { requestId: req.id });
        }
      } catch (err) {
        console.error(`[expiry] failed to delete ticket ${req.id}:`, err);
      }
    }
  } catch (err) {
    console.error('[expiry] ticket expiry error:', err);
  }
}

setInterval(expireTickets, 60 * 1000);
