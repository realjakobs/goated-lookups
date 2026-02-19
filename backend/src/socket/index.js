'use strict';

const jwt = require('jsonwebtoken');

/**
 * Socket.io event handler setup.
 *
 * Authentication: clients must pass { auth: { token: '<jwt>' } } when
 * connecting. The token is verified before the socket joins any room.
 *
 * Room conventions:
 *   - 'admin-queue'          — all connected admins
 *   - 'user:<userId>'        — personal room per user (targeted notifications)
 *   - 'conversation:<id>'   — participants of a given conversation
 */
function initSocket(io) {
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Authentication token required'));
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      if (payload.pending2FA) return next(new Error('Two-factor verification required'));
      socket.user = payload;
      next();
    } catch {
      next(new Error('Invalid or expired token'));
    }
  });

  io.on('connection', (socket) => {
    const { id: userId, role } = socket.user;
    console.log(`[socket] connected user=${userId} role=${role}`);

    // Each user joins their own personal room for targeted notifications
    socket.join(`user:${userId}`);

    if (role === 'ADMIN') {
      socket.join('admin-queue');
    }

    socket.on('join-conversation', (conversationId) => {
      if (typeof conversationId !== 'string') return;
      socket.join(`conversation:${conversationId}`);
    });

    socket.on('leave-conversation', (conversationId) => {
      if (typeof conversationId !== 'string') return;
      socket.leave(`conversation:${conversationId}`);
    });

    socket.on('disconnect', () => {
      console.log(`[socket] disconnected user=${userId}`);
    });
  });

  io.notifyNewMessage = (conversationId, message) => {
    io.to(`conversation:${conversationId}`).emit('new-message', message);
  };

  io.notifyNewRequest = (marxRequest) => {
    io.to('admin-queue').emit('new-marx-request', marxRequest);
  };

  io.notifyRequestClaimed = (requestId, conversationId) => {
    io.to('admin-queue').emit('request-claimed', { requestId, conversationId });
  };

  // Notify the specific agent that an admin joined their conversation
  io.notifyAgentRequestClaimed = (agentId, conversationId) => {
    io.to(`user:${agentId}`).emit('request-claimed-by-admin', { conversationId });
  };

  io.notifyMessagesExpired = (conversationId, messageIds) => {
    io.to(`conversation:${conversationId}`).emit('messages-expired', { conversationId, messageIds });
  };
}

module.exports = initSocket;
