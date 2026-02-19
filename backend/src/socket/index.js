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
 *   - 'conversation:<id>'   — participants of a given conversation
 */
function initSocket(io) {
  // Middleware: authenticate every socket connection
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) {
      return next(new Error('Authentication token required'));
    }
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      socket.user = payload;
      next();
    } catch {
      next(new Error('Invalid or expired token'));
    }
  });

  io.on('connection', (socket) => {
    const { id: userId, role } = socket.user;
    console.log(`[socket] connected user=${userId} role=${role}`);

    // Admins auto-join the shared queue room
    if (role === 'ADMIN') {
      socket.join('admin-queue');
    }

    // Client asks to join a specific conversation room
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

  // Expose helpers so routes can emit events
  io.notifyNewMessage = (conversationId, message) => {
    io.to(`conversation:${conversationId}`).emit('new-message', message);
  };

  io.notifyNewRequest = (marxRequest) => {
    io.to('admin-queue').emit('new-marx-request', marxRequest);
  };

  io.notifyRequestClaimed = (requestId, conversationId) => {
    io.to('admin-queue').emit('request-claimed', { requestId, conversationId });
  };

  io.notifyMessagesExpired = (conversationId, messageIds) => {
    io.to(`conversation:${conversationId}`).emit('messages-expired', { conversationId, messageIds });
  };
}

module.exports = initSocket;
