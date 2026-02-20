'use strict';

const prisma = require('../lib/prisma');

/**
 * Role-based access control middleware factory.
 * Must be used AFTER the `authenticate` middleware.
 *
 * @param {...string} roles - Allowed roles (e.g. 'ADMIN', 'AGENT')
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthenticated' });
    }
    if (!roles.includes(req.user.role)) {
      prisma.auditLog.create({
        data: {
          userId: req.user.id,
          action: 'AUTHORIZATION_FAILED',
          details: {
            reason: 'insufficient_role',
            requiredRoles: roles,
            userRole: req.user.role,
            path: req.originalUrl,
            method: req.method,
          },
          ipAddress: req.ip,
        },
      }).catch(() => {});
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

module.exports = { requireRole };
