'use strict';

const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const prisma = require('../lib/prisma');

const router = express.Router();
const BCRYPT_ROUNDS = 12;
const REFRESH_TOKEN_EXPIRY_DAYS = 7;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 30;

const SECURITY_QUESTIONS = [
  'What was the name of your first pet?',
  'What city were you born in?',
  'What was your childhood nickname?',
  "What is your mother's maiden name?",
  'What was the name of your elementary school?',
  'What is the name of the street you grew up on?',
  'What was the make of your first car?',
];

const registerSchema = z.object({
  email: z.string().email('Invalid email address').max(254),
  password: z.string().min(8, 'Password must be at least 8 characters').max(128),
  inviteToken: z.string().min(1, 'Invite token is required'),
  securityQuestion: z.string().min(1, 'Security question is required'),
  securityAnswer: z.string().min(1, 'Security answer is required').max(200),
});

const loginSchema = z.object({
  email: z.string().email('Invalid email address').max(254),
  password: z.string().min(1).max(128),
});

// ---------------------------------------------------------------------------
// GET /api/auth/security-questions
// ---------------------------------------------------------------------------
router.get('/security-questions', (_req, res) => {
  res.json({ questions: SECURITY_QUESTIONS });
});

// ---------------------------------------------------------------------------
// GET /api/auth/invite/:token
// Validates an invite token without consuming it.
// ---------------------------------------------------------------------------
router.get('/invite/:token', async (req, res, next) => {
  try {
    const tokenHash = hashToken(req.params.token);
    const invite = await prisma.invite.findUnique({ where: { tokenHash } });

    if (!invite || invite.usedAt || invite.expiresAt < new Date()) {
      return res.status(410).json({ error: 'Invite link is invalid or has expired.' });
    }

    res.json({ valid: true });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/register
// Requires a valid invite token. Always creates an AGENT account.
// ---------------------------------------------------------------------------
router.post('/register', async (req, res, next) => {
  try {
    const result = registerSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({ error: result.error.issues[0].message });
    }
    const { email, password, inviteToken, securityQuestion, securityAnswer } = result.data;

    // Validate invite
    const tokenHash = hashToken(inviteToken);
    const invite = await prisma.invite.findUnique({ where: { tokenHash } });
    if (!invite || invite.usedAt || invite.expiresAt < new Date()) {
      return res.status(410).json({ error: 'Invite link is invalid or has expired.' });
    }

    if (!SECURITY_QUESTIONS.includes(securityQuestion)) {
      return res.status(400).json({ error: 'Invalid security question.' });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const securityAnswerHash = await bcrypt.hash(
      securityAnswer.toLowerCase().trim(),
      BCRYPT_ROUNDS,
    );

    // Create user and mark invite as used atomically
    const [user] = await prisma.$transaction([
      prisma.user.create({
        data: {
          email,
          passwordHash,
          role: 'AGENT',
          securityQuestion,
          securityAnswerHash,
        },
        select: { id: true, email: true, role: true },
      }),
      prisma.invite.update({
        where: { tokenHash },
        data: { usedAt: new Date() },
      }),
    ]);

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'USER_REGISTERED',
        details: { email: user.email, role: user.role },
      },
    });

    const { accessToken, refreshToken } = await issueTokenPair(user);
    res.status(201).json({ token: accessToken, refreshToken, user });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------------
router.post('/login', async (req, res, next) => {
  try {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({ error: result.error.issues[0].message });
    }
    const { email, password } = result.data;

    const user = await prisma.user.findUnique({ where: { email } });

    // Check lockout before verifying password
    if (user?.lockedUntil && user.lockedUntil > new Date()) {
      const minutesLeft = Math.ceil((user.lockedUntil - new Date()) / 60000);
      return res.status(423).json({
        error: `Account locked due to too many failed attempts. Try again in ${minutesLeft} minute${minutesLeft === 1 ? '' : 's'}.`,
      });
    }

    const valid = user && await bcrypt.compare(password, user.passwordHash);

    if (!valid) {
      if (user) {
        const attempts = user.failedLoginAttempts + 1;
        const shouldLock = attempts >= MAX_FAILED_ATTEMPTS;
        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: attempts,
            lockedUntil: shouldLock
              ? new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000)
              : undefined,
          },
        });
        await prisma.auditLog.create({
          data: {
            userId: user.id,
            action: 'LOGIN_FAILED',
            details: { email, attempts, locked: shouldLock },
            ipAddress: req.ip,
          },
        });
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Successful login — reset lockout counters
    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'LOGIN',
        details: { email: user.email },
        ipAddress: req.ip,
      },
    });

    const { accessToken, refreshToken } = await issueTokenPair({
      id: user.id,
      email: user.email,
      role: user.role,
    });
    res.json({
      token: accessToken,
      refreshToken,
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/refresh
// ---------------------------------------------------------------------------
router.post('/refresh', async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token provided' });
    }

    const tokenHash = hashToken(refreshToken);
    const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });

    if (!stored || stored.revokedAt || stored.expiresAt < new Date()) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    await prisma.refreshToken.update({
      where: { id: stored.id },
      data: { revokedAt: new Date() },
    });

    const user = await prisma.user.findUnique({
      where: { id: stored.userId },
      select: { id: true, email: true, role: true },
    });
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    const { accessToken, refreshToken: newRefreshToken } = await issueTokenPair(user);
    res.json({ token: accessToken, refreshToken: newRefreshToken, user });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/logout
// ---------------------------------------------------------------------------
router.post('/logout', async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      const tokenHash = hashToken(refreshToken);
      await prisma.refreshToken.updateMany({
        where: { tokenHash, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    }
    res.json({ message: 'Logged out' });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '15m' },
  );
}

function hashToken(plaintext) {
  return crypto.createHash('sha256').update(plaintext).digest('hex');
}

async function issueTokenPair(user) {
  const accessToken = signToken(user);
  const plainRefresh = crypto.randomBytes(64).toString('hex');
  const tokenHash = hashToken(plainRefresh);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000);

  await prisma.refreshToken.create({
    data: { tokenHash, userId: user.id, expiresAt },
  });

  return { accessToken, refreshToken: plainRefresh };
}

module.exports = router;
