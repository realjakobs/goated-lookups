'use strict';

const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const prisma = require('../lib/prisma');
const { sendUnlockEmail, sendOtpEmail, sendPasswordResetEmail } = require('../lib/email');

const router = express.Router();
const BCRYPT_ROUNDS = 12;
const REFRESH_TOKEN_EXPIRY_DAYS = 7;
const UNLOCK_TOKEN_EXPIRY_HOURS = 1;
const MAX_FAILED_ATTEMPTS = 5;
const OTP_EXPIRY_MINUTES = 5;
const OTP_MAX_ATTEMPTS = 5;
const PASSWORD_RESET_EXPIRY_HOURS = 1;
const PASSWORD_HISTORY_COUNT = 3;

/**
 * Validates password complexity.
 * Returns null if valid, or an error message string.
 */
function validatePasswordComplexity(password) {
  if (password.length < 12) return 'Password must be at least 12 characters';
  if (password.length > 128) return 'Password must be at most 128 characters';
  if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter';
  if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter';
  if (!/[0-9]/.test(password)) return 'Password must contain at least one number';
  if (!/[^A-Za-z0-9]/.test(password)) return 'Password must contain at least one special character';
  return null;
}

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
  firstName: z.string().min(1, 'First name is required').max(100),
  lastName: z.string().min(1, 'Last name is required').max(100),
  email: z.string().email('Invalid email address').max(254),
  password: z.string().min(12, 'Password must be at least 12 characters').max(128),
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
    const { firstName, lastName, email, password, inviteToken, securityQuestion, securityAnswer } = result.data;

    // Validate invite
    const tokenHash = hashToken(inviteToken);
    const invite = await prisma.invite.findUnique({ where: { tokenHash } });
    if (!invite || invite.usedAt || invite.expiresAt < new Date()) {
      return res.status(410).json({ error: 'Invite link is invalid or has expired.' });
    }

    if (!SECURITY_QUESTIONS.includes(securityQuestion)) {
      return res.status(400).json({ error: 'Invalid security question.' });
    }

    const complexityError = validatePasswordComplexity(password);
    if (complexityError) {
      return res.status(400).json({ error: complexityError });
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
          firstName: firstName.trim(),
          lastName: lastName.trim(),
          email,
          passwordHash,
          role: 'AGENT',
          securityQuestion,
          securityAnswerHash,
        },
        select: { id: true, email: true, role: true, firstName: true, lastName: true },
      }),
      prisma.invite.update({
        where: { tokenHash },
        data: { usedAt: new Date() },
      }),
    ]);

    // Save initial password to history
    await prisma.passwordHistory.create({
      data: { userId: user.id, passwordHash },
    });

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'USER_REGISTERED',
        details: { email: user.email, role: user.role },
        ipAddress: req.ip,
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

    // Check if account is deactivated by admin
    if (user && !user.isActive) {
      return res.status(403).json({ error: 'Your account has been deactivated. Contact your administrator.' });
    }

    // Check lockout
    if (user?.lockedUntil && user.lockedUntil > new Date()) {
      return res.status(423).json({
        error: 'Account locked due to too many failed login attempts. Check your email for an unlock link.',
      });
    }

    const valid = user && await bcrypt.compare(password, user.passwordHash);

    if (!valid) {
      if (user) {
        const attempts = user.failedLoginAttempts + 1;
        const shouldLock = attempts >= MAX_FAILED_ATTEMPTS;

        // Lock for 30 days — only unlockable via the email link
        const lockedUntil = shouldLock
          ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          : undefined;

        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: attempts,
            lockedUntil,
            ...(shouldLock && { force2FA: true }),
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

        if (shouldLock && user.securityQuestion) {
          // Generate unlock token and email it
          const plainToken = crypto.randomBytes(32).toString('hex');
          const tokenHash = hashToken(plainToken);
          const expiresAt = new Date(Date.now() + UNLOCK_TOKEN_EXPIRY_HOURS * 60 * 60 * 1000);

          await prisma.unlockToken.create({
            data: { tokenHash, userId: user.id, expiresAt },
          });

          // Fire-and-forget — don't let email failure block the response
          sendUnlockEmail(user.email, plainToken).catch(err =>
            console.error('[email] Failed to send unlock email:', err),
          );
        }
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Successful password — reset lockout counters
    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });

    // Determine if 2FA is required
    const SKIP_2FA_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
    const recentLogin = user.lastLoginAt &&
      (Date.now() - user.lastLoginAt.getTime()) < SKIP_2FA_WINDOW_MS;
    const skip2FA = recentLogin && !user.force2FA;

    if (skip2FA) {
      // Recent login and no forced 2FA — issue tokens directly
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      });

      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'LOGIN',
          details: { email: user.email, skipped2FA: true },
          ipAddress: req.ip,
        },
      });

      const { accessToken, refreshToken } = await issueTokenPair({
        id: user.id,
        email: user.email,
        role: user.role,
      });
      return res.json({
        token: accessToken,
        refreshToken,
        user: { id: user.id, email: user.email, role: user.role, firstName: user.firstName, lastName: user.lastName },
      });
    }

    // 2FA required — generate and send OTP
    // Invalidate any prior unused OTPs for this user
    await prisma.otpCode.updateMany({
      where: { userId: user.id, usedAt: null },
      data: { usedAt: new Date() },
    });

    // Generate and store OTP
    const plainOtp = generateOtp();
    const codeHash = hashToken(plainOtp);
    const otpExpiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    await prisma.otpCode.create({
      data: { codeHash, userId: user.id, expiresAt: otpExpiresAt },
    });

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'OTP_SENT',
        details: { email: user.email },
        ipAddress: req.ip,
      },
    });

    // Fire-and-forget email
    sendOtpEmail(user.email, plainOtp).catch(err =>
      console.error('[email] Failed to send OTP email:', err),
    );

    const pending2faToken = signPending2faToken(user);
    res.json({ requires2FA: true, tempToken: pending2faToken });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/verify-otp
// Verifies the 6-digit OTP and issues the real token pair.
// ---------------------------------------------------------------------------
const verifyOtpSchema = z.object({
  otp: z.string().length(6, 'OTP must be 6 digits').regex(/^\d{6}$/, 'OTP must be numeric'),
});

router.post('/verify-otp', async (req, res, next) => {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing authorization header' });
    }

    let payload;
    try {
      payload = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    } catch {
      return res.status(401).json({ error: 'Invalid or expired verification session. Please log in again.' });
    }

    if (!payload.pending2FA) {
      return res.status(400).json({ error: 'Invalid token type' });
    }

    const result = verifyOtpSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({ error: result.error.issues[0].message });
    }
    const { otp } = result.data;

    // Find the most recent unused, non-expired OTP for this user
    const otpRecord = await prisma.otpCode.findFirst({
      where: {
        userId: payload.id,
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!otpRecord) {
      await prisma.auditLog.create({
        data: {
          userId: payload.id,
          action: 'OTP_FAILED',
          details: { reason: 'no_valid_otp' },
          ipAddress: req.ip,
        },
      });
      return res.status(401).json({ error: 'No valid verification code found. Please log in again.' });
    }

    // Check attempt limit
    if (otpRecord.attempts >= OTP_MAX_ATTEMPTS) {
      await prisma.otpCode.update({
        where: { id: otpRecord.id },
        data: { usedAt: new Date() },
      });
      await prisma.auditLog.create({
        data: {
          userId: payload.id,
          action: 'OTP_FAILED',
          details: { reason: 'max_attempts_exceeded' },
          ipAddress: req.ip,
        },
      });
      return res.status(401).json({ error: 'Too many failed attempts. Please log in again.' });
    }

    // Verify the OTP
    const codeHash = hashToken(otp);
    if (codeHash !== otpRecord.codeHash) {
      await prisma.otpCode.update({
        where: { id: otpRecord.id },
        data: { attempts: otpRecord.attempts + 1 },
      });
      await prisma.auditLog.create({
        data: {
          userId: payload.id,
          action: 'OTP_FAILED',
          details: { reason: 'wrong_code', attempts: otpRecord.attempts + 1 },
          ipAddress: req.ip,
        },
      });
      const remaining = OTP_MAX_ATTEMPTS - (otpRecord.attempts + 1);
      return res.status(401).json({
        error: `Incorrect verification code. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.`,
      });
    }

    // OTP correct — mark as used and update login timestamp
    await prisma.otpCode.update({
      where: { id: otpRecord.id },
      data: { usedAt: new Date() },
    });

    await prisma.user.update({
      where: { id: payload.id },
      data: { lastLoginAt: new Date(), force2FA: false },
    });

    const user = await prisma.user.findUnique({
      where: { id: payload.id },
      select: { id: true, email: true, role: true, firstName: true, lastName: true, isActive: true },
    });

    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'Account is deactivated.' });
    }

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'OTP_VERIFIED',
        details: { email: user.email },
        ipAddress: req.ip,
      },
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
      user: { id: user.id, email: user.email, role: user.role, firstName: user.firstName, lastName: user.lastName },
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// GET /api/auth/unlock/:token
// Validates the unlock token and returns the user's security question.
// ---------------------------------------------------------------------------
router.get('/unlock/:token', async (req, res, next) => {
  try {
    const tokenHash = hashToken(req.params.token);
    const unlockToken = await prisma.unlockToken.findUnique({
      where: { tokenHash },
      include: { user: { select: { securityQuestion: true } } },
    });

    if (!unlockToken || unlockToken.usedAt || unlockToken.expiresAt < new Date()) {
      return res.status(410).json({ error: 'This unlock link is invalid or has expired. Please contact your administrator.' });
    }

    res.json({ securityQuestion: unlockToken.user.securityQuestion });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/unlock/:token
// Verifies the security answer and unlocks the account.
// ---------------------------------------------------------------------------
router.post('/unlock/:token', async (req, res, next) => {
  try {
    const { securityAnswer } = req.body;
    if (!securityAnswer || typeof securityAnswer !== 'string') {
      return res.status(400).json({ error: 'Security answer is required.' });
    }

    const tokenHash = hashToken(req.params.token);
    const unlockToken = await prisma.unlockToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!unlockToken || unlockToken.usedAt || unlockToken.expiresAt < new Date()) {
      return res.status(410).json({ error: 'This unlock link is invalid or has expired. Please contact your administrator.' });
    }

    const { user } = unlockToken;

    // If an admin has deactivated this account, unlock should not be permitted
    if (!user.isActive) {
      return res.status(403).json({ error: 'Your account has been deactivated. Contact your administrator.' });
    }

    const answerValid = user.securityAnswerHash &&
      await bcrypt.compare(securityAnswer.toLowerCase().trim(), user.securityAnswerHash);

    if (!answerValid) {
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'UNLOCK_FAILED',
          details: { reason: 'wrong_security_answer' },
          ipAddress: req.ip,
        },
      });
      return res.status(401).json({ error: 'Incorrect security answer.' });
    }

    // Unlock account and mark token as used atomically
    await prisma.$transaction([
      prisma.user.update({
        where: { id: user.id },
        data: { failedLoginAttempts: 0, lockedUntil: null },
      }),
      prisma.unlockToken.update({
        where: { id: unlockToken.id },
        data: { usedAt: new Date() },
      }),
    ]);

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'ACCOUNT_UNLOCKED',
        details: { method: 'security_question' },
        ipAddress: req.ip,
      },
    });

    res.json({ message: 'Account unlocked. You may now log in.' });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/request-password-reset
// Always returns success to avoid revealing whether an email exists.
// ---------------------------------------------------------------------------
router.post('/request-password-reset', async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== 'string') {
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    const user = await prisma.user.findUnique({ where: { email } });

    if (user && user.isActive) {
      // Invalidate any prior unused reset tokens
      await prisma.passwordResetToken.updateMany({
        where: { userId: user.id, usedAt: null },
        data: { usedAt: new Date() },
      });

      const plainToken = crypto.randomBytes(32).toString('hex');
      const tokenHash = hashToken(plainToken);
      const expiresAt = new Date(Date.now() + PASSWORD_RESET_EXPIRY_HOURS * 60 * 60 * 1000);

      await prisma.passwordResetToken.create({
        data: { tokenHash, userId: user.id, expiresAt },
      });

      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'PASSWORD_RESET_REQUESTED',
          details: { email: user.email },
          ipAddress: req.ip,
        },
      });

      sendPasswordResetEmail(user.email, plainToken).catch(err =>
        console.error('[email] Failed to send password reset email:', err),
      );
    }

    res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// GET /api/auth/reset-password/:token
// Validates the reset token without consuming it.
// ---------------------------------------------------------------------------
router.get('/reset-password/:token', async (req, res, next) => {
  try {
    const tokenHash = hashToken(req.params.token);
    const resetToken = await prisma.passwordResetToken.findUnique({ where: { tokenHash } });

    if (!resetToken || resetToken.usedAt || resetToken.expiresAt < new Date()) {
      return res.status(410).json({ error: 'This reset link is invalid or has expired.' });
    }

    res.json({ valid: true });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/reset-password/:token
// Validates the token, checks password complexity & history, updates password.
// ---------------------------------------------------------------------------
const resetPasswordSchema = z.object({
  password: z.string().min(12, 'Password must be at least 12 characters').max(128),
});

router.post('/reset-password/:token', async (req, res, next) => {
  try {
    const tokenHash = hashToken(req.params.token);
    const resetToken = await prisma.passwordResetToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!resetToken || resetToken.usedAt || resetToken.expiresAt < new Date()) {
      return res.status(410).json({ error: 'This reset link is invalid or has expired.' });
    }

    const result = resetPasswordSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({ error: result.error.issues[0].message });
    }
    const { password } = result.data;

    const complexityError = validatePasswordComplexity(password);
    if (complexityError) {
      return res.status(400).json({ error: complexityError });
    }

    const { user } = resetToken;

    // Check against last 3 passwords
    const recentPasswords = await prisma.passwordHistory.findMany({
      where: { userId: user.id },
      orderBy: { createdAt: 'desc' },
      take: PASSWORD_HISTORY_COUNT,
    });

    for (const entry of recentPasswords) {
      const reused = await bcrypt.compare(password, entry.passwordHash);
      if (reused) {
        return res.status(400).json({ error: 'Cannot reuse your last 3 passwords. Please choose a different password.' });
      }
    }

    const newPasswordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // Update password, save to history, mark token used, revoke all sessions — atomically
    await prisma.$transaction([
      prisma.user.update({
        where: { id: user.id },
        data: { passwordHash: newPasswordHash },
      }),
      prisma.passwordHistory.create({
        data: { userId: user.id, passwordHash: newPasswordHash },
      }),
      prisma.passwordResetToken.update({
        where: { id: resetToken.id },
        data: { usedAt: new Date() },
      }),
      // Revoke all existing sessions so old tokens can no longer be used
      prisma.refreshToken.updateMany({
        where: { userId: user.id, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ]);

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'PASSWORD_RESET_COMPLETED',
        details: { email: user.email },
        ipAddress: req.ip,
      },
    });

    res.json({ message: 'Password has been reset. You may now log in.' });
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
      select: { id: true, email: true, role: true, isActive: true, firstName: true, lastName: true },
    });

    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'Account is deactivated.' });
    }

    const { accessToken, refreshToken: newRefreshToken } = await issueTokenPair(user);
    res.json({ token: accessToken, refreshToken: newRefreshToken, user: { id: user.id, email: user.email, role: user.role, firstName: user.firstName, lastName: user.lastName } });
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
    let userId = null;
    if (refreshToken) {
      const tokenHash = hashToken(refreshToken);
      const existing = await prisma.refreshToken.findUnique({ where: { tokenHash }, select: { userId: true } });
      userId = existing?.userId ?? null;
      await prisma.refreshToken.updateMany({
        where: { tokenHash, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    }

    // Fallback: extract userId from JWT if refresh token didn't resolve one
    if (!userId) {
      try {
        const header = req.headers.authorization;
        if (header && header.startsWith('Bearer ')) {
          const payload = jwt.verify(header.slice(7), process.env.JWT_SECRET);
          userId = payload.id;
        }
      } catch {
        // Token may be expired — that's fine, best-effort
      }
    }

    if (userId) {
      await prisma.auditLog.create({
        data: {
          userId,
          action: 'LOGOUT',
          details: {},
          ipAddress: req.ip,
        },
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

function signPending2faToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, pending2FA: true },
    process.env.JWT_SECRET,
    { expiresIn: '5m' },
  );
}

function generateOtp() {
  return crypto.randomInt(0, 1000000).toString().padStart(6, '0');
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
