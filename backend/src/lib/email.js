'use strict';

const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);
const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@goatedlookups.com';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

async function sendUnlockEmail(toEmail, unlockToken) {
  const unlockUrl = `${FRONTEND_URL}/unlock/${unlockToken}`;

  await resend.emails.send({
    from: FROM_EMAIL,
    to: toEmail,
    subject: 'Unlock your Goated Lookups account',
    html: `
      <p>Your <strong>Goated Lookups</strong> account has been locked after too many failed login attempts.</p>
      <p>Click the link below to unlock your account. You will need to answer your security question.</p>
      <p><a href="${unlockUrl}" style="display:inline-block;padding:10px 20px;background:#1a73e8;color:white;text-decoration:none;border-radius:4px;">Unlock My Account</a></p>
      <p>This link expires in <strong>1 hour</strong>.</p>
      <p>If you did not attempt to log in, contact your administrator immediately.</p>
    `,
  });
}

async function sendOtpEmail(toEmail, otpCode) {
  await resend.emails.send({
    from: FROM_EMAIL,
    to: toEmail,
    subject: 'Your Goated Lookups verification code',
    html: `
      <p>Your <strong>Goated Lookups</strong> verification code is:</p>
      <p style="font-size:32px;font-weight:bold;letter-spacing:8px;text-align:center;
                padding:16px;background:#f4f4f5;border-radius:8px;font-family:monospace;">
        ${otpCode}
      </p>
      <p>This code expires in <strong>5 minutes</strong>.</p>
      <p>If you did not attempt to log in, contact your administrator immediately.</p>
    `,
  });
}

module.exports = { sendUnlockEmail, sendOtpEmail };
