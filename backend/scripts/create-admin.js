'use strict';

/**
 * One-time script to create an ADMIN user.
 * Run with your production DATABASE_URL to seed the live database:
 *
 *   DATABASE_URL="postgresql://..." node scripts/create-admin.js
 *
 * Or just run it locally if your .env already points at the right database.
 */

require('dotenv').config();
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
const readline = require('readline');

const prisma = new PrismaClient();

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((res) => rl.question(q, res));

async function main() {
  const email = (await ask('Admin email: ')).trim().toLowerCase();
  const password = await ask('Admin password (min 8 chars): ');

  if (password.length < 8) {
    console.error('Password must be at least 8 characters.');
    process.exit(1);
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    console.error(`A user with email ${email} already exists (role: ${existing.role}).`);
    process.exit(1);
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      role: 'ADMIN',
      isActive: true,
    },
  });

  console.log(`\nAdmin created successfully!`);
  console.log(`  ID:    ${user.id}`);
  console.log(`  Email: ${user.email}`);
  console.log(`  Role:  ${user.role}`);
}

main()
  .catch((err) => { console.error(err); process.exit(1); })
  .finally(async () => { rl.close(); await prisma.$disconnect(); });
