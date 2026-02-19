# HIPAA Messenger

A HIPAA-compliant encrypted messaging platform for healthcare organizations, enabling secure communication between agents and administrators for MARx (Medication Administration Record) lookup requests.

## Project Overview

Agents submit MARx lookup requests that enter a shared admin queue. Admins claim and respond to requests within a dedicated conversation. Agents are scoped to their own conversations only. All message content is encrypted at rest using AES-256-GCM.

## Stack

- **Runtime**: Node.js (CommonJS)
- **Backend**: Express, Socket.io, Prisma ORM
- **Database**: PostgreSQL
- **Frontend**: React (Vite), Socket.io-client
- **Auth**: JWT (short-lived access tokens)
- **Encryption**: AES-256-GCM (Node.js `crypto` module, built-in)

## Directory Structure

```
hippa-messenger/
├── CLAUDE.md
├── package.json          # Root npm workspace config
├── backend/
│   ├── package.json
│   ├── .env.example
│   ├── prisma/
│   │   └── schema.prisma
│   └── src/
│       ├── index.js           # Express + Socket.io entry point
│       ├── lib/
│       │   ├── prisma.js      # Prisma client singleton
│       │   └── crypto.js      # AES-256-GCM encrypt/decrypt helpers
│       ├── middleware/
│       │   ├── auth.js        # JWT verification middleware
│       │   └── requireRole.js # RBAC middleware (AGENT / ADMIN)
│       ├── routes/
│       │   ├── auth.js        # POST /api/auth/register, /login
│       │   ├── messages.js    # GET/POST messages within a conversation
│       │   ├── conversations.js
│       │   └── admin.js       # Admin queue: list, claim, respond
│       └── socket/
│           └── index.js       # Socket.io event handlers
└── frontend/
    ├── package.json
    ├── index.html
    ├── vite.config.js
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── context/
        │   └── AuthContext.jsx
        ├── lib/
        │   └── api.js         # Axios instance with JWT header injection
        ├── pages/
        │   ├── LoginPage.jsx
        │   ├── AgentPage.jsx  # Submit MARx request, view own conversations
        │   └── AdminPage.jsx  # Queue view, claim, respond
        └── components/
            ├── ConversationList.jsx
            ├── MessageList.jsx
            ├── MessageInput.jsx
            └── AdminQueue.jsx
```

## Data Models (Prisma)

| Model | Purpose |
|---|---|
| `User` | Authenticated user; role is `AGENT` or `ADMIN` |
| `Conversation` | Thread between one agent and one (or more) admins |
| `ConversationParticipant` | Join table; enforces who can read a conversation |
| `Message` | Encrypted message within a conversation |
| `MARxRequest` | Tracks state of a lookup request (`PENDING → CLAIMED → RESOLVED`) |
| `AuditLog` | Append-only log of sensitive actions for HIPAA audit trail |

## Security & HIPAA Notes

- **Encryption at rest**: Every `Message.encryptedContent` is AES-256-GCM encrypted. The IV is stored alongside the ciphertext. The encryption key comes from `ENCRYPTION_KEY` env var (32-byte hex).
- **Access control**: Agents can only query conversations they are a `ConversationParticipant` of. This is enforced at the route layer, not just the UI.
- **Audit logging**: All create/claim/resolve actions write an `AuditLog` row (userId, action, details, IP).
- **Passwords**: Hashed with bcrypt (cost factor ≥ 12).
- **HTTPS**: Must be terminated at the load balancer or via nginx in production. Never run HTTP in production.
- **JWT expiry**: Access tokens expire in 15 minutes; refresh token flow should be added before production.

## Environment Variables

See `backend/.env.example`. Required vars:
- `DATABASE_URL` – PostgreSQL connection string
- `JWT_SECRET` – long random string for signing tokens
- `ENCRYPTION_KEY` – 64 hex chars (32 bytes) for AES-256-GCM

## Development Setup

```bash
# Install all dependencies (root workspace)
npm install

# Start backend dev server
npm run dev:backend

# Start frontend dev server
npm run dev:frontend

# Run Prisma migrations
cd backend && npx prisma migrate dev
```

## Key Conventions

- All route handlers are async; errors bubble to a central error handler in `src/index.js`.
- Encryption/decryption happens in `lib/crypto.js` — never inline crypto logic in routes.
- Socket.io events are authenticated: the `socket.handshake.auth.token` JWT is verified before any room join.
- Admins join the `admin-queue` Socket.io room; agents join rooms named `conversation:{id}`.
