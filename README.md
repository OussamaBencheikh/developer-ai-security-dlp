# Developer AI Security DLP

Privacy-first protection that helps detect sensitive developer information before it is sent to supported AI services.

## Current implementation

- Strict TypeScript npm monorepo.
- Local detection engine with developer-focused rules, context checks, placeholder suppression, severity and confidence metadata.
- Redaction engine that only consumes spans and replacement labels; it never needs the original secret as a separate value.
- Manifest V3 extension foundation for ChatGPT, Claude, and Gemini domains.
- Metadata-only API endpoint and security headers.
- Local development authentication endpoints with scrypt password hashing and opaque HttpOnly sessions.
- PostgreSQL migration for organizations, members, users, sessions, policies, and metadata-only security events.
- A dashboard web app with authenticated overview metrics and organization role visibility.
- Centralized organization RBAC and billing entitlements for FREE, PRO, TEAM, and ENTERPRISE.
- Synthetic tests for detection and redaction.
- Team, billing, and admin API routes with authorization checks.

Raw prompts and secret values are not sent to the API by design.

The API uses PostgreSQL-backed authentication automatically when `DATABASE_URL` is configured; without it, it falls back to an in-memory local development store. Apply `infrastructure/database/001_initial.sql` before starting with PostgreSQL.

## Development

Requires Node.js 20+ and npm 10+.

```sh
npm install
npm run typecheck
npm test
npm run build
```

Run the API with `npm run build -w @dlp/api` and `npm run start -w @dlp/api`.

For a local dashboard session, use three terminals from the repository root:

```sh
docker compose -f infrastructure/docker/docker-compose.yml up -d postgres
$env:DATABASE_URL="postgresql://dlp:dlp@localhost:5432/dlp" # PowerShell
npm run build
npm run start -w @dlp/api
python -m http.server 5173 --directory apps/web/dist
```

Open `http://localhost:5173`, choose **Register**, and use a password with at least 12 characters. Without `DATABASE_URL`, the API uses an in-memory store for quick local demos and accounts disappear when the API restarts.

## Build the extension

```sh
npm run build -w @dlp/extension
```

Load the unpacked extension from `apps/extension/dist` in `chrome://extensions` with Developer mode enabled.

## Production boundary

The working local product includes the detection core, extension, CLI, Git hook, API authentication, dashboard, RBAC, team routes, billing entitlements, and PostgreSQL schema/repository. Production still requires managed database operations, payment-provider webhooks, CSRF protection, distributed rate limiting, observability, deployment hardening, and an external security audit. See `docs/production-checklist.md`.
