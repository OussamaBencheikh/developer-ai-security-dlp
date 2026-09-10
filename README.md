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

## Build the extension

```sh
npm run build -w @dlp/extension
```

Load the unpacked extension from `apps/extension/dist` in `chrome://extensions` with Developer mode enabled.

## Scope

This repository currently contains the secure working core and foundations. Authentication, persistent PostgreSQL repositories, organization authorization, dashboard UI, billing providers, and Chrome Web Store packaging remain explicitly tracked work rather than being represented as completed.
