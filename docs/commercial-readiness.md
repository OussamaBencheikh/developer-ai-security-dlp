# Commercial readiness

## Implemented foundation

- Dashboard web app in `apps/web` with login, overview metrics, recent event metadata, role display, and logout.
- PostgreSQL schema and tenant-scoped repository in `services/api`.
- Organization roles and permission checks in `services/api/src/authorization.ts`.
- Centralized plan entitlements in `services/billing`.
- Local auth/session implementation for development.

## Still required before production billing or enterprise sale

- Wire the repository into the API with a managed PostgreSQL pool and migrations runner.
- Replace the in-memory auth store with database-backed users and hashed session identifiers.
- Add member invitation/removal endpoints with authorization checks and audit records.
- Add a real payment provider adapter and webhook signature verification.
- Add admin-only routes and an admin web surface with audited actions.
- Add production deployment, backup/restore, monitoring, and an external security audit.