# Commercial readiness

## Implemented foundation

- Dashboard web app in `apps/web` with login, overview metrics, recent event metadata, role display, and logout.
- PostgreSQL schema and tenant-scoped repository in `services/api`.
- Organization roles and permission checks in `services/api/src/authorization.ts`.
- Centralized plan entitlements in `services/billing`.
- Local auth/session implementation for development.

## Implemented API surface

- `GET /v1/team` and `POST /v1/team/members` enforce organization role permissions.
- `GET /v1/billing` exposes local entitlement metadata without claiming payment processing.
- `GET /v1/admin/health` is restricted to owner/admin roles.
- RLS policies protect policies and security events when tenant context is set.

## Still required before production billing or enterprise sale

- Wire the repository into the API with a managed PostgreSQL pool and migrations runner.
- Replace the in-memory auth store with database-backed users and hashed session identifiers.
- Add email-backed member invitations and persist member-management audit records.
- Add a real payment provider adapter and webhook signature verification.
- Add a full admin web surface with audited actions.
- Add production deployment, backup/restore, monitoring, and an external security audit.