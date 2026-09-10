# API baseline

`GET /health` returns service health.

`POST /v1/security-events` accepts metadata only. The current local implementation applies a payload size limit, rejects sensitive field names recursively, and returns `202` without persisting data. Authentication, tenant authorization, persistence, and rate limiting are required before production use.

Authentication endpoints are available for local development:

- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `GET /v1/auth/me`
- `POST /v1/auth/logout`

They use scrypt hashing and opaque HttpOnly sessions. With `DATABASE_URL`, users and session hashes are stored in PostgreSQL; without it, the API uses an in-memory local fallback. Apply `infrastructure/database/001_initial.sql` before enabling the database mode.
