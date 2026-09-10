# API baseline

`GET /health` returns service health.

`POST /v1/security-events` accepts metadata only. The current local implementation applies a payload size limit, rejects sensitive field names recursively, and returns `202` without persisting data. Authentication, tenant authorization, persistence, and rate limiting are required before production use.

Authentication endpoints are available for local development:

- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `GET /v1/auth/me`
- `POST /v1/auth/logout`

They use scrypt hashing and opaque HttpOnly sessions in memory. Production must replace the store with the PostgreSQL schema in `infrastructure/database/001_initial.sql` and hash session identifiers at rest.
