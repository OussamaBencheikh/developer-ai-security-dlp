# Security Baseline

## Privacy boundary

Detection runs locally in the extension. The API accepts security-event metadata only and rejects payloads containing prompt, secret, source-code, password, token, or private-key field names.

## Current controls

- Manifest V3 with narrowly scoped AI host permissions.
- No remote JavaScript execution.
- Strict TypeScript settings.
- Placeholder suppression and confidence/severity scoring.
- API payload size limit and security headers.
- No secret values in detection results; only spans and category-specific replacement labels.

## Required before production

Add authenticated sessions, PostgreSQL repositories with tenant-scoped queries, CSRF/session protections, rate limiting backed by shared storage, audit logging, dependency scanning, signed extension release artifacts, and independent security testing.
