# Production launch checklist

## Application

- [x] Local detection and redaction are deterministic and tested.
- [x] API rejects raw prompt, secret, password, token, cookie, and authorization fields.
- [x] Passwords use scrypt and sessions are opaque HttpOnly cookies.
- [x] Organization roles and permission checks exist.
- [x] PostgreSQL schema includes tenant identifiers, foreign keys, indexes, and RLS policies.
- [ ] Run migrations through an authenticated deployment job.
- [ ] Use a managed PostgreSQL pool with TLS and connection limits.
- [ ] Replace local fallback auth in production configuration.
- [ ] Add CSRF protection for cookie-authenticated state changes.
- [ ] Add persistent distributed rate limiting.

## Billing and operations

- [x] Entitlement abstraction separates plan access from product code.
- [ ] Add a payment provider adapter and verify webhook signatures.
- [ ] Add audited admin actions and immutable audit retention.
- [ ] Configure backups, restore drills, key rotation, and incident response.
- [ ] Configure error/performance monitoring with sensitive-data scrubbing.

## Independent review

Before selling to organizations, commission an external security assessment covering authentication, IDOR, tenant isolation, extension message spoofing, XSS, CSRF, SSRF, SQL injection, ReDoS, dependency supply chain, and Chrome Web Store policy compliance. This repository does not claim that an external audit has been completed.
