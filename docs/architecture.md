# Architecture

The repository is an npm workspace monorepo.

- `packages/detection-engine`: browser-independent deterministic scanning.
- `packages/redaction-engine`: span-based formatting-preserving redaction.
- `apps/extension`: Manifest V3 content script, service worker, popup, and options page.
- `services/api`: small metadata-only HTTP boundary for local development.
- `infrastructure/docker`: local PostgreSQL development service.

The next production boundary is a typed repository layer between the API and PostgreSQL, with organization ID checks at every query.
