# API baseline

`GET /health` returns service health.

`POST /v1/security-events` accepts metadata only. The current local implementation applies a payload size limit, rejects sensitive field names recursively, and returns `202` without persisting data. Authentication, tenant authorization, persistence, and rate limiting are required before production use.
