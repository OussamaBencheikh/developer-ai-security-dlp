# Threat model

Assets include prompt content, credentials, sessions, organization metadata, and security-event metadata. The primary trust boundary is the browser extension to API boundary.

The extension keeps prompt content local. The API must authenticate callers, authorize every organization-owned resource, reject sensitive fields, and avoid logging request bodies. Threats include malicious pages, forged extension messages, IDOR, session theft, rule tampering, and accidental telemetry collection.

This document is a baseline; a production release requires a reviewed STRIDE analysis and independent testing.
