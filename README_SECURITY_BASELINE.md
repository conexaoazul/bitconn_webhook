# Security baseline contribution

This branch contains a focused, upstreamable security baseline for `bitconn_webhook`.

It intentionally keeps deployment-specific policy out of the module and focuses on portable controls:

- no network/package installation during addon import;
- explicit WebSocket dependency declaration;
- administrator-only execution-log access while preserving the legacy ACL external ID for safe upgrades;
- credential redaction before execution-log persistence;
- serializable pin/capture responses for multipart uploads;
- positive execution-log retention validation;
- Odoo regression tests for ACL, credential redaction and retention;
- documented threat boundaries and upgrade checks in `SECURITY.md`.

Terminal isolation, HMAC anti-replay, rate limiting and idempotency are intentionally left for separate changes so this review remains small and auditable.
