# Security hardening notes

## Proposed baseline

- Remove runtime `pip install` from addon import.
- Declare the WebSocket dependency explicitly.
- Preserve `access_bitconn_execution_log_user` while moving it to `base.group_system` so upgrades revoke broad read access instead of leaving a stale ACL behind.
- Redact reusable credentials from persisted execution logs.
- Keep multipart `FileStorage` objects out of pin/capture JSON responses.
- Reject zero/negative execution-log retention values.
- Add Odoo regression coverage for ACL, credential redaction and retention.

This contribution is intentionally scoped. Terminal isolation and request-level controls such as HMAC anti-replay, rate limiting and idempotency are proposed as separate follow-ups.
