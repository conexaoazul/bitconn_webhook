# Security model

## Trust boundaries

`bitconn_webhook` can expose Odoo operations and optional custom-code execution to external callers. The optional web terminal can spawn an operating-system or Odoo shell. Treat both surfaces as privileged integration endpoints.

## Baseline controls

- Keep inbound authentication enabled and rotate webhook credentials when exposure is suspected.
- WebSocket support is an environment dependency; importing the addon never installs packages or performs network access.
- Execution logs are administrator-only and sensitive credential fields are redacted before persistence.
- Multipart file objects are available to custom code but are excluded from pin/capture responses.
- Execution-log retention must be a positive number of days.

## Deployment guidance

Install Python dependencies in the image or virtualenv before Odoo starts. Use a secure `bitconn_ws_secret_key` of at least 32 characters when the terminal is enabled. Place WebSocket transport behind TLS in production and restrict network exposure at the reverse proxy and firewall layers.

## Upgrade regression checks

When upgrading from a revision that exposed execution logs to `base.group_user`, verify that the existing external ID `bitconn_webhook.access_bitconn_execution_log_user` is updated to `base.group_system`.

Verify that accepted webhook credential headers (`Webhook-Key`, `webhook_key`, `X-Webhook-Key`, `x_webhook_key`) never persist in execution logs.

## Scope note

This baseline intentionally avoids deployment-platform-specific policy. Terminal isolation into an optional addon and stronger request controls such as HMAC anti-replay, rate limiting and idempotency are best reviewed as separate changes.
