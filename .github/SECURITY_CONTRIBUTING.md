# Security contribution guidance

Keep security fixes focused and independently reviewable. Prefer preserving existing Odoo external IDs during permission migrations, avoid runtime network/package installation, add regression tests for upgrade behavior, and keep deployment-specific policy outside the reusable addon.
