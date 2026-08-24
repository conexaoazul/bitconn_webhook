## Security change

Describe the trust boundary affected and why the change is safe to upgrade.

### Checklist

- [ ] No secrets or reusable credentials are persisted in logs.
- [ ] Existing XML/external IDs are preserved when changing access rules.
- [ ] No network/package installation occurs during addon import or registry load.
- [ ] Odoo regression tests cover the security behavior.
- [ ] Upgrade/rollback implications are documented.
