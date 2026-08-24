# -*- coding: utf-8 -*-

import json

from odoo.exceptions import ValidationError
from odoo.tests.common import TransactionCase

from ..models.security_hardening import _sanitize_log_text


class TestBitconnWebhookSecurityHardening(TransactionCase):
    def test_execution_log_acl_external_id_is_restricted_to_system_group(self):
        access = self.env.ref('bitconn_webhook.access_bitconn_execution_log_user')
        self.assertEqual(access.group_id, self.env.ref('base.group_system'))
        self.assertTrue(access.perm_read)

    def test_supported_webhook_credential_headers_are_redacted_from_json(self):
        payload = json.dumps({
            'headers': {
                'Webhook-Key': 'secret-one',
                'webhook_key': 'secret-two',
                'X-Webhook-Key': 'secret-three',
                'x_webhook_key': 'secret-four',
                'Content-Type': 'application/json',
            }
        })
        headers = json.loads(_sanitize_log_text(payload))['headers']
        for key in ('Webhook-Key', 'webhook_key', 'X-Webhook-Key', 'x_webhook_key'):
            self.assertEqual(headers[key], '***REDACTED***')
        self.assertEqual(headers['Content-Type'], 'application/json')

    def test_supported_webhook_credential_headers_are_redacted_from_text(self):
        sanitized = _sanitize_log_text(
            'Webhook-Key: secret-one; webhook_key=secret-two; '
            'X-Webhook-Key: secret-three; x_webhook_key=secret-four'
        )
        for secret in ('secret-one', 'secret-two', 'secret-three', 'secret-four'):
            self.assertNotIn(secret, sanitized)
        self.assertGreaterEqual(sanitized.count('***REDACTED***'), 4)

    def test_execution_log_retention_must_be_positive(self):
        settings = self.env['bitconn.webhook.config.settings'].new({
            'execution_log_retention_days': 0,
        })
        with self.assertRaises(ValidationError):
            settings._check_execution_log_retention_days()
