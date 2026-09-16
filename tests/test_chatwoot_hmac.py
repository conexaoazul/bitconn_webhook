import hashlib
import hmac
import time

from odoo.tests.common import TransactionCase


class TestChatwootHmac(TransactionCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.secret = 'chatwoot-test-secret'
        cls.webhook = cls.env['bitconn.webhook'].create({
            'name': 'Chatwoot HMAC Test',
            'user_id': cls.env.user.id,
            'inbound_auth_type': 'chatwoot_hmac',
            'secret_key': cls.secret,
            'can_create': False,
            'can_write': False,
            'can_unlink': False,
            'can_code': False,
        })

    def _headers(self, body, timestamp):
        message = str(timestamp).encode('ascii') + b'.' + body
        signature = 'sha256=' + hmac.new(
            self.secret.encode('utf-8'), message, hashlib.sha256
        ).hexdigest()
        return {
            'X-Chatwoot-Timestamp': str(timestamp),
            'X-Chatwoot-Signature': signature,
        }

    def test_valid_chatwoot_signature(self):
        body = b'{"event":"message_created","id":123}'
        now = int(time.time())
        headers = self._headers(body, now)
        self.assertTrue(self.webhook._check_inbound_auth(headers, body))

    def test_invalid_chatwoot_signature(self):
        body = b'{"event":"message_created","id":123}'
        now = int(time.time())
        headers = self._headers(body, now)
        headers['X-Chatwoot-Signature'] = 'sha256=' + ('0' * 64)
        self.assertFalse(self.webhook._check_inbound_auth(headers, body))

    def test_stale_chatwoot_timestamp(self):
        body = b'{"event":"message_created","id":123}'
        stale = int(time.time()) - 301
        headers = self._headers(body, stale)
        self.assertFalse(self.webhook._check_inbound_auth(headers, body))

    def test_missing_chatwoot_headers(self):
        self.assertFalse(self.webhook._check_inbound_auth({}, b'{}'))

    def test_legacy_header_auth_still_works(self):
        self.webhook.inbound_auth_type = 'header'
        headers = {'Authorization': 'Bearer %s' % self.secret}
        self.assertTrue(self.webhook._check_inbound_auth(headers))

    def test_public_mode_still_works(self):
        self.webhook.inbound_auth_type = 'none'
        self.assertTrue(self.webhook._check_inbound_auth({}))
