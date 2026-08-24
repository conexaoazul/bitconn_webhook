# -*- coding: utf-8 -*-

import json
import re

from odoo import api, models, _
from odoo.exceptions import ValidationError


_SENSITIVE_KEYS = {
    'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
    'password', 'passwd', 'secret', 'secret_key', 'client_secret',
    'access_token', 'refresh_token', 'token', 'api_key', 'apikey',
    'webhook-key', 'webhook_key', 'x-webhook-key', 'x_webhook_key',
}
_LOG_TEXT_FIELDS = ('input_data', 'execution_data', 'output_data', 'error_message')


def _redact_value(value):
    if isinstance(value, dict):
        return {
            key: ('***REDACTED***' if str(key).lower() in _SENSITIVE_KEYS else _redact_value(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _sanitize_log_text(value):
    if not isinstance(value, str) or not value:
        return value
    try:
        parsed = json.loads(value)
    except Exception:
        sanitized = value
        for key in _SENSITIVE_KEYS:
            sanitized = re.sub(
                rf'(?i)(["\']?{re.escape(key)}["\']?\s*[:=]\s*["\']?)([^"\'\s,;}}]+)',
                rf'\1***REDACTED***',
                sanitized,
            )
        sanitized = re.sub(
            r'(?i)(authorization\s*[:=]\s*["\']?bearer\s+)[^"\'\s,;}}]+',
            r'\1***REDACTED***',
            sanitized,
        )
        return sanitized
    return json.dumps(_redact_value(parsed), ensure_ascii=False, default=str)


class BitconnWebhookSecurityHardening(models.Model):
    _inherit = 'bitconn.webhook'

    def _exec_code(self, *args, **kwargs):
        result = super()._exec_code(*args, **kwargs)
        if isinstance(result, dict) and result.get('request') and isinstance(result['request'], dict):
            request_copy = dict(result['request'])
            # FileStorage objects stay available during custom-code execution,
            # but never leave pin/capture responses where JSON serialization occurs.
            request_copy.pop('files_data', None)
            result = dict(result)
            result['request'] = request_copy
        return result


class BitconnWebhookExecutionLogSecurity(models.Model):
    _inherit = 'bitconn.webhook.execution.log'

    @api.model_create_multi
    def create(self, vals_list):
        safe_vals_list = []
        for vals in vals_list:
            vals = dict(vals)
            for field_name in _LOG_TEXT_FIELDS:
                if field_name in vals:
                    vals[field_name] = _sanitize_log_text(vals[field_name])
            safe_vals_list.append(vals)
        return super().create(safe_vals_list)

    def write(self, vals):
        vals = dict(vals)
        for field_name in _LOG_TEXT_FIELDS:
            if field_name in vals:
                vals[field_name] = _sanitize_log_text(vals[field_name])
        return super().write(vals)


class BitconnWebhookConfigSettingsSecurity(models.TransientModel):
    _inherit = 'bitconn.webhook.config.settings'

    @api.constrains('execution_log_retention_days')
    def _check_execution_log_retention_days(self):
        for record in self:
            if record.execution_log_retention_days <= 0:
                raise ValidationError(_('Execution log retention must be greater than zero days.'))

    def action_save(self):
        self._check_execution_log_retention_days()
        return super().action_save()
