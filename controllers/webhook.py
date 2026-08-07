from odoo import http
from odoo.http import request
import json
import re
import ast
import time
import gzip
import zlib
from urllib.parse import urlencode
from lxml import etree


class BitconnWebhookController(http.Controller):

    def _resolve_conf(self, uuid_str):
        return request.env['bitconn.webhook'].sudo().search([('webhook_uuid', '=', uuid_str)], limit=1)

    def _validate(self, conf):
        headers = request.httprequest.headers
        return conf._check_header(headers)

    def _save_sample_async(self, webhook_id, raw_body):
        """Save sample request asynchronously after commit"""
        try:
            with request.env.registry.cursor() as new_cr:
                webhook = request.env['bitconn.webhook'].with_env(
                    request.env(cr=new_cr)
                ).sudo().browse(webhook_id)
                if webhook.exists():
                    webhook.write({'sample_request_payload': raw_body[:10000]})
                    new_cr.commit()
        except Exception:
            pass  # Silent fail

    def _default_payload(self, conf):
        return {
            'secret_key': conf.secret_key,
            'webhook_uuid': conf.webhook_uuid,
            'model': 'res.partner',
            'method': 'create',
            'domain': [],
            'values': {'name': 'Webhook Partner'},
        }

    def _lenient_parse(self, text):
        """Tenta fazer parsing JSON tolerante (vírgulas finais, aspas simples).
        Retorna (data, error_msg) onde error_msg é None se sucesso."""
        if not text:
            return {}, None
        # Primeiro: tentativa normal
        try:
            return json.loads(text), None
        except Exception as e_first:
            original_error = str(e_first)
        work = text
        # Remover BOM se existir
        work = work.lstrip('\ufeff')
        # Remover comentários simples // ou # (linha inteira)
        work = '\n'.join([
            ln for ln in work.splitlines()
            if not ln.strip().startswith('//') and not ln.strip().startswith('#')
        ])
        # Remover vírgulas finais em objetos/arrays
        work = re.sub(r",\s*([}\]])", r"\1", work)
        # Converter aspas simples em chaves 'campo': -> "campo":
        work = re.sub(r"'([A-Za-z0-9_\-]+)'\s*:", r'"\\1":', work)
        # Converter strings de valores e arrays com aspas simples simples 'valor'
        # Cuidado para não substituir dentro de aspas duplas já válidas
        # Estratégia simples: substituir aspas simples que delimitam tokens alfanuméricos
        work = re.sub(r":\s*'([^'\\]*)'", lambda m: ': "' + m.group(1).replace('"', '\\"') + '"', work)
        work = re.sub(r"\[\s*'([^'\\]*)'", lambda m: '[ "' + m.group(1).replace('"', '\\"') + '"', work)
        work = re.sub(r"'([^'\\]*)'\s*]", lambda m: '"' + m.group(1).replace('"', '\\"') + '"]', work)
        # Strings internas em arrays separadas por vírgula
        work = re.sub(r",\s*'([^'\\]*)'", lambda m: ', "' + m.group(1).replace('"', '\\"') + '"', work)
        try:
            return json.loads(work), None
        except Exception:
            # Último fallback: se o payload for só um dicionário python, tentar ast.literal_eval
            try:
                data = ast.literal_eval(text)
                if isinstance(data, (dict, list)):
                    return data, None
            except Exception:
                pass
            return {}, 'invalid_json: %s' % original_error

    def _decode_jsonish(self, val):
        """Decodifica valores que claramente são JSON ({ ou [ no início).
        Usado em urlencoded/multipart, onde campos chegam como string."""
        if isinstance(val, str) and val and val[0] in '{[':
            try:
                return json.loads(val)
            except Exception:
                return val
        return val

    def _form_to_payload(self, form):
        """Converte um MultiDict de form em dict.
        Chaves repetidas viram lista. Valores que parecem JSON são decodificados.
        (paridade n8n: sem coerção de tipos)"""
        payload = {}
        for key in form:
            vals = form.getlist(key)
            if len(vals) == 1:
                payload[key] = self._decode_jsonish(vals[0])
            else:
                payload[key] = [self._decode_jsonish(v) for v in vals]
        return payload

    def _xml_to_dict(self, el):
        """Converte um elemento lxml em dict/string recursivamente.
        Atributos viram @nome, texto de nó com filhos vira #text,
        tags repetidas viram lista."""
        attrib = {'@%s' % k: v for k, v in (el.attrib or {}).items()}
        children = list(el)
        text = (el.text or '').strip()
        if not children and not attrib:
            return text
        node = {}
        if text:
            node['#text'] = text
        node.update(attrib)
        for ch in children:
            tag = ch.tag
            val = self._xml_to_dict(ch)
            if tag in node:
                if isinstance(node[tag], list):
                    node[tag].append(val)
                else:
                    node[tag] = [node[tag], val]
            else:
                node[tag] = val
        return node

    def _unwrap_xml_root(self, data):
        """Se o XML tiver um único nó raiz contendo um único dict, desempacota."""
        if isinstance(data, dict) and len(data) == 1:
            only = list(data.values())[0]
            if isinstance(only, dict):
                return only
        return data

    def _parse_xml(self, raw_body):
        """Converte XML em dict. Retorna (data, error_msg)."""
        try:
            root = etree.fromstring(raw_body.encode('utf-8'))
            data = self._xml_to_dict(root)
            if isinstance(data, dict):
                data = self._unwrap_xml_root(data)
            return data, None
        except Exception as e:
            return {}, 'invalid_xml: %s' % e

    def _parse_body(self, mime, httprequest):
        """Converte o body recebido em dict conforme o Content-Type.
        Retorna (payload, parse_error, files, files_data, raw_body).
        O Odoo já parseia form data (urlencoded/multipart) na dispatch via
        get_http_params -> httprequest.form, o que consome o stream — por isso
        usamos httprequest.form/files e reconstruímos o raw_body, em vez de get_data().
        Demais content-types (json/xml/text/plain/octet-stream) usam get_data()
        com suporte a gzip/deflate. application/octet-stream fica raw."""
        files = {}
        files_data = {}

        if mime == 'multipart/form-data':
            payload = self._form_to_payload(httprequest.form)
            for key in httprequest.files:
                f = httprequest.files[key]
                meta = {
                    'filename': getattr(f, 'filename', None),
                    'content_type': getattr(f, 'content_type', None),
                    'mimetype': getattr(f, 'mimetype', None),
                    'size': None,
                }
                try:
                    stream = getattr(f, 'stream', None)
                    if stream is not None and getattr(stream, 'seek', None):
                        old = stream.tell()
                        stream.seek(0, 2)
                        meta['size'] = stream.tell()
                        stream.seek(old)
                except Exception:
                    pass
                files[key] = meta
                files_data[key] = f
            return payload, None, files, files_data, ''

        if mime == 'application/x-www-form-urlencoded':
            # Stream já consumido pelo Odoo na dispatch: usa o form parseado
            # e reconstrói o raw_body para request['body']/sample.
            payload = self._form_to_payload(httprequest.form)
            raw_body = urlencode(list(httprequest.form.lists()), doseq=True)
            return payload, None, files, files_data, raw_body

        enc = (httprequest.environ.get('HTTP_CONTENT_ENCODING') or '').lower()
        data = b''
        try:
            data = httprequest.get_data() or b''
        except Exception:
            data = b''
        parse_error = None
        if enc == 'gzip' and data:
            try:
                data = gzip.decompress(data)
            except Exception as e:
                parse_error = 'invalid_encoding: %s' % e
        elif enc == 'deflate' and data:
            try:
                data = zlib.decompress(data)
            except Exception as e:
                parse_error = 'invalid_encoding: %s' % e
        raw_body = data.decode('utf-8', errors='replace')

        if not raw_body:
            return {}, parse_error, files, files_data, raw_body

        if mime in ('application/json', 'text/json') or mime.endswith('+json'):
            payload, err = self._lenient_parse(raw_body)
            return payload, parse_error or err, files, files_data, raw_body
        if mime.endswith('/xml') or mime.endswith('+xml'):
            payload, err = self._parse_xml(raw_body)
            return payload, parse_error or err, files, files_data, raw_body
        if mime == 'text/plain':
            payload, err = self._lenient_parse(raw_body)
            if err:
                payload = {'body': raw_body}
            return payload, parse_error, files, files_data, raw_body
        # application/octet-stream e demais: manter raw, sem conversão
        return {}, parse_error, files, files_data, raw_body

    @http.route('/bitconn/webhook/<string:uuid_str>', type='http', auth='public', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'], csrf=False)
    def receive(self, uuid_str, **kwargs):
        conf = self._resolve_conf(uuid_str)
        if not conf:
            return request.make_json_response({'ok': False, 'error': 'conf_not_found'}, status=404)
        if not self._validate(conf):
            return request.make_json_response({'ok': False, 'error': 'forbidden', 'reason': 'invalid_token'}, status=401)

        # Get HTTP method
        http_method = request.httprequest.method
        
        # Check if method is allowed for this webhook
        if not conf._is_method_allowed(http_method):
            allowed = []
            if conf.inbound_allowed_methods == 'POST':
                allowed = ['POST']
            elif conf.inbound_allowed_methods == 'ALL':
                allowed = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
            elif conf.inbound_allowed_methods == 'CUSTOM':
                if conf.inbound_methods_get: allowed.append('GET')
                if conf.inbound_methods_post: allowed.append('POST')
                if conf.inbound_methods_put: allowed.append('PUT')
                if conf.inbound_methods_patch: allowed.append('PATCH')
                if conf.inbound_methods_delete: allowed.append('DELETE')
            
            return request.make_json_response({
                'ok': False, 
                'error': 'method_not_allowed',
                'message': f'Method {http_method} not allowed for this webhook',
                'allowed_methods': allowed
            }, status=405)
        
        content_type = request.httprequest.content_type or ''
        mime = (content_type.split(';')[0] or '').strip().lower()

        # Converte o body em dict conforme o Content-Type.
        # Todo formato textual (json, urlencoded, multipart, xml, text/plain) vira dict.
        # Multipart não lê get_data(); gzip/deflate são descomprimidos antes do parse.
        payload, parse_error, files, files_data, raw_body = self._parse_body(mime, request.httprequest)

        # Normalizar campo 'fields' se veio em formato de string tipo Python: "['id','name',]"
        fields = payload.get('fields')
        if isinstance(fields, str):
            try:
                f_list = ast.literal_eval(fields)
                if isinstance(f_list, (list, tuple)):
                    payload['fields'] = [str(x) for x in f_list if str(x).strip()]
            except Exception:
                # manter original, não fatal
                pass
        model = payload.get('model')
        method = (payload.get('method') or 'create').lower()
        values = payload.get('values') or {}
        domain = payload.get('domain') or []
        fields = payload.get('fields')
        limit = payload.get('limit')
        offset = payload.get('offset') or 0
        order = payload.get('order')
        ids = payload.get('ids')

        # No modo código não bloqueamos por formato: o parse nunca aborta o request,
        # o conteúdo chega via request['json']/request['body'] e o código decide.
        is_code_request = conf.can_code and (
            method == 'code'
            or (not model and conf.pin_request)
            or (not model and conf.python_code)
        )

        # Se houve erro de parsing e não conseguimos extrair nada significativo
        if parse_error and not payload and not is_code_request:
            return request.make_json_response({'ok': False, 'error': 'invalid_json', 'detail': parse_error}, status=400)

        if method == 'default_payload':
            # echo current headers to ease client config
            return request.make_json_response({
                'ok': True,
                'payload': self._default_payload(conf),
                'headers_example': {
                    'Authorization': f"Bearer {conf.secret_key}",
                    'Webhook-Key': conf.secret_key,
                }
            }, status=200)

        # Helper function to save sample request asynchronously
        def save_sample_async_if_pinned():
            """Save sample request if pin_request is enabled"""
            if conf.pin_request and raw_body:
                import logging
                _logger = logging.getLogger(__name__)
                
                # Capture values BEFORE creating thread to avoid "object unbound" error
                webhook_id = conf.id
                webhook_name = conf.name
                registry = request.env.registry  # Capture registry before thread
                db_name = request.env.cr.dbname  # Capture database name
                
                _logger.info(f"PIN REQUEST DETECTED - Saving sample for webhook {webhook_name} (ID: {webhook_id})")
                
                # Build complete request object to save
                request_obj = {
                    'body': raw_body,
                    'headers': dict(request.httprequest.headers),
                    'method': request.httprequest.method,
                    'content_type': content_type,
                }
                request_obj['json'] = payload if isinstance(payload, dict) else {}
                
                # Convert to JSON string
                sample_data = json.dumps(request_obj, indent=2, ensure_ascii=False)[:10000]
                
                _logger.info(f"Sample data prepared, length: {len(sample_data)}")
                
                # Schedule async save in a separate thread to avoid serialization conflicts
                import threading
                import time
                def delayed_save():
                    time.sleep(0.5)  # Wait for main transaction to complete
                    try:
                        _logger.info(f"Starting delayed save for webhook ID {webhook_id}")
                        # Use captured registry instead of request.env.registry
                        with registry.cursor() as new_cr:
                            # Create new environment with the new cursor
                            from odoo.api import Environment
                            new_env = Environment(new_cr, 1, {})  # uid=1 (admin)
                            webhook = new_env['bitconn.webhook'].sudo().browse(webhook_id)
                            if webhook.exists():
                                webhook.write({'sample_request_payload': sample_data})
                                new_cr.commit()
                                _logger.info(f"Sample request saved successfully for webhook {webhook_name}")
                            else:
                                _logger.warning(f"Webhook ID {webhook_id} not found")
                    except Exception as e:
                        _logger.error(f"Failed to save sample request: {e}", exc_info=True)
                
                thread = threading.Thread(target=delayed_save)
                thread.daemon = True
                thread.start()
                _logger.info("Async save thread started")
            elif conf.pin_request:
                import logging
                _logger = logging.getLogger(__name__)
                # Capture webhook_name before using it
                webhook_name = conf.name
                _logger.warning(f"PIN REQUEST enabled but no raw_body for webhook {webhook_name}")
        
        # Check if custom code execution is enabled (doesn't require model)
        # If can_code is enabled and method is 'code', OR if no model provided and can_code is enabled
        if is_code_request:
            _start = time.time()
            res = conf._exec_code(
                raw_body,
                request_headers=dict(request.httprequest.headers),
                request_method=request.httprequest.method,
                content_type=content_type,
                parsed_payload=payload,
                parse_error=parse_error,
                files=files,
                files_data=files_data,
            )
            status = 200 if res.get('ok') else 400

            conf._create_execution_log(
                direction='inbound',
                state='success' if res.get('ok') else 'error',
                input_data=raw_body,
                execution_data=conf.python_code,
                output_data=json.dumps(res, indent=2, ensure_ascii=False),
                error_message=res.get('error') or res.get('reason'),
                http_method=http_method,
                http_status=status,
                content_type=content_type,
                method='code',
                duration=time.time() - _start,
            )

            # Save sample request if pinned
            save_sample_async_if_pinned()

            return request.make_json_response(res, status=status)

        # For other methods, model is required
        if not model:
            return request.make_json_response({'ok': False, 'error': 'invalid_payload', 'reason': 'missing_model'}, status=400)

        _start = time.time()
        if method == 'create':
            res = conf._exec_create(model, values)
        elif method == 'write':
            res = conf._exec_write(model, domain, values)
        elif method == 'unlink':
            res = conf._exec_unlink(model, domain)
        elif method == 'read':
            res = conf._exec_read(model, ids, fields=fields)
        elif method == 'search':
            res = conf._exec_search(model, domain, fields=fields, limit=limit, offset=offset, order=order)
        else:
            res = {'ok': False, 'error': 'invalid_method'}

        status = 200 if res.get('ok') else 400
        if parse_error and res.get('ok'):
            # Anexar aviso de parsing tolerante, sem quebrar sucesso principal
            res['warning'] = parse_error

        conf._create_execution_log(
            direction='inbound',
            state='success' if res.get('ok') else 'error',
            input_data=raw_body,
            execution_data=f"[{method}] {model} | {content_type or '-'}",
            output_data=json.dumps(res, indent=2, ensure_ascii=False),
            error_message=res.get('error') or res.get('reason'),
            http_method=http_method,
            http_status=status,
            content_type=content_type,
            model_name=model,
            method=method,
            duration=time.time() - _start,
        )

        # Save sample request if pinned (for all operations)
        save_sample_async_if_pinned()

        return request.make_json_response(res, status=status)

    @http.route(['/bitconn/webhook/<string:webhook_uuid>/schema'], type='http', auth='public', methods=['GET'], csrf=False)
    def webhook_schema(self, webhook_uuid, **kw):
        # Query params: model, method=create|write
        conf = self._resolve_conf(webhook_uuid)
        if not conf:
            return request.make_json_response({'ok': False, 'error': 'invalid_webhook'}, status=404)
        if not self._validate(conf):
            return request.make_json_response({'ok': False, 'error': 'forbidden', 'reason': 'invalid_token'}, status=401)
        model = request.params.get('model')
        method = (request.params.get('method') or 'create').lower()
        if not model:
            return request.make_json_response({'ok': False, 'error': 'missing_param', 'param': 'model'}, status=400)
        res = conf._get_model_schema(model, method)
        status = 200 if res.get('ok') else 400
        return request.make_json_response(res, status=status)

    @http.route(['/bitconn/webhook/<string:webhook_uuid>/required'], type='http', auth='public', methods=['GET'], csrf=False)
    def webhook_required(self, webhook_uuid, **kw):
    # Query params: model (required), values (optional JSON string), source=model|view|auto (default:model)
        conf = self._resolve_conf(webhook_uuid)
        if not conf:
            return request.make_json_response({'ok': False, 'error': 'invalid_webhook'}, status=404)
        if not self._validate(conf):
            return request.make_json_response({'ok': False, 'error': 'forbidden', 'reason': 'invalid_token'}, status=401)
        model = request.params.get('model')
        if not model:
            return request.make_json_response({'ok': False, 'error': 'missing_param', 'param': 'model'}, status=400)
        source = (request.params.get('source') or 'auto').lower()
        values_raw = request.params.get('values')
        values = None
        if values_raw:
            try:
                values = request.jsonrequest and request.jsonrequest.get('values')  # not applicable on GET
            except Exception:
                values = None
            # fallback: try to parse querystring JSON
            if values is None:
                import json
                try:
                    values = json.loads(values_raw)
                except Exception:
                    values = None
        res = conf._get_required_for_create(model, values=values, source=source)
        if not res.get('ok'):
            return request.make_json_response({'error': res.get('error') or 'invalid'}, status=400)
        # If details=1, return field + label; else just list of fields
        details = (request.params.get('details') in ('1', 'true', 'True'))
        if details:
            return request.make_json_response(res.get('must_provide_detailed', []), status=200)
        return request.make_json_response(res.get('must_provide', []), status=200)
