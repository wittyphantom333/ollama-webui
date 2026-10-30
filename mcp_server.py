"""MCP server — read Vivus telemetry from a remote AI agent.

Speaks MCP over Streamable HTTP at POST /mcp. That is JSON-RPC 2.0, which is
hand-rolled here rather than pulled in via the `mcp` SDK: that SDK is
async/ASGI-first and would fight Flask's synchronous gunicorn workers for what
amounts to a few hundred lines of request handling, and the portal has
deliberately few dependencies.

Two tiers of data, because they carry very different risk:

  metrics  - counts, tokens, cost, durations, model and tool NAMES, error
             strings. Safe to hand to an agent. Available to any valid key,
             scoped to that key's own account.
  content  - the user's query text, model output, file diffs, shell commands,
             prompt text. ADMIN KEYS ONLY, and never returned by a tool that
             a metrics-tier caller can reach.

Writes are deliberately limited to model unlisting (reversible, small blast
radius). Key revocation, user disable and arbitrary settings mutation are NOT
exposed: an agent reached by prompt injection holding an admin key should not
be able to lock people out of the platform.
"""

from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from models import (
    db, ApiKey, OAuthToken, SiteSettings, ToolCall, UsageRecord, User,
    EventRecord, utc_iso,
)

mcp_bp = Blueprint('mcp', __name__)

PROTOCOL_VERSION = '2025-06-18'
SERVER_INFO = {'name': 'vivus-telemetry', 'version': '1.0.0'}

MAX_ROWS = 200
DEFAULT_ROWS = 25
UNLISTED_MODELS_KEY = 'unlisted_models'


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class McpError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def _caller():
    """(user, is_admin). Raises McpError when the credential is unusable."""
    raw_key = request.headers.get('x-api-key') or ''
    user = None
    if raw_key:
        key_obj = ApiKey.lookup(raw_key)
        user = key_obj.user if key_obj else None
    if user is None:
        auth = request.headers.get('Authorization', '')
        if auth.lower().startswith('bearer '):
            tok = OAuthToken.lookup_access(auth[7:].strip())
            if tok:
                user = User.query.get(tok.user_id)
    if user is None:
        raise McpError(-32001, 'Unauthorized: supply a valid x-api-key')
    if not user.is_active_user:
        raise McpError(-32001, 'Account disabled')
    return user, bool(user.is_admin)


def _require_admin(is_admin, what):
    if not is_admin:
        raise McpError(
            -32002,
            f'{what} exposes session content (prompts, diffs, commands) and '
            'requires an admin key. Metrics-only tools are available instead.',
        )


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def _window(args):
    hours = args.get('hours', 24)
    try:
        hours = max(1, min(int(hours), 24 * 90))
    except (TypeError, ValueError):
        hours = 24
    return datetime.now(timezone.utc) - timedelta(hours=hours), hours


def _limit(args):
    try:
        return max(1, min(int(args.get('limit', DEFAULT_ROWS)), MAX_ROWS))
    except (TypeError, ValueError):
        return DEFAULT_ROWS


def _scope(query, model, user, is_admin):
    """Restrict to the caller's own rows unless they are an admin."""
    return query if is_admin else query.filter(model.user_id == user.id)


def _usage_metrics(r):
    """Metrics-tier view of a usage record — no query text, no model output."""
    return {
        'id': r.id,
        'created_at': utc_iso(r.created_at),
        'model': r.model,
        'tier': r.tier,
        'prompt_tokens': r.prompt_tokens or 0,
        'completion_tokens': r.completion_tokens or 0,
        'total_tokens': r.total_tokens or 0,
        'duration_ms': r.duration_ms or 0,
        'stop_reason': r.stop_reason,
        'tools_called': [t for t in (r.tool_names or '').split(',') if t],
        'tool_round': r.tool_round or 0,
        'messages_sent': r.messages_sent or 0,
        'prompt_budget_dropped': r.prompt_budget_dropped or 0,
        'error': r.error,
        'salvaged': bool(r.salvaged),
        'classifier_denied': bool(r.classifier_denied),
        'session_id': r.session_id,
        'user_id': r.user_id,
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def _tool_list_models(args, user, is_admin):
    from app import get_unlisted_models
    unlisted = get_unlisted_models()
    rows = (db.session.query(UsageRecord.model, db.func.count(UsageRecord.id))
            .group_by(UsageRecord.model).all())
    seen = {m: c for m, c in rows}
    models = []
    for name in sorted(set(seen) | set(unlisted)):
        entry = {'model': name, 'requests_all_time': seen.get(name, 0)}
        if is_admin:
            entry['unlisted'] = name in unlisted
        models.append(entry)
    return {'models': models}


def _tool_usage_summary(args, user, is_admin):
    since, hours = _window(args)
    group_by = args.get('group_by', 'model')
    if group_by not in ('model', 'user', 'day', 'session'):
        group_by = 'model'
    q = _scope(UsageRecord.query.filter(UsageRecord.created_at >= since),
               UsageRecord, user, is_admin)
    rows = q.all()

    buckets = {}
    for r in rows:
        if group_by == 'model':
            key = r.model
        elif group_by == 'user':
            key = str(r.user_id)
        elif group_by == 'session':
            key = r.session_id or '(none)'
        else:
            key = utc_iso(r.created_at)[:10] if r.created_at else '(unknown)'
        b = buckets.setdefault(key, {
            'key': key, 'requests': 0, 'prompt_tokens': 0,
            'completion_tokens': 0, 'total_tokens': 0, 'errors': 0,
            'total_duration_ms': 0,
        })
        b['requests'] += 1
        b['prompt_tokens'] += r.prompt_tokens or 0
        b['completion_tokens'] += r.completion_tokens or 0
        b['total_tokens'] += r.total_tokens or 0
        b['total_duration_ms'] += r.duration_ms or 0
        if r.error:
            b['errors'] += 1
    for b in buckets.values():
        b['avg_duration_ms'] = round(b['total_duration_ms'] / b['requests']) if b['requests'] else 0
        del b['total_duration_ms']

    ordered = sorted(buckets.values(), key=lambda b: -b['requests'])
    return {
        'window_hours': hours,
        'group_by': group_by,
        'scope': 'all users' if is_admin else 'own account',
        'total_requests': len(rows),
        'groups': ordered[:MAX_ROWS],
    }


def _tool_recent_requests(args, user, is_admin):
    since, hours = _window(args)
    q = _scope(UsageRecord.query.filter(UsageRecord.created_at >= since),
               UsageRecord, user, is_admin)
    if args.get('model'):
        q = q.filter(UsageRecord.model == args['model'])
    if args.get('session_id'):
        q = q.filter(UsageRecord.session_id == args['session_id'])
    if args.get('errors_only'):
        q = q.filter(UsageRecord.error.isnot(None))
    rows = q.order_by(UsageRecord.created_at.desc()).limit(_limit(args)).all()
    return {'window_hours': hours, 'count': len(rows),
            'requests': [_usage_metrics(r) for r in rows]}


def _tool_top_errors(args, user, is_admin):
    since, hours = _window(args)
    q = _scope(UsageRecord.query.filter(UsageRecord.created_at >= since,
                                        UsageRecord.error.isnot(None)),
               UsageRecord, user, is_admin)
    counts = {}
    for r in q.all():
        entry = counts.setdefault(r.error, {'error': r.error, 'count': 0, 'models': set()})
        entry['count'] += 1
        entry['models'].add(r.model)
    out = [{'error': e['error'], 'count': e['count'], 'models': sorted(e['models'])}
           for e in counts.values()]
    out.sort(key=lambda e: -e['count'])
    return {'window_hours': hours, 'errors': out[:MAX_ROWS]}


def _tool_session_activity(args, user, is_admin):
    since, hours = _window(args)
    q = _scope(UsageRecord.query.filter(UsageRecord.created_at >= since,
                                        UsageRecord.session_id.isnot(None)),
               UsageRecord, user, is_admin)
    sessions = {}
    for r in q.all():
        s = sessions.setdefault(r.session_id, {
            'session_id': r.session_id, 'requests': 0, 'total_tokens': 0,
            'models': set(), 'tools': set(), 'errors': 0,
            'started_at': None, 'last_at': None, 'user_id': r.user_id,
        })
        s['requests'] += 1
        s['total_tokens'] += r.total_tokens or 0
        s['models'].add(r.model)
        for t in (r.tool_names or '').split(','):
            if t:
                s['tools'].add(t)
        if r.error:
            s['errors'] += 1
        ts = utc_iso(r.created_at)
        if ts:
            if s['started_at'] is None or ts < s['started_at']:
                s['started_at'] = ts
            if s['last_at'] is None or ts > s['last_at']:
                s['last_at'] = ts
    out = []
    for s in sessions.values():
        s['models'] = sorted(s['models'])
        s['tools'] = sorted(s['tools'])
        out.append(s)
    out.sort(key=lambda s: s['last_at'] or '', reverse=True)
    return {'window_hours': hours, 'sessions': out[:_limit(args)]}


def _tool_recent_events(args, user, is_admin):
    since, hours = _window(args)
    q = _scope(EventRecord.query.filter(EventRecord.created_at >= since),
               EventRecord, user, is_admin)
    if args.get('event'):
        q = q.filter(EventRecord.event == args['event'])
    counts = {}
    for r in q.all():
        counts[r.event] = counts.get(r.event, 0) + 1
    out = [{'event': k, 'count': v} for k, v in counts.items()]
    out.sort(key=lambda e: -e['count'])
    return {'window_hours': hours, 'events': out[:MAX_ROWS]}


def _tool_request_detail(args, user, is_admin):
    _require_admin(is_admin, 'request_detail')
    try:
        record_id = int(args.get('request_id'))
    except (TypeError, ValueError):
        raise McpError(-32602, 'request_id must be an integer')
    r = db.session.get(UsageRecord, record_id)
    if r is None:
        raise McpError(-32602, f'No usage record {record_id}')
    detail = _usage_metrics(r)
    detail['query_summary'] = r.query_summary
    detail['raw_text'] = r.raw_text
    calls = (ToolCall.query.filter_by(usage_record_id=r.id)
             .order_by(ToolCall.seq.asc()).limit(MAX_ROWS).all())
    detail['tool_calls'] = [{
        'seq': c.seq, 'name': c.name, 'action': c.action, 'target': c.target,
        'command': c.command, 'old_text': c.old_text, 'new_text': c.new_text,
        'content': c.content, 'bytes': c.bytes or 0,
        'result_content': c.result_content,
        'result_is_error': bool(c.result_is_error),
    } for c in calls]
    return detail


def _tool_set_model_unlisted(args, user, is_admin):
    _require_admin(is_admin, 'set_model_unlisted')
    import json as _json
    model = (args.get('model') or '').strip()
    if not model:
        raise McpError(-32602, 'model is required')
    unlisted = args.get('unlisted')
    if not isinstance(unlisted, bool):
        raise McpError(-32602, 'unlisted must be a boolean')
    current = set()
    try:
        parsed = _json.loads(SiteSettings.get(UNLISTED_MODELS_KEY, '[]'))
        if isinstance(parsed, list):
            current = set(parsed)
    except (ValueError, TypeError):
        pass
    if unlisted:
        current.add(model)
    else:
        current.discard(model)
    SiteSettings.set(UNLISTED_MODELS_KEY, _json.dumps(sorted(current)))
    return {
        'model': model,
        'unlisted': unlisted,
        'note': 'Listing only — the model still serves requests that name it '
                'explicitly. Takes effect within ~15s.',
        'unlisted_models': sorted(current),
    }


TOOLS = {
    'list_models': {
        'handler': _tool_list_models,
        'description': 'Models that have served traffic, with all-time request counts. Admin keys also see which are unlisted.',
        'schema': {'type': 'object', 'properties': {}},
    },
    'usage_summary': {
        'handler': _tool_usage_summary,
        'description': 'Aggregated usage over a time window, grouped by model, user, day or session. Metrics only.',
        'schema': {'type': 'object', 'properties': {
            'hours': {'type': 'integer', 'description': 'Lookback window, 1-2160. Default 24.'},
            'group_by': {'type': 'string', 'enum': ['model', 'user', 'day', 'session']},
        }},
    },
    'recent_requests': {
        'handler': _tool_recent_requests,
        'description': 'Recent individual requests with tokens, duration, tool names and errors. No prompt text or model output.',
        'schema': {'type': 'object', 'properties': {
            'hours': {'type': 'integer'},
            'limit': {'type': 'integer', 'description': 'Max rows, 1-200. Default 25.'},
            'model': {'type': 'string'},
            'session_id': {'type': 'string'},
            'errors_only': {'type': 'boolean'},
        }},
    },
    'top_errors': {
        'handler': _tool_top_errors,
        'description': 'Error strings in the window, ranked by frequency, with the models that hit them.',
        'schema': {'type': 'object', 'properties': {'hours': {'type': 'integer'}}},
    },
    'session_activity': {
        'handler': _tool_session_activity,
        'description': 'Requests grouped into conversations by session id, with duration, models and tools used.',
        'schema': {'type': 'object', 'properties': {
            'hours': {'type': 'integer'}, 'limit': {'type': 'integer'},
        }},
    },
    'recent_events': {
        'handler': _tool_recent_events,
        'description': 'Product event names and counts (commands run, skills loaded, errors). Names and counts only.',
        'schema': {'type': 'object', 'properties': {
            'hours': {'type': 'integer'}, 'event': {'type': 'string'},
        }},
    },
    'request_detail': {
        'handler': _tool_request_detail,
        'description': 'ADMIN ONLY. Full detail for one request including query text, model output, tool arguments, file diffs and shell commands.',
        'schema': {'type': 'object', 'properties': {
            'request_id': {'type': 'integer'},
        }, 'required': ['request_id']},
    },
    'set_model_unlisted': {
        'handler': _tool_set_model_unlisted,
        'description': 'ADMIN ONLY. Hide or re-show a model in listings. Does not affect whether it serves requests.',
        'schema': {'type': 'object', 'properties': {
            'model': {'type': 'string'},
            'unlisted': {'type': 'boolean'},
        }, 'required': ['model', 'unlisted']},
    },
}


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

RESOURCES = [
    {'uri': 'vivus://usage/last-24h', 'name': 'Usage, last 24h',
     'description': 'Per-model request counts and tokens for the last 24 hours.',
     'mimeType': 'application/json'},
    {'uri': 'vivus://errors/last-24h', 'name': 'Errors, last 24h',
     'description': 'Error strings ranked by frequency for the last 24 hours.',
     'mimeType': 'application/json'},
    {'uri': 'vivus://models', 'name': 'Models',
     'description': 'Models that have served traffic.',
     'mimeType': 'application/json'},
]

RESOURCE_HANDLERS = {
    'vivus://usage/last-24h': lambda u, a: _tool_usage_summary({'hours': 24}, u, a),
    'vivus://errors/last-24h': lambda u, a: _tool_top_errors({'hours': 24}, u, a),
    'vivus://models': lambda u, a: _tool_list_models({}, u, a),
}


# ---------------------------------------------------------------------------
# JSON-RPC plumbing
# ---------------------------------------------------------------------------

def _result(req_id, payload):
    return {'jsonrpc': '2.0', 'id': req_id, 'result': payload}


def _error(req_id, code, message):
    return {'jsonrpc': '2.0', 'id': req_id, 'error': {'code': code, 'message': message}}


def _handle(message):
    method = message.get('method')
    req_id = message.get('id')
    params = message.get('params') or {}

    # Notifications carry no id and must not be answered.
    if req_id is None and method and method.startswith('notifications/'):
        return None

    if method == 'initialize':
        return _result(req_id, {
            'protocolVersion': PROTOCOL_VERSION,
            'capabilities': {'tools': {}, 'resources': {}},
            'serverInfo': SERVER_INFO,
        })
    if method == 'ping':
        return _result(req_id, {})

    user, is_admin = _caller()

    if method == 'tools/list':
        return _result(req_id, {'tools': [{
            'name': name,
            'description': spec['description'],
            'inputSchema': spec['schema'],
        } for name, spec in TOOLS.items()]})

    if method == 'tools/call':
        name = params.get('name')
        spec = TOOLS.get(name)
        if spec is None:
            raise McpError(-32602, f'Unknown tool: {name}')
        payload = spec['handler'](params.get('arguments') or {}, user, is_admin)
        import json as _json
        return _result(req_id, {
            'content': [{'type': 'text', 'text': _json.dumps(payload, indent=2, default=str)}],
            'isError': False,
        })

    if method == 'resources/list':
        return _result(req_id, {'resources': RESOURCES})

    if method == 'resources/read':
        uri = params.get('uri')
        handler = RESOURCE_HANDLERS.get(uri)
        if handler is None:
            raise McpError(-32602, f'Unknown resource: {uri}')
        import json as _json
        return _result(req_id, {'contents': [{
            'uri': uri, 'mimeType': 'application/json',
            'text': _json.dumps(handler(user, is_admin), indent=2, default=str),
        }]})

    raise McpError(-32601, f'Method not found: {method}')


@mcp_bp.route('/mcp', methods=['POST'])
def mcp_endpoint():
    body = request.get_json(silent=True)
    if body is None:
        return jsonify(_error(None, -32700, 'Parse error')), 400

    batch = isinstance(body, list)
    messages = body if batch else [body]
    responses = []
    for message in messages:
        req_id = message.get('id') if isinstance(message, dict) else None
        try:
            if not isinstance(message, dict):
                raise McpError(-32600, 'Invalid request')
            resp = _handle(message)
            if resp is not None:
                responses.append(resp)
        except McpError as e:
            responses.append(_error(req_id, e.code, e.message))
        except Exception:
            # Never leak a stack trace or SQL to a remote agent.
            from flask import current_app
            current_app.logger.exception('MCP tool failed')
            responses.append(_error(req_id, -32603, 'Internal error'))

    if not responses:
        return '', 202
    return jsonify(responses if batch else responses[0])


@mcp_bp.route('/mcp', methods=['GET'])
def mcp_sse_unsupported():
    # No server-initiated streams: every tool here is request/response.
    return jsonify({'error': 'SSE stream not supported; POST JSON-RPC to this endpoint'}), 405
