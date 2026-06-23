"""API blueprint — key management, validation, and metrics ingestion.

Routes used by the Vivus translation proxy:
  POST /api/v1/keys/validate   — check an API key, return user info
  POST /api/v1/metrics         — ingest usage telemetry from the proxy

Routes used by the portal UI:
  GET/POST /keys               — list / create API keys
  POST /keys/<id>/revoke       — revoke a key
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from models import (
    db, ApiKey, UsageRecord, SiteSettings, CloudProvider, ToolCall,
    OAuthAuthCode, OAuthToken, OAUTH_ALLOWED_CLIENT_IDS, OAUTH_GRANTED_SCOPE, Feedback,
    EventRecord, TraceSpan, TraceLog, Group,
)

api_bp = Blueprint('api', __name__, template_folder='templates')


# Per-user "cloud subagents" feature. When enabled for a user, the CLI routes
# all subagents to the chosen off-box cloud model (so fan-out parallelizes
# without contending for the single local GPU). The first entry is the default
# offered in the admin UI. Keep in sync with the proxy's cloud model table.
CLOUD_SUBAGENT_FLAG = 'vivus_cloud_subagent_model'
CLOUD_SUBAGENT_MODELS = [
    'minimax-m3:cloud',
    'qwen3-coder-next:cloud',
    'glm-5.2:cloud',
    'deepseek-v4-pro:cloud',
    'kimi-k2.7-code:cloud',
]

# Per-agent-type model configuration. The CLI reads this map (key in the
# delivered feature flags) and resolves each agent's model from it, overriding
# the baked task-aligned defaults. Keys are the CLI's agent-type identifiers.
AGENT_MODELS_FLAG = 'vivus_agent_models'

# Known agent types shown in the group editor, with the CLI's baked default
# (for reference) and a human label. Built-ins + the proxy agents.json agents.
KNOWN_AGENT_TYPES = [
    ('general-purpose', 'General purpose (default fan-out agent)', 'minimax-m3:cloud'),
    ('Explore', 'Explore — fast read-only codebase search', 'deepseek-v4-flash:cloud'),
    ('Plan', 'Plan — planning / reasoning', 'deepseek-v4-pro:cloud'),
    ('verification', 'Verification — careful checking', 'deepseek-v4-pro:cloud'),
    ('vivus-guide', 'Vivus guide — docs Q&A', 'deepseek-v4-flash:cloud'),
    ('statusline-setup', 'Statusline setup — config script', 'qwen3-coder-next:cloud'),
    ('coder', 'Coder — code editing', 'qwen3-coder-next:cloud'),
    ('explorer', 'Explorer — filesystem search', 'deepseek-v4-flash:cloud'),
    ('reviewer', 'Reviewer — code review', 'kimi-k2.7-code:cloud'),
    ('writer', 'Writer — file creation', 'qwen3-coder-next:cloud'),
]


def _available_model_names():
    """Best-effort list of model names the proxy/Ollama can serve, for the
    group-editor dropdowns. Falls back to the curated cloud list on error."""
    import requests as _requests
    names = []
    try:
        import app as _app  # OLLAMA_API_URL + ollama_headers live in app.py
        resp = _requests.get(f'{_app.OLLAMA_API_URL}/tags',
                             headers=_app.ollama_headers(), timeout=3)
        if resp.ok:
            data = resp.json() or {}
            names = sorted({m.get('name') for m in data.get('models', []) if m.get('name')})
    except Exception:
        names = []
    if not names:
        names = list(CLOUD_SUBAGENT_MODELS)
    return names


def _merged_feature_flags(user):
    """Compose the feature flags delivered to the CLI for a user.

    Precedence (later wins): group.feature_flags → group.agent_models (as
    AGENT_MODELS_FLAG) → user.feature_flags (per-user overrides, incl. a
    per-user AGENT_MODELS_FLAG that merges on top of the group's per-agent map).
    """
    flags = {}
    group = getattr(user, 'group', None) if user else None
    if group:
        if group.feature_flags:
            flags.update(group.feature_flags)
        if group.agent_models:
            flags[AGENT_MODELS_FLAG] = dict(group.agent_models)

    user_flags = dict((user.feature_flags or {})) if user else {}
    # Merge a per-user agent map ON TOP of the group's (per-agent granularity).
    user_agent_models = user_flags.pop(AGENT_MODELS_FLAG, None)
    if isinstance(user_agent_models, dict):
        merged = dict(flags.get(AGENT_MODELS_FLAG, {}))
        merged.update(user_agent_models)
        flags[AGENT_MODELS_FLAG] = merged
    # Remaining user-level flags override group-level keys.
    flags.update(user_flags)
    # Drop an empty agent map so the CLI cleanly falls back to baked defaults.
    if AGENT_MODELS_FLAG in flags and not flags[AGENT_MODELS_FLAG]:
        flags.pop(AGENT_MODELS_FLAG, None)
    return flags


def _user_from_request():
    """Resolve the calling user from an x-api-key header or OAuth bearer token.

    Mirrors the dual-auth resolution used by the feedback endpoints — the proxy
    forwards whichever credential the CLI used. Returns a User or None.
    """
    raw_key = request.headers.get('x-api-key') or ''
    api_key_obj = ApiKey.lookup(raw_key) if raw_key else None
    if api_key_obj:
        return api_key_obj.user
    auth_header = request.headers.get('Authorization', '')
    if auth_header.lower().startswith('bearer '):
        token_obj = OAuthToken.lookup_access(auth_header[7:].strip())
        if token_obj:
            from models import User
            return User.query.get(token_obj.user_id)
    return None


# ---------------------------------------------------------------------------
# Portal UI — API key management
# ---------------------------------------------------------------------------

@api_bp.route('/keys', methods=['GET', 'POST'])
@login_required
def keys():
    if request.method == 'POST':
        name = request.form.get('key_name', '').strip() or 'default'
        raw_key, key_hash, key_prefix = ApiKey.generate_key()
        api_key = ApiKey(
            user_id=current_user.id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
        )
        db.session.add(api_key)
        db.session.commit()
        # Show the raw key exactly once
        flash(f'API key created. Copy it now — it will not be shown again: {raw_key}', 'success')
        return redirect(url_for('api.keys'))

    user_keys = current_user.api_keys.order_by(ApiKey.created_at.desc()).all()
    return render_template('keys.html', keys=user_keys)


@api_bp.route('/keys/<int:key_id>/revoke', methods=['POST'])
@login_required
def revoke_key(key_id):
    api_key = ApiKey.query.get_or_404(key_id)
    if api_key.user_id != current_user.id and not current_user.is_admin:
        flash('Not authorized.', 'danger')
        return redirect(url_for('api.keys'))
    api_key.is_active = False
    db.session.commit()
    flash(f'Key "{api_key.name}" revoked.', 'info')
    return redirect(url_for('api.keys'))


# ---------------------------------------------------------------------------
# Proxy-facing API — key validation
# ---------------------------------------------------------------------------

@api_bp.route('/api/v1/keys/validate', methods=['POST'])
def validate_key():
    """Called by server.mjs on every request to authenticate the API key.

    Expects JSON: {"key": "sk-vivus-..."}
    Returns 200 with user info or 401.
    """
    data = request.get_json(silent=True) or {}
    raw_key = data.get('key', '')

    if not raw_key:
        return jsonify({'valid': False, 'error': 'Missing key'}), 401

    api_key = ApiKey.lookup(raw_key)
    if not api_key:
        return jsonify({'valid': False, 'error': 'Invalid or revoked key'}), 401

    user = api_key.user
    if not user.is_active:
        return jsonify({'valid': False, 'error': 'User disabled'}), 401

    # Update last-used timestamp
    api_key.last_used_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        'valid': True,
        'user_id': user.id,
        'username': user.username,
        'is_admin': user.is_admin,
        'key_id': api_key.id,
    })


# ---------------------------------------------------------------------------
# Proxy-facing API — metrics / telemetry ingestion
# ---------------------------------------------------------------------------

@api_bp.route('/api/v1/metrics', methods=['POST'])
def ingest_metrics():
    """Called by server.mjs after each completed request to record usage.

    Expects JSON:
    {
      "key": "sk-vivus-...",
      "model": "qwen3.5:35b",
      "tier": "default",
      "prompt_tokens": 1234,
      "completion_tokens": 567,
      "total_tokens": 1801,
      "duration_ms": 4500,
      "endpoint": "/v1/messages"
    }
    """
    data = request.get_json(silent=True) or {}
    raw_key = data.get('key', '')

    api_key = ApiKey.lookup(raw_key) if raw_key else None
    if not api_key:
        # Accept metrics even if key is unknown — don't block on this
        return jsonify({'ok': True, 'warning': 'unknown key'}), 200

    # Normalize list fields to comma-separated strings
    tool_names_raw = data.get('tool_names')
    tool_names = ','.join(tool_names_raw) if isinstance(tool_names_raw, list) else (tool_names_raw or None)
    tools_avail_raw = data.get('tools_available')
    tools_available = ','.join(tools_avail_raw) if isinstance(tools_avail_raw, list) else (tools_avail_raw or None)
    salvaged_tools_raw = data.get('salvaged_tools')
    salvaged_tools = ','.join(salvaged_tools_raw) if isinstance(salvaged_tools_raw, list) else (salvaged_tools_raw or None)
    raw_text = data.get('raw_text')
    if isinstance(raw_text, str) and len(raw_text) > 20000:
        raw_text = raw_text[:20000] + '\n…(truncated)'

    record = UsageRecord(
        user_id=api_key.user_id,
        api_key_id=api_key.id,
        model=data.get('model', 'unknown'),
        tier=data.get('tier', 'default'),
        prompt_tokens=data.get('prompt_tokens', 0),
        completion_tokens=data.get('completion_tokens', 0),
        total_tokens=data.get('total_tokens', 0),
        duration_ms=data.get('duration_ms', 0),
        endpoint=data.get('endpoint', ''),
        stop_reason=data.get('stop_reason'),
        tool_names=tool_names,
        tools_available=tools_available,
        tool_round=data.get('tool_round', 0),
        query_summary=(data.get('query_summary') or '')[:500] or None,
        error=data.get('error'),
        messages_sent=data.get('messages_sent', 0),
        prompt_budget_dropped=data.get('prompt_budget_dropped', 0),
        salvaged=bool(data.get('salvaged')),
        salvaged_tools=salvaged_tools,
        raw_text=(raw_text or None),
    )
    db.session.add(record)
    db.session.flush()  # assign record.id before linking tool calls

    # Optional captured tool details (proxy sends these only with
    # CAPTURE_TOOL_DETAILS=1). Already redacted + size-capped upstream; we
    # additionally hard-cap each field here as defense in depth.
    tool_calls = data.get('tool_calls')
    if isinstance(tool_calls, list):
        FIELD_CAP = 16000

        def _cap(v):
            if v is None:
                return None
            s = v if isinstance(v, str) else str(v)
            return s[:FIELD_CAP] if len(s) > FIELD_CAP else s

        for i, tc in enumerate(tool_calls[:50]):
            if not isinstance(tc, dict) or not tc.get('name'):
                continue
            db.session.add(ToolCall(
                usage_record_id=record.id,
                seq=i,
                name=str(tc.get('name'))[:80],
                action=(str(tc.get('action'))[:20] if tc.get('action') else None),
                target=_cap(tc.get('target')),
                command=_cap(tc.get('command')),
                old_text=_cap(tc.get('old_text')),
                new_text=_cap(tc.get('new_text')),
                content=_cap(tc.get('content')),
                bytes=int(tc.get('bytes') or 0),
            ))

    db.session.commit()

    return jsonify({'ok': True}), 200


# ---------------------------------------------------------------------------
# Proxy-facing API — feedback ingestion
# ---------------------------------------------------------------------------

def _bounded_payload_json(inner, limit=600000):
    """Serialize a payload to VALID JSON within `limit` chars.

    Bounds size by trimming the transcript array (dropping the OLDEST messages)
    and/or truncating long string values — NEVER by slicing the JSON string,
    which corrupts it and makes the stored payload unparseable. Always returns
    valid JSON so the admin viewer can render it.
    """
    import json as _json
    try:
        s = _json.dumps(inner, ensure_ascii=False)
    except Exception:
        return _json.dumps({'_error': 'unserializable payload'})
    if len(s) <= limit:
        return s
    # 1) Trim an oversized transcript array (keep the NEWEST messages).
    if isinstance(inner, dict) and isinstance(inner.get('transcript'), list):
        base = {k: v for k, v in inner.items() if k != 'transcript'}
        total = len(inner['transcript'])
        keep = list(inner['transcript'])
        while keep:
            candidate = {**base, 'transcript': keep,
                         '_truncated': f'showing last {len(keep)} of {total} messages'}
            cs = _json.dumps(candidate, ensure_ascii=False)
            if len(cs) <= limit:
                return cs
            keep = keep[max(1, len(keep) // 4):]  # drop oldest ~25%, converge fast
        inner = base  # transcript can't fit at all — fall through to value capping

    # 2) Recursively cap long string values anywhere in the structure. This
    #    handles payloads with NO transcript array (e.g. bloated by embedded
    #    tool schemas / system context) that the step above can't shrink.
    def _shrink(obj, budget):
        if isinstance(obj, str):
            return obj if len(obj) <= budget else obj[:budget] + '…(truncated)'
        if isinstance(obj, list):
            return [_shrink(x, budget) for x in obj]
        if isinstance(obj, dict):
            return {k: _shrink(v, budget) for k, v in obj.items()}
        return obj
    for cap in (8000, 2000, 500, 100):
        shrunk = _shrink(inner, cap)
        if isinstance(shrunk, dict):
            shrunk = {**shrunk, '_truncated': f'string values capped at {cap} chars'}
        cs = _json.dumps(shrunk, ensure_ascii=False)
        if len(cs) <= limit:
            return cs

    # 3) Last resort: a VALID JSON object carrying a bounded raw excerpt as a
    #    string value (json.dumps escapes it, so the result stays parseable).
    return _json.dumps({
        '_truncated': 'payload too large to store structured; raw excerpt only',
        '_raw_excerpt': s[:limit - 200],
    }, ensure_ascii=False)


@api_bp.route('/api/v1/feedback', methods=['POST'])
def ingest_feedback():
    """Called by the proxy when a user submits /feedback or /bug in the CLI.

    The CLI sends { "content": "<json-string>" } where the inner JSON has
    shape { description, platform, version, gitRepo, message_count, datetime,
    transcript, ... }. The user's actual feedback text is `description`.
    Returns { feedback_id } — the CLI treats a missing feedback_id as failure.
    """
    import json as _json
    data = request.get_json(silent=True) or {}

    # Unwrap the CLI envelope: the real payload is a JSON string in `content`.
    inner = {}
    content = data.get('content')
    if isinstance(content, str) and content:
        try:
            inner = _json.loads(content)
        except (ValueError, TypeError):
            inner = {}
    elif isinstance(content, dict):
        inner = content
    # Some callers may post the payload directly (no envelope).
    if not inner:
        inner = data

    # The user's feedback text lives in `description`.
    comment = (inner.get('description') or inner.get('comment') or inner.get('feedback') or '')[:4000]
    category = (inner.get('category') or inner.get('type') or 'feedback')[:20]

    # Resolve the submitting user from the forwarded API key.
    raw_key = (
        request.headers.get('x-api-key')
        or inner.get('api_key')
        or data.get('api_key')
        or ''
    )
    api_key_obj = ApiKey.lookup(raw_key) if raw_key else None
    user_id = api_key_obj.user_id if api_key_obj else None
    key_prefix = api_key_obj.key_prefix if api_key_obj else None

    # Fall back to the OAuth bearer token for OAuth-authenticated users.
    if user_id is None:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.lower().startswith('bearer '):
            token_obj = OAuthToken.lookup_access(auth_header[7:].strip())
            if token_obj:
                user_id = token_obj.user_id

    # Store the full inner payload (transcript, env, version) for admin review.
    payload_str = _bounded_payload_json(inner)

    record = Feedback(
        user_id=user_id,
        category=category,
        comment=comment,
        payload=payload_str,
        key_prefix=key_prefix,
    )
    db.session.add(record)
    db.session.commit()

    return jsonify({'feedback_id': f'fb_{record.id}', 'ok': True}), 200


# ---------------------------------------------------------------------------
# Proxy-facing API — CLI product / behavioral event ingestion
# ---------------------------------------------------------------------------

@api_bp.route('/api/v1/events', methods=['POST'])
def ingest_events():
    """Ingest a batch of CLI product events forwarded by the proxy.

    The CLI's portal event sink (VIVUS_CODE_ENABLE_EVENT_LOGGING=1) batches
    tengu_* events and POSTs them to the proxy, which forwards here. Body:
      { client, run_id, user_id (CLI device id), events: [ {event, timestamp, metadata} ] }
    Auth (x-api-key or OAuth bearer, forwarded by the proxy) resolves the
    portal user when available. Always returns 200 so the CLI never blocks.
    """
    import json as _json
    data = request.get_json(silent=True) or {}
    events = data.get('events')
    if not isinstance(events, list) or not events:
        return jsonify({'ok': True, 'stored': 0}), 200

    user = _user_from_request()
    user_id = user.id if user else None
    raw_key = request.headers.get('x-api-key') or ''
    api_key_obj = ApiKey.lookup(raw_key) if raw_key else None
    key_prefix = api_key_obj.key_prefix if api_key_obj else None

    run_id = data.get('run_id') or None
    device_id = data.get('user_id') or None
    client = (data.get('client') or 'vivus-cli')[:40]

    stored = 0
    for ev in events[:500]:
        if not isinstance(ev, dict):
            continue
        name = ev.get('event')
        if not name:
            continue

        ts = ev.get('timestamp')
        client_ts = None
        if isinstance(ts, (int, float)):
            try:
                client_ts = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                client_ts = None

        meta = ev.get('metadata')
        try:
            meta_str = _json.dumps(meta, ensure_ascii=False)[:8000] if meta is not None else None
        except (TypeError, ValueError):
            meta_str = None

        db.session.add(EventRecord(
            user_id=user_id,
            event=str(name)[:120],
            run_id=(str(run_id)[:64] if run_id else None),
            device_id=(str(device_id)[:64] if device_id else None),
            client=client,
            metadata_json=meta_str,
            client_ts=client_ts,
            key_prefix=key_prefix,
        ))
        stored += 1

    db.session.commit()
    return jsonify({'ok': True, 'stored': stored}), 200


# ---------------------------------------------------------------------------
# Proxy-facing API — OpenTelemetry (OTLP/JSON) ingestion
# ---------------------------------------------------------------------------

_OTLP_ATTR_CAP = 16000  # per-attribute-value char cap (defense in depth)


def _safe_int(v):
    """Parse an OTLP numeric field (often a string-encoded int64) to int|None."""
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _otlp_value(v):
    """Decode a single OTLP AnyValue object into a Python scalar/list/dict."""
    if not isinstance(v, dict):
        return v
    if 'stringValue' in v:
        return v['stringValue']
    if 'intValue' in v:
        try:
            return int(v['intValue'])
        except (ValueError, TypeError):
            return v['intValue']
    if 'doubleValue' in v:
        return v['doubleValue']
    if 'boolValue' in v:
        return bool(v['boolValue'])
    if 'arrayValue' in v:
        vals = (v['arrayValue'] or {}).get('values', []) or []
        return [_otlp_value(x) for x in vals]
    if 'kvlistValue' in v:
        return _otlp_attrs_to_dict((v['kvlistValue'] or {}).get('values', []))
    return None


def _otlp_attrs_to_dict(attr_list):
    """Convert an OTLP attribute list [{key, value}] into a flat dict."""
    out = {}
    if not isinstance(attr_list, list):
        return out
    for kv in attr_list:
        if not isinstance(kv, dict):
            continue
        k = kv.get('key')
        if not k:
            continue
        val = _otlp_value(kv.get('value'))
        if isinstance(val, str) and len(val) > _OTLP_ATTR_CAP:
            val = val[:_OTLP_ATTR_CAP] + f'…(+{len(val) - _OTLP_ATTR_CAP} chars)'
        out[k] = val
    return out


def _otlp_session_id(attrs):
    """Best-effort session/run id from common attribute keys."""
    for k in ('session.id', 'session_id', 'sessionId', 'run_id', 'conversation.id'):
        v = attrs.get(k)
        if v:
            return str(v)[:64]
    return None


@api_bp.route('/api/v1/otlp/traces', methods=['POST'])
def ingest_otlp_traces():
    """Ingest an OTLP/JSON trace export forwarded by the proxy (/v1/traces)."""
    import json as _json
    data = request.get_json(silent=True) or {}
    user = _user_from_request()
    user_id = user.id if user else None
    raw_key = request.headers.get('x-api-key') or ''
    api_key_obj = ApiKey.lookup(raw_key) if raw_key else None
    key_prefix = api_key_obj.key_prefix if api_key_obj else None

    stored = 0
    for rs in (data.get('resourceSpans') or [])[:200]:
        res_attrs = _otlp_attrs_to_dict((rs.get('resource') or {}).get('attributes', []))
        for ss in (rs.get('scopeSpans') or [])[:200]:
            for sp in (ss.get('spans') or [])[:1000]:
                attrs = _otlp_attrs_to_dict(sp.get('attributes', []))
                merged_for_session = {**res_attrs, **attrs}
                start_ns = _safe_int(sp.get('startTimeUnixNano'))
                end_ns = _safe_int(sp.get('endTimeUnixNano'))
                dur_ms = None
                if start_ns and end_ns and end_ns >= start_ns:
                    dur_ms = int((end_ns - start_ns) / 1_000_000)
                status = sp.get('status') or {}
                try:
                    attrs_str = _json.dumps(attrs, ensure_ascii=False)[:120000]
                except (TypeError, ValueError):
                    attrs_str = None
                db.session.add(TraceSpan(
                    trace_id=str(sp.get('traceId') or '')[:40],
                    span_id=str(sp.get('spanId') or '')[:24],
                    parent_span_id=(str(sp.get('parentSpanId'))[:24] if sp.get('parentSpanId') else None),
                    name=str(sp.get('name') or '')[:120],
                    span_type=(str(attrs.get('span.type'))[:40] if attrs.get('span.type') else None),
                    start_ns=start_ns,
                    end_ns=end_ns,
                    duration_ms=dur_ms,
                    status_code=_safe_int(status.get('code')),
                    user_id=user_id,
                    session_id=_otlp_session_id(merged_for_session),
                    attributes_json=attrs_str,
                    key_prefix=key_prefix,
                ))
                stored += 1

    db.session.commit()
    return jsonify({'ok': True, 'stored': stored}), 200


@api_bp.route('/api/v1/otlp/logs', methods=['POST'])
def ingest_otlp_logs():
    """Ingest an OTLP/JSON log export forwarded by the proxy (/v1/logs)."""
    import json as _json
    data = request.get_json(silent=True) or {}
    user = _user_from_request()
    user_id = user.id if user else None
    raw_key = request.headers.get('x-api-key') or ''
    api_key_obj = ApiKey.lookup(raw_key) if raw_key else None
    key_prefix = api_key_obj.key_prefix if api_key_obj else None

    stored = 0
    for rl in (data.get('resourceLogs') or [])[:200]:
        res_attrs = _otlp_attrs_to_dict((rl.get('resource') or {}).get('attributes', []))
        for sl in (rl.get('scopeLogs') or [])[:200]:
            for lr in (sl.get('logRecords') or [])[:1000]:
                attrs = _otlp_attrs_to_dict(lr.get('attributes', []))
                body = _otlp_value(lr.get('body'))
                if not isinstance(body, str):
                    try:
                        body = _json.dumps(body, ensure_ascii=False)
                    except (TypeError, ValueError):
                        body = str(body)
                if body and len(body) > 120000:
                    body = body[:120000]
                try:
                    attrs_str = _json.dumps(attrs, ensure_ascii=False)[:120000]
                except (TypeError, ValueError):
                    attrs_str = None
                db.session.add(TraceLog(
                    trace_id=(str(lr.get('traceId'))[:40] if lr.get('traceId') else None),
                    span_id=(str(lr.get('spanId'))[:24] if lr.get('spanId') else None),
                    severity=(str(lr.get('severityText'))[:20] if lr.get('severityText') else None),
                    body=body,
                    attributes_json=attrs_str,
                    time_ns=_safe_int(lr.get('timeUnixNano')),
                    user_id=user_id,
                    session_id=_otlp_session_id({**res_attrs, **attrs}),
                    key_prefix=key_prefix,
                ))
                stored += 1

    db.session.commit()
    return jsonify({'ok': True, 'stored': stored}), 200


@api_bp.route('/api/v1/otlp/metrics', methods=['POST'])
def ingest_otlp_metrics():
    """Accept (and currently drop) OTLP metric exports so the exporter gets a
    clean 200. Usage metrics are already captured via /api/v1/metrics."""
    return jsonify({'ok': True}), 200


@api_bp.route('/api/v1/transcript_share', methods=['POST'])
def ingest_transcript_share():
    """Called by the proxy when a user shares their session transcript from the
    feedback survey ("vote 1-4" → "share transcript?").

    The CLI sends { content: "<json-string>", appearance_id }. The inner JSON
    has { trigger, version, platform, transcript, ... }. Stored as a feedback
    row with category 'transcript_share'. Returns { transcript_id }.
    """
    import json as _json
    data = request.get_json(silent=True) or {}

    inner = {}
    content = data.get('content')
    if isinstance(content, str) and content:
        try:
            inner = _json.loads(content)
        except (ValueError, TypeError):
            inner = {}
    elif isinstance(content, dict):
        inner = content

    trigger = (inner.get('trigger') or 'transcript_share')[:40]

    raw_key = request.headers.get('x-api-key') or ''
    api_key_obj = ApiKey.lookup(raw_key) if raw_key else None
    user_id = api_key_obj.user_id if api_key_obj else None
    key_prefix = api_key_obj.key_prefix if api_key_obj else None
    if user_id is None:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.lower().startswith('bearer '):
            token_obj = OAuthToken.lookup_access(auth_header[7:].strip())
            if token_obj:
                user_id = token_obj.user_id

    payload_str = _bounded_payload_json(inner)

    record = Feedback(
        user_id=user_id,
        category='transcript_share',
        comment=f'Transcript share ({trigger})',
        payload=payload_str,
        key_prefix=key_prefix,
    )
    db.session.add(record)
    db.session.commit()

    return jsonify({'transcript_id': f'ts_{record.id}', 'ok': True}), 200


# ---------------------------------------------------------------------------
# Proxy-facing API — per-user feature flags
# ---------------------------------------------------------------------------

@api_bp.route('/api/vivus_cli_feature_flags', methods=['GET'])
def vivus_cli_feature_flags():
    """Called by the proxy's /api/vivus_cli/bootstrap to fetch this user's
    per-user feature flags (e.g. cloud subagents).

    Auth via x-api-key or OAuth bearer — the proxy forwards whichever the CLI
    used. The CLI mirrors the returned flags into its GrowthBook config
    overrides. Unknown caller → empty flags so users fall back to safe local
    defaults (never auto-enabling cloud usage).
    """
    user = _user_from_request()
    flags = _merged_feature_flags(user) if user else {}
    return jsonify({'feature_flags': flags})


# ---------------------------------------------------------------------------
# Portal UI — admin feedback viewer
# ---------------------------------------------------------------------------

def _short_json(obj, limit=300):
    """Compact single-line JSON preview of a tool input/result."""
    import json as _json
    try:
        s = _json.dumps(obj, ensure_ascii=False)
    except Exception:
        s = str(obj)
    s = ' '.join(s.split())
    return s[:limit] + ('…' if len(s) > limit else '')


def _flatten_tool_result(content, limit=600):
    """Tool results may be a string or a list of {type:text,text} blocks."""
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                parts.append(b.get('text') or b.get('content') or '')
            elif isinstance(b, str):
                parts.append(b)
        text = '\n'.join(p for p in parts if p)
    else:
        text = '' if content is None else str(content)
    text = text.strip()
    return text[:limit] + ('…' if len(text) > limit else '')


def _summarize_message(m):
    """Normalize one transcript message into {role, parts:[(kind, text)]}.

    Handles both flat ({role, content}) and nested ({type, message:{role,content}})
    shapes, and content as a string or a list of typed blocks.
    """
    if not isinstance(m, dict):
        return None
    role = m.get('role')
    content = m.get('content')
    inner = m.get('message')
    if role is None and isinstance(inner, dict):
        role = inner.get('role')
        content = inner.get('content')
    if role is None:
        role = m.get('type')  # 'user' / 'assistant'

    parts = []
    if isinstance(content, str):
        if content.strip():
            parts.append(('text', content.strip()))
    elif isinstance(content, list):
        for b in content:
            if isinstance(b, str):
                if b.strip():
                    parts.append(('text', b.strip()))
                continue
            if not isinstance(b, dict):
                continue
            bt = b.get('type')
            if bt == 'text':
                t = (b.get('text') or '').strip()
                if t:
                    parts.append(('text', t))
            elif bt == 'thinking':
                t = (b.get('thinking') or '').strip()
                if t:
                    parts.append(('thinking', t))
            elif bt == 'tool_use':
                name = b.get('name', 'tool')
                parts.append(('tool_use', f"{name}({_short_json(b.get('input', {}))})"))
            elif bt == 'tool_result':
                parts.append(('tool_result', _flatten_tool_result(b.get('content'))))
            elif bt == 'image':
                parts.append(('text', '[image]'))
    if not parts:
        return None
    return {'role': role or 'unknown', 'parts': parts}


def _parse_feedback_payload(payload_str):
    """Parse a stored feedback payload into displayable meta + conversation."""
    import json as _json
    out = {'meta': {}, 'messages': [], 'raw': payload_str or ''}
    if not payload_str:
        return out
    try:
        data = _json.loads(payload_str)
    except Exception:
        # Best-effort salvage of top-level scalar meta from a truncated/invalid
        # payload (e.g. legacy rows stored before bounded serialization).
        import re as _re
        for k in ('description', 'platform', 'version', 'datetime', 'message_count', 'terminal'):
            mm = _re.search(r'"' + k + r'"\s*:\s*"?([^",}]*)', payload_str)
            if mm and mm.group(1):
                out['meta'][k] = mm.group(1).strip()
        out['meta']['_truncated'] = 'payload was truncated/corrupted — showing recovered fields only'
        return out
    if not isinstance(data, dict):
        return out
    for k in ('trigger', 'description', 'platform', 'version', 'gitRepo',
              'message_count', 'datetime', '_truncated'):
        if k in data and data[k] not in (None, ''):
            out['meta'][k] = data[k]
    try:
        out['raw'] = _json.dumps(data, indent=2, ensure_ascii=False)
    except Exception:
        pass
    transcript = data.get('transcript')
    if isinstance(transcript, list):
        msgs = [_summarize_message(m) for m in transcript]
        out['messages'] = [m for m in msgs if m]
    return out


@api_bp.route('/admin/feedback')
@login_required
def admin_feedback():
    if not current_user.is_admin:
        flash('Admin only.', 'danger')
        return redirect(url_for('api.usage'))
    from models import User
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', '')
    q = Feedback.query.order_by(Feedback.created_at.desc())
    if category:
        q = q.filter(Feedback.category == category)
    pagination = q.paginate(page=page, per_page=25, error_out=False)
    users = {u.id: u.username for u in User.query.all()}
    parsed = {fb.id: _parse_feedback_payload(fb.payload) for fb in pagination.items}
    return render_template(
        'admin_feedback.html',
        feedbacks=pagination.items,
        pagination=pagination,
        users=users,
        parsed=parsed,
        category_filter=category,
    )


# ---------------------------------------------------------------------------
# Portal UI — CLI product events (telemetry) viewer
# ---------------------------------------------------------------------------

# Human-friendly labels for the feedback-survey rating values.
_RATING_LABELS = {'good': 'Good', 'fine': 'Fine', 'bad': 'Bad', 'dismissed': 'Dismissed'}


@api_bp.route('/admin/events')
@login_required
def admin_events():
    """Browse CLI product events forwarded by the proxy (tengu_* telemetry),
    with a feedback-survey rating summary. Admin sees all; regular users see
    only their own events."""
    import json as _json
    from sqlalchemy import func
    from models import User

    is_admin = current_user.is_admin
    page = request.args.get('page', 1, type=int)
    event_filter = request.args.get('event', '')

    base_q = EventRecord.query
    if not is_admin:
        base_q = base_q.filter(EventRecord.user_id == current_user.id)

    q = base_q.order_by(EventRecord.id.desc())
    if event_filter:
        q = q.filter(EventRecord.event == event_filter)
    pagination = q.paginate(page=page, per_page=50, error_out=False)

    users = {u.id: u.username for u in User.query.all()}

    # Event-name breakdown (respecting the per-user scope) for the overview +
    # filter chips.
    counts_q = db.session.query(EventRecord.event, func.count(EventRecord.id))
    if not is_admin:
        counts_q = counts_q.filter(EventRecord.user_id == current_user.id)
    counts = counts_q.group_by(EventRecord.event).order_by(func.count(EventRecord.id).desc()).all()
    total_events = sum(c for _, c in counts)

    runs_q = db.session.query(func.count(func.distinct(EventRecord.run_id)))
    if not is_admin:
        runs_q = runs_q.filter(EventRecord.user_id == current_user.id)
    distinct_runs = runs_q.scalar() or 0

    # Feedback-survey rating tally: response lives in the metadata of the
    # 'responded' events (event_type == 'responded').
    ratings = {'good': 0, 'fine': 0, 'bad': 0, 'dismissed': 0}
    survey_q = db.session.query(EventRecord.metadata_json).filter(
        EventRecord.event == 'tengu_feedback_survey_event')
    if not is_admin:
        survey_q = survey_q.filter(EventRecord.user_id == current_user.id)
    for (meta_str,) in survey_q.all():
        try:
            m = _json.loads(meta_str) if meta_str else {}
        except (ValueError, TypeError):
            continue
        if m.get('event_type') == 'responded':
            r = m.get('response')
            if r in ratings:
                ratings[r] += 1
    survey_total = sum(ratings.values())

    # Pretty-print metadata for the visible rows. Also extract the survey
    # rating (response) for feedback-survey rows so the table can show it inline.
    parsed = {}
    survey_resp = {}
    for ev in pagination.items:
        if not ev.metadata_json:
            parsed[ev.id] = ''
            continue
        try:
            m = _json.loads(ev.metadata_json)
            parsed[ev.id] = _json.dumps(m, indent=2, ensure_ascii=False)
            if ev.event == 'tengu_feedback_survey_event' and isinstance(m, dict):
                if m.get('event_type') == 'responded' and m.get('response'):
                    survey_resp[ev.id] = m.get('response')
                elif m.get('event_type'):
                    survey_resp[ev.id] = m.get('event_type')  # appeared / etc.
        except (ValueError, TypeError):
            parsed[ev.id] = ev.metadata_json

    return render_template(
        'admin_events.html',
        events=pagination.items,
        pagination=pagination,
        users=users,
        counts=counts,
        total_events=total_events,
        distinct_runs=distinct_runs,
        ratings=ratings,
        rating_labels=_RATING_LABELS,
        survey_total=survey_total,
        survey_resp=survey_resp,
        event_filter=event_filter,
        parsed=parsed,
        is_admin=is_admin,
    )


# ---------------------------------------------------------------------------
# Portal UI — aggregate insights from CLI events
# ---------------------------------------------------------------------------

@api_bp.route('/admin/insights')
@login_required
def admin_insights():
    """Aggregate insights computed from the tengu_* event stream: activity over
    time, top slash commands, top skills, errors, models, and session stats
    (cost/duration/lines from tengu_exit). Admin = all users; user = own."""
    import json as _json
    from collections import Counter, defaultdict
    from datetime import timedelta
    from sqlalchemy import func

    is_admin = current_user.is_admin

    def _scope(q):
        return q if is_admin else q.filter(EventRecord.user_id == current_user.id)

    total_events = _scope(db.session.query(func.count(EventRecord.id))).scalar() or 0
    distinct_runs = _scope(db.session.query(func.count(func.distinct(EventRecord.run_id)))).scalar() or 0

    # Activity over the last 14 days (UTC date buckets).
    since = datetime.now(timezone.utc) - timedelta(days=14)
    day_counts = Counter()
    rows = _scope(db.session.query(EventRecord.created_at)).filter(EventRecord.created_at >= since).all()
    for (ts,) in rows:
        if ts:
            day_counts[ts.strftime('%Y-%m-%d')] += 1
    activity = []
    for i in range(13, -1, -1):
        d = (datetime.now(timezone.utc) - timedelta(days=i)).strftime('%Y-%m-%d')
        activity.append({'date': d[5:], 'count': day_counts.get(d, 0)})
    activity_max = max((a['count'] for a in activity), default=0)

    # Pull metadata for the breakdown events (cap the scan for safety).
    def _meta_rows(event_name, limit=20000):
        q = _scope(db.session.query(EventRecord.metadata_json)).filter(
            EventRecord.event == event_name
        ).order_by(EventRecord.id.desc()).limit(limit)
        out = []
        for (m,) in q.all():
            if not m:
                continue
            try:
                out.append(_json.loads(m))
            except (ValueError, TypeError):
                continue
        return out

    # Top slash commands (tengu_input_command.input).
    cmd_counter = Counter()
    for m in _meta_rows('tengu_input_command'):
        c = m.get('input')
        if c:
            cmd_counter[str(c)[:40]] += 1
    top_commands = cmd_counter.most_common(12)

    # Top skills (tengu_skill_loaded._PROTO_skill_name / skill_name).
    skill_counter = Counter()
    for m in _meta_rows('tengu_skill_loaded'):
        s = m.get('_PROTO_skill_name') or m.get('skill_name')
        if s:
            skill_counter[str(s)[:60]] += 1
    top_skills = skill_counter.most_common(12)

    # Models (tengu_api_query.model).
    model_counter = Counter()
    for m in _meta_rows('tengu_api_query'):
        mod = m.get('model')
        if mod:
            model_counter[str(mod)[:50]] += 1
    top_models = model_counter.most_common(10)

    # Errors: unhandled rejections by type + total error/failure-ish events.
    err_counter = Counter()
    for m in _meta_rows('tengu_unhandled_rejection'):
        err_counter[str(m.get('error_name') or 'unknown')[:50]] += 1
    top_errors = err_counter.most_common(10)
    error_event_total = _scope(db.session.query(func.count(EventRecord.id))).filter(
        (EventRecord.event.like('%_error%')) | (EventRecord.event.like('%rejection%')) |
        (EventRecord.event.like('%_failed%'))
    ).scalar() or 0

    # Session stats from tengu_exit summaries.
    sess = {'count': 0, 'cost': 0.0, 'api_ms': 0, 'wall_ms': 0, 'added': 0, 'removed': 0, 'in_tok': 0, 'out_tok': 0}
    for m in _meta_rows('tengu_exit'):
        sess['count'] += 1
        sess['cost'] += float(m.get('last_session_cost') or 0)
        sess['api_ms'] += int(m.get('last_session_api_duration') or 0)
        sess['wall_ms'] += int(m.get('last_session_duration') or 0)
        sess['added'] += int(m.get('last_session_lines_added') or 0)
        sess['removed'] += int(m.get('last_session_lines_removed') or 0)
        sess['in_tok'] += int(m.get('last_session_total_input_tokens') or m.get('last_session_input_tokens') or 0)
        sess['out_tok'] += int(m.get('last_session_total_output_tokens') or m.get('last_session_output_tokens') or 0)

    # Survey ratings tally.
    ratings = {'good': 0, 'fine': 0, 'bad': 0, 'dismissed': 0}
    for m in _meta_rows('tengu_feedback_survey_event'):
        if m.get('event_type') == 'responded' and m.get('response') in ratings:
            ratings[m['response']] += 1

    return render_template(
        'admin_insights.html',
        total_events=total_events,
        distinct_runs=distinct_runs,
        activity=activity,
        activity_max=activity_max,
        top_commands=top_commands,
        top_skills=top_skills,
        top_models=top_models,
        top_errors=top_errors,
        error_event_total=error_event_total,
        sess=sess,
        ratings=ratings,
        rating_labels=_RATING_LABELS,
        is_admin=is_admin,
    )


# ---------------------------------------------------------------------------
# Portal UI — OpenTelemetry trace viewer
# ---------------------------------------------------------------------------

def _span_attr_preview(attrs):
    """A compact one-line hint for a span row (tool name, model, etc.)."""
    for k in ('tool.name', 'tool_name', 'model', 'hook.name', 'error', 'error.message'):
        v = attrs.get(k)
        if v:
            return f'{k}={v}'
    return ''


@api_bp.route('/admin/traces')
@login_required
def admin_traces():
    """Browse OpenTelemetry traces (span trees) from the CLI deep-tracing
    exporter. Admin = all users; user = own."""
    import json as _json
    from sqlalchemy import func

    is_admin = current_user.is_admin
    from models import User
    users = {u.id: u.username for u in User.query.all()}

    page = request.args.get('page', 1, type=int)
    per_page = 20

    def _scope(q):
        return q if is_admin else q.filter(TraceSpan.user_id == current_user.id)

    # Distinct traces ordered by recency (max row id per trace_id).
    tq = _scope(db.session.query(
        TraceSpan.trace_id, func.max(TraceSpan.id).label('mx')
    )).group_by(TraceSpan.trace_id).order_by(func.max(TraceSpan.id).desc())
    total_traces = tq.count()
    trace_rows = tq.limit(per_page).offset((page - 1) * per_page).all()
    trace_ids = [r[0] for r in trace_rows]

    total_spans = _scope(db.session.query(func.count(TraceSpan.id))).scalar() or 0

    traces = []
    if trace_ids:
        all_spans = _scope(TraceSpan.query.filter(TraceSpan.trace_id.in_(trace_ids))).all()
        by_trace = {}
        for s in all_spans:
            by_trace.setdefault(s.trace_id, []).append(s)

        for tid in trace_ids:
            spans = by_trace.get(tid, [])
            by_id = {s.span_id: s for s in spans}
            children = {}
            roots = []
            for s in spans:
                if s.parent_span_id and s.parent_span_id in by_id:
                    children.setdefault(s.parent_span_id, []).append(s)
                else:
                    roots.append(s)
            roots.sort(key=lambda s: (s.start_ns or 0))

            ordered = []  # (span, depth)

            def _walk(node, depth):
                ordered.append((node, depth))
                kids = sorted(children.get(node.span_id, []), key=lambda s: (s.start_ns or 0))
                for k in kids:
                    _walk(k, depth + 1)

            for r in roots:
                _walk(r, 0)

            root = roots[0] if roots else (spans[0] if spans else None)
            root_attrs = {}
            if root and root.attributes_json:
                try:
                    root_attrs = _json.loads(root.attributes_json)
                except (ValueError, TypeError):
                    root_attrs = {}
            error_count = sum(1 for s in spans if s.status_code == 2)

            span_vms = []
            for s, depth in ordered:
                try:
                    attrs = _json.loads(s.attributes_json) if s.attributes_json else {}
                except (ValueError, TypeError):
                    attrs = {}
                span_vms.append({
                    'depth': depth,
                    'name': s.name,
                    'span_type': s.span_type,
                    'duration_ms': s.duration_ms,
                    'status_code': s.status_code,
                    'span_id': s.span_id,
                    'preview': _span_attr_preview(attrs),
                    'attrs_pretty': _json.dumps(attrs, indent=2, ensure_ascii=False) if attrs else '',
                })

            traces.append({
                'trace_id': tid,
                'root_name': root.name if root else '(unknown)',
                'root_duration_ms': root.duration_ms if root else None,
                'start_dt': (datetime.fromtimestamp(root.start_ns / 1e9, tz=timezone.utc)
                             if root and root.start_ns else (root.created_at if root else None)),
                'user': users.get(root.user_id) if root else None,
                'prompt': str(root_attrs.get('user_prompt') or '')[:160],
                'span_count': len(spans),
                'error_count': error_count,
                'spans': span_vms,
            })

    # Pagination shim (lightweight; mirrors what the template expects).
    class _Pg:
        def __init__(self, page, per_page, total):
            self.page = page
            self.per_page = per_page
            self.total = total
            self.pages = max(1, (total + per_page - 1) // per_page)

        def iter_pages(self, **kw):
            return range(1, self.pages + 1)

    pagination = _Pg(page, per_page, total_traces)

    return render_template(
        'admin_traces.html',
        traces=traces,
        pagination=pagination,
        total_traces=total_traces,
        total_spans=total_spans,
        is_admin=is_admin,
    )




# ---------------------------------------------------------------------------
# Portal UI — usage analytics dashboard
# ---------------------------------------------------------------------------

@api_bp.route('/usage')
@login_required
def usage():
    """Rich analytics dashboard. Admins see all users; regular users see own data."""
    from sqlalchemy import func, case, cast, String
    from models import User
    from datetime import timedelta

    is_admin = current_user.is_admin
    base_q = UsageRecord.query
    if not is_admin:
        base_q = base_q.filter(UsageRecord.user_id == current_user.id)

    # --- Summary stats ---
    totals = db.session.query(
        func.count(UsageRecord.id).label('requests'),
        func.coalesce(func.sum(UsageRecord.prompt_tokens), 0).label('prompt'),
        func.coalesce(func.sum(UsageRecord.completion_tokens), 0).label('completion'),
        func.coalesce(func.sum(UsageRecord.total_tokens), 0).label('total'),
        func.coalesce(func.sum(case((UsageRecord.error != None, 1), else_=0)), 0).label('errors'),
        func.coalesce(func.sum(UsageRecord.duration_ms), 0).label('total_duration_ms'),
    )
    if not is_admin:
        totals = totals.filter(UsageRecord.user_id == current_user.id)
    totals = totals.first()

    # --- Per-user breakdown (admin) ---
    users_data = None
    if is_admin:
        user_stats = db.session.query(
            UsageRecord.user_id,
            func.count(UsageRecord.id).label('requests'),
            func.coalesce(func.sum(UsageRecord.total_tokens), 0).label('total_tokens'),
            func.coalesce(func.sum(case((UsageRecord.error != None, 1), else_=0)), 0).label('errors'),
            func.coalesce(func.sum(UsageRecord.duration_ms), 0).label('total_duration_ms'),
            func.max(UsageRecord.created_at).label('last_active'),
        ).group_by(UsageRecord.user_id).all()
        # Join with usernames
        user_map = {u.id: u.username for u in User.query.all()}
        users_data = [{
            'user_id': s.user_id,
            'username': user_map.get(s.user_id, f'user-{s.user_id}'),
            'requests': s.requests,
            'total_tokens': s.total_tokens,
            'errors': s.errors,
            'total_duration_ms': s.total_duration_ms,
            'last_active': s.last_active,
        } for s in user_stats]

    # --- Tool usage breakdown ---
    # Aggregate in SQL by distinct comma-separated combo, then split once per combo.
    # The base table may have ~20k matching rows, but distinct combos are typically <50.
    tool_combo_q = db.session.query(
        UsageRecord.tool_names,
        func.count(UsageRecord.id).label('n'),
    ).filter(UsageRecord.tool_names != None)
    if not is_admin:
        tool_combo_q = tool_combo_q.filter(UsageRecord.user_id == current_user.id)
    tool_combo_rows = tool_combo_q.group_by(UsageRecord.tool_names).all()
    tool_counts = {}
    for combo, n in tool_combo_rows:
        if not combo:
            continue
        for t in combo.split(','):
            t = t.strip()
            if t:
                tool_counts[t] = tool_counts.get(t, 0) + n
    tool_usage = sorted(tool_counts.items(), key=lambda x: -x[1])

    # --- Stop reason distribution ---
    stop_stats = db.session.query(
        UsageRecord.stop_reason,
        func.count(UsageRecord.id).label('count'),
    )
    if not is_admin:
        stop_stats = stop_stats.filter(UsageRecord.user_id == current_user.id)
    stop_stats = stop_stats.group_by(UsageRecord.stop_reason).all()

    # --- Error types ---
    error_stats = db.session.query(
        UsageRecord.error,
        func.count(UsageRecord.id).label('count'),
    ).filter(UsageRecord.error != None)
    if not is_admin:
        error_stats = error_stats.filter(UsageRecord.user_id == current_user.id)
    error_stats = error_stats.group_by(UsageRecord.error).order_by(func.count(UsageRecord.id).desc()).limit(10).all()

    # --- Hourly activity (last 24h) ---
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    hourly = db.session.query(
        func.strftime('%H', UsageRecord.created_at).label('hour'),
        func.count(UsageRecord.id).label('count'),
    ).filter(UsageRecord.created_at >= day_ago)
    if not is_admin:
        hourly = hourly.filter(UsageRecord.user_id == current_user.id)
    hourly = hourly.group_by('hour').order_by('hour').all()
    hourly_data = {int(h.hour): h.count for h in hourly}

    # --- Daily activity (last 30 days) ---
    month_ago = now - timedelta(days=30)
    daily = db.session.query(
        func.date(UsageRecord.created_at).label('day'),
        func.count(UsageRecord.id).label('requests'),
        func.coalesce(func.sum(UsageRecord.total_tokens), 0).label('tokens'),
        func.coalesce(func.sum(case((UsageRecord.error != None, 1), else_=0)), 0).label('errors'),
    ).filter(UsageRecord.created_at >= month_ago)
    if not is_admin:
        daily = daily.filter(UsageRecord.user_id == current_user.id)
    daily = daily.group_by('day').order_by('day').all()

    # --- Avg response time by model ---
    tier_perf = db.session.query(
        UsageRecord.model,
        func.count(UsageRecord.id).label('count'),
        func.avg(UsageRecord.duration_ms).label('avg_ms'),
        func.avg(UsageRecord.completion_tokens).label('avg_completion'),
    ).filter(UsageRecord.error == None)
    if not is_admin:
        tier_perf = tier_perf.filter(UsageRecord.user_id == current_user.id)
    tier_perf = tier_perf.group_by(UsageRecord.model).all()

    # --- Recent queries (last 100) ---
    recent = base_q.order_by(UsageRecord.created_at.desc()).limit(100).all()

    # Build user map for admin view (username lookup for recent requests)
    user_map = {}
    if is_admin:
        user_ids = {r.user_id for r in recent}
        if user_ids:
            from models import User as UserModel
            for u in UserModel.query.filter(UserModel.id.in_(user_ids)).all():
                user_map[u.id] = u.username

    return render_template('usage.html',
        totals=totals, users_data=users_data, tool_usage=tool_usage,
        stop_stats=stop_stats, error_stats=error_stats,
        hourly_data=hourly_data, daily=daily, tier_perf=tier_perf,
        recent=recent, is_admin=is_admin, user_map=user_map,
    )


@api_bp.route('/request/<int:request_id>')
@login_required
def request_detail(request_id):
    """Return JSON details for a single usage record."""
    from models import User as UserModel

    record = UsageRecord.query.get_or_404(request_id)

    # Authorization: admin can see any, regular users only their own
    if not current_user.is_admin and record.user_id != current_user.id:
        return jsonify({'error': 'forbidden'}), 403

    user = UserModel.query.get(record.user_id)

    return jsonify({
        'id': record.id,
        'user': user.username if user else f'user-{record.user_id}',
        'model': record.model,
        'tier': record.tier,
        'status': 'error' if record.error else 'success',
        'error': record.error,
        'endpoint': record.endpoint,
        'timestamp': record.created_at.isoformat() if record.created_at else '',
        'prompt_tokens': record.prompt_tokens,
        'completion_tokens': record.completion_tokens,
        'total_tokens': record.total_tokens,
        'duration': record.duration_ms,
        'messages_sent': record.messages_sent,
        'budget_dropped': record.prompt_budget_dropped,
        'tool_round': record.tool_round,
        'stop_reason': record.stop_reason,
        'salvaged': bool(record.salvaged),
        'salvaged_tools': (record.salvaged_tools or '').split(',') if record.salvaged_tools else [],
        'raw_text': record.raw_text or '',
        'tools_used': (record.tool_names or '').split(',') if record.tool_names else [],
        'tools_available': (record.tools_available or '').split(',') if record.tools_available else [],
        'query': record.query_summary or '',
        'tool_calls': [
            {
                'name': tc.name,
                'action': tc.action,
                'target': tc.target,
                'command': tc.command,
                'old_text': tc.old_text,
                'new_text': tc.new_text,
                'content': tc.content,
                'bytes': tc.bytes,
            }
            for tc in record.tool_calls.order_by(ToolCall.seq).all()
        ],
    })


@api_bp.route('/usage/user/<int:user_id>')
@login_required
def user_usage(user_id):
    """Per-user detailed usage view. Admin or self only."""
    from sqlalchemy import func, case
    from models import User
    from datetime import timedelta

    if not current_user.is_admin and current_user.id != user_id:
        flash('Not authorized.', 'danger')
        return redirect(url_for('api.usage'))

    user = User.query.get_or_404(user_id)
    base_q = UsageRecord.query.filter_by(user_id=user_id)

    # Summary
    totals = db.session.query(
        func.count(UsageRecord.id).label('requests'),
        func.coalesce(func.sum(UsageRecord.total_tokens), 0).label('total'),
        func.coalesce(func.sum(case((UsageRecord.error != None, 1), else_=0)), 0).label('errors'),
        func.coalesce(func.sum(UsageRecord.duration_ms), 0).label('total_duration_ms'),
        func.min(UsageRecord.created_at).label('first_seen'),
        func.max(UsageRecord.created_at).label('last_seen'),
    ).filter(UsageRecord.user_id == user_id).first()

    # Tool usage
    all_records = base_q.filter(UsageRecord.tool_names != None).all()
    tool_counts = {}
    for r in all_records:
        if r.tool_names:
            for t in r.tool_names.split(','):
                t = t.strip()
                if t:
                    tool_counts[t] = tool_counts.get(t, 0) + 1
    tool_usage = sorted(tool_counts.items(), key=lambda x: -x[1])

    # Reconstruct sessions — group requests within 5min gaps
    all_req = base_q.order_by(UsageRecord.created_at.asc()).all()
    sessions = []
    current_session = []
    for r in all_req:
        if current_session and r.created_at and current_session[-1].created_at:
            gap = (r.created_at - current_session[-1].created_at).total_seconds()
            if gap > 300:  # 5 min gap = new session
                sessions.append(current_session)
                current_session = []
        current_session.append(r)
    if current_session:
        sessions.append(current_session)

    session_summaries = []
    for s in sessions[-20:]:  # last 20 sessions
        queries = [r.query_summary for r in s if r.query_summary]
        errors = sum(1 for r in s if r.error)
        tokens = sum(r.total_tokens or 0 for r in s)
        duration = sum(r.duration_ms or 0 for r in s)
        session_summaries.append({
            'start': s[0].created_at,
            'end': s[-1].created_at,
            'requests': len(s),
            'tokens': tokens,
            'errors': errors,
            'duration_ms': duration,
            'queries': queries[:5],  # first 5 unique queries
        })
    session_summaries.reverse()

    # Recent requests
    recent = base_q.order_by(UsageRecord.created_at.desc()).limit(100).all()

    return render_template('user_usage.html',
        user=user, totals=totals, tool_usage=tool_usage,
        sessions=session_summaries, recent=recent,
    )


# ---------------------------------------------------------------------------
# Admin — user management
# ---------------------------------------------------------------------------

@api_bp.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    from models import User
    users = User.query.order_by(User.created_at.desc()).all()
    groups = Group.query.order_by(Group.name.asc()).all()
    return render_template(
        'admin_users.html',
        users=users,
        groups=groups,
        cloud_subagent_models=CLOUD_SUBAGENT_MODELS,
        cloud_subagent_flag=CLOUD_SUBAGENT_FLAG,
    )


@api_bp.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@login_required
def toggle_user(user_id):
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    from models import User
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot disable yourself.', 'danger')
        return redirect(url_for('api.admin_users'))
    user.is_active_user = not user.is_active_user
    db.session.commit()
    status = 'enabled' if user.is_active_user else 'disabled'
    flash(f'User "{user.username}" {status}.', 'info')
    return redirect(url_for('api.admin_users'))


@api_bp.route('/admin/users/<int:user_id>/flags', methods=['POST'])
@login_required
def update_user_flags(user_id):
    """Set or clear a user's per-user feature flags from the admin UI.

    Currently exposes the "cloud subagents" toggle: a non-empty, known cloud
    model enables the feature for that user; an empty/unknown value disables it
    (subagents revert to the local model). Delivered to the CLI on next launch
    via the bootstrap endpoint.
    """
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    from models import User
    from sqlalchemy.orm.attributes import flag_modified
    user = User.query.get_or_404(user_id)
    cloud_model = (request.form.get('cloud_subagent_model') or '').strip()
    flags = dict(user.feature_flags or {})
    if cloud_model and cloud_model in CLOUD_SUBAGENT_MODELS:
        flags[CLOUD_SUBAGENT_FLAG] = cloud_model
        msg = f'Cloud subagents enabled ({cloud_model}) for "{user.username}".'
    else:
        flags.pop(CLOUD_SUBAGENT_FLAG, None)
        msg = f'Cloud subagents disabled for "{user.username}".'
    user.feature_flags = flags
    flag_modified(user, 'feature_flags')  # ensure JSON mutation is persisted
    db.session.commit()
    flash(msg, 'info')
    return redirect(url_for('api.admin_users'))


@api_bp.route('/admin/users/create', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    from models import User

    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    is_admin = 'is_admin' in request.form

    errors = []
    if not username or len(username) < 3:
        errors.append('Username must be at least 3 characters.')
    if not email or '@' not in email:
        errors.append('A valid email is required.')
    if len(password) < 8:
        errors.append('Password must be at least 8 characters.')
    if User.query.filter_by(username=username).first():
        errors.append('Username already taken.')
    if User.query.filter_by(email=email).first():
        errors.append('Email already registered.')

    if errors:
        for e in errors:
            flash(e, 'danger')
    else:
        user = User(username=username, email=email, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash(f'User "{username}" created.', 'success')
    return redirect(url_for('api.admin_users'))


@api_bp.route('/admin/users/<int:user_id>/group', methods=['POST'])
@login_required
def assign_user_group(user_id):
    """Assign (or clear) a user's group. The group's agent-model config +
    feature flags are delivered to that user's CLI on next launch."""
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    from models import User
    user = User.query.get_or_404(user_id)
    raw = (request.form.get('group_id') or '').strip()
    if not raw:
        user.group_id = None
        msg = f'Cleared group for "{user.username}".'
    else:
        group = Group.query.get(int(raw)) if raw.isdigit() else None
        if not group:
            flash('Unknown group.', 'danger')
            return redirect(url_for('api.admin_users'))
        user.group_id = group.id
        msg = f'Assigned "{user.username}" to group "{group.name}".'
    db.session.commit()
    flash(msg, 'info')
    return redirect(url_for('api.admin_users'))


# ---------------------------------------------------------------------------
# Admin — group configuration profiles
# ---------------------------------------------------------------------------

@api_bp.route('/admin/groups')
@login_required
def admin_groups():
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    groups = Group.query.order_by(Group.name.asc()).all()
    return render_template('admin_groups.html', groups=groups)


@api_bp.route('/admin/groups/create', methods=['POST'])
@login_required
def create_group():
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    name = (request.form.get('name') or '').strip()
    description = (request.form.get('description') or '').strip() or None
    if not name:
        flash('Group name is required.', 'danger')
        return redirect(url_for('api.admin_groups'))
    if Group.query.filter_by(name=name).first():
        flash('A group with that name already exists.', 'danger')
        return redirect(url_for('api.admin_groups'))
    group = Group(name=name, description=description, agent_models={}, feature_flags={})
    db.session.add(group)
    db.session.commit()
    flash(f'Group "{name}" created.', 'success')
    return redirect(url_for('api.edit_group', group_id=group.id))


@api_bp.route('/admin/groups/<int:group_id>/edit')
@login_required
def edit_group(group_id):
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    group = Group.query.get_or_404(group_id)
    return render_template(
        'admin_group_edit.html',
        group=group,
        agent_types=KNOWN_AGENT_TYPES,
        available_models=_available_model_names(),
        cloud_subagent_models=CLOUD_SUBAGENT_MODELS,
        cloud_subagent_flag=CLOUD_SUBAGENT_FLAG,
    )


@api_bp.route('/admin/groups/<int:group_id>/update', methods=['POST'])
@login_required
def update_group(group_id):
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    from sqlalchemy.orm.attributes import flag_modified
    group = Group.query.get_or_404(group_id)

    name = (request.form.get('name') or '').strip()
    if name and name != group.name:
        if Group.query.filter(Group.name == name, Group.id != group.id).first():
            flash('Another group already uses that name.', 'danger')
            return redirect(url_for('api.edit_group', group_id=group.id))
        group.name = name
    group.description = (request.form.get('description') or '').strip() or None

    # Per-agent models: a form field `agent__<type>` for each known agent type.
    # Empty value = unset (CLI uses its baked default). 'inherit' = parent model.
    agent_models = {}
    for agent_type, _label, _default in KNOWN_AGENT_TYPES:
        val = (request.form.get(f'agent__{agent_type}') or '').strip()
        if val:
            agent_models[agent_type] = val
    group.agent_models = agent_models
    flag_modified(group, 'agent_models')

    # Optional group-level cloud-subagent default (applies when an agent type
    # has no explicit mapping and the CLI falls through to the global flag).
    flags = dict(group.feature_flags or {})
    cloud_model = (request.form.get('cloud_subagent_model') or '').strip()
    if cloud_model:
        flags[CLOUD_SUBAGENT_FLAG] = cloud_model
    else:
        flags.pop(CLOUD_SUBAGENT_FLAG, None)
    group.feature_flags = flags
    flag_modified(group, 'feature_flags')

    db.session.commit()
    flash(f'Group "{group.name}" saved.', 'success')
    return redirect(url_for('api.edit_group', group_id=group.id))


@api_bp.route('/admin/groups/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    group = Group.query.get_or_404(group_id)
    # Detach members (set group_id NULL) before delete.
    for member in group.members.all():
        member.group_id = None
    name = group.name
    db.session.delete(group)
    db.session.commit()
    flash(f'Group "{name}" deleted.', 'info')
    return redirect(url_for('api.admin_groups'))


# ---------------------------------------------------------------------------
# Admin — site settings + cloud providers
# ---------------------------------------------------------------------------

@api_bp.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'save_settings':
            signup_enabled = 'signup_enabled' in request.form
            SiteSettings.set('signup_enabled', 'true' if signup_enabled else 'false')
            flash('Settings saved.', 'success')

        elif action == 'save_ollama_token':
            token = request.form.get('ollama_token', '').strip()
            if token:
                SiteSettings.set('ollama_token', token)
                flash('Ollama token saved.', 'success')
            else:
                # Clear the token
                from models import SiteSettings as SS
                row = SS.query.get('ollama_token')
                if row:
                    db.session.delete(row)
                    db.session.commit()
                flash('Ollama token cleared.', 'info')

        return redirect(url_for('api.admin_settings'))

    signup_enabled = SiteSettings.get('signup_enabled', 'true') == 'true'
    ollama_token = SiteSettings.get('ollama_token')
    return render_template('settings.html', signup_enabled=signup_enabled, ollama_token=ollama_token)


# ---------------------------------------------------------------------------
# OAuth 2.0 — token exchange & CLI key provisioning (machine-facing)
# ---------------------------------------------------------------------------
# These are called by the Vivus CLI (not a browser), so they live on the
# CSRF-exempt api blueprint. The browser-facing consent + callback pages are
# in oauth_routes.py.

def _bearer_token():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:].strip()
    return ''


def _oauth_user_from_bearer():
    """Resolve the active OAuth access token to a live user, or None."""
    token = OAuthToken.lookup_access(_bearer_token())
    if token is None:
        return None
    user = token.user
    if user is None or not user.is_active:
        return None
    return user


@api_bp.route('/v1/oauth/token', methods=['POST'])
def oauth_token():
    """Exchange a PKCE authorization code (or refresh token) for tokens."""
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    grant_type = data.get('grant_type', '')
    client_id = data.get('client_id', '')

    if client_id and client_id not in OAUTH_ALLOWED_CLIENT_IDS:
        return jsonify({'error': 'invalid_client'}), 401

    if grant_type == 'authorization_code':
        row, err = OAuthAuthCode.consume(
            data.get('code', ''),
            data.get('redirect_uri', ''),
            data.get('code_verifier', ''),
        )
        if err:
            return jsonify({'error': err}), 401
        token = OAuthToken.issue(row.user_id, row.client_id, row.scope or OAUTH_GRANTED_SCOPE)
    elif grant_type == 'refresh_token':
        existing = OAuthToken.lookup_refresh(data.get('refresh_token', ''))
        if existing is None:
            return jsonify({'error': 'invalid_grant'}), 401
        requested = data.get('scope') or existing.scope or OAUTH_GRANTED_SCOPE
        # Never grant inference scope — keep the CLI on the API-key path.
        scope = ' '.join(s for s in requested.split() if s != 'user:inference')
        token = OAuthToken.issue(existing.user_id, existing.client_id, scope)
    else:
        return jsonify({'error': 'unsupported_grant_type'}), 400

    user = token.user
    return jsonify({
        'token_type': 'Bearer',
        'access_token': token.access_token,
        'refresh_token': token.refresh_token,
        'expires_in': token.expires_in,
        'scope': token.scope,
        'account': {
            'uuid': user.account_uuid,
            'email_address': user.email,
        },
        'organization': {
            'uuid': user.org_uuid,
        },
    })


@api_bp.route('/api/oauth/vivus_cli/create_api_key', methods=['POST'])
def oauth_create_api_key():
    """Mint a per-user API key for the authenticated CLI session."""
    user = _oauth_user_from_bearer()
    if user is None:
        return jsonify({'error': 'unauthorized'}), 401
    raw_key, key_hash, key_prefix = ApiKey.generate_key()
    api_key = ApiKey(user_id=user.id, name='vivus-cli', key_hash=key_hash, key_prefix=key_prefix)
    db.session.add(api_key)
    db.session.commit()
    return jsonify({
        'raw_key': raw_key,
        'key_id': api_key.id,
        'key_prefix': key_prefix,
    })


@api_bp.route('/api/oauth/vivus_cli/roles', methods=['GET'])
def oauth_roles():
    """Best-effort roles for the signed-in user (non-fatal in the CLI)."""
    user = _oauth_user_from_bearer()
    if user is None:
        return jsonify({'error': 'unauthorized'}), 401
    role = 'admin' if user.is_admin else 'member'
    return jsonify({
        'organization_role': role,
        'workspace_role': role,
        'organization_name': 'Vivus',
    })


def _profile_payload(user):
    """Build the OAuth profile shape the CLI expects (installOAuthTokens reads
    account.uuid/email/created_at and organization.uuid).

    organization_type is intentionally left null so the CLI does NOT classify
    the user as a subscription (vivus_pro/max/...) — that keeps it on the
    x-api-key inference path the proxy authenticates, rather than sending an
    OAuth bearer the proxy can't validate.
    """
    created = user.created_at.isoformat() if getattr(user, 'created_at', None) else None
    return {
        'account': {
            'uuid': user.account_uuid,
            'email': user.email,
            'email_address': user.email,
            'display_name': user.username,
            'full_name': user.username,
            'created_at': created,
            'has_verified_email': True,
        },
        'organization': {
            'uuid': user.org_uuid,
            'name': 'Vivus',
            'organization_type': None,
            'rate_limit_tier': None,
            'has_extra_usage_enabled': False,
            'billing_type': None,
            'subscription_created_at': None,
        },
    }


@api_bp.route('/api/oauth/profile', methods=['GET'])
def oauth_profile():
    """OAuth profile for a bearer-authenticated CLI session."""
    user = _oauth_user_from_bearer()
    if user is None:
        return jsonify({'error': 'unauthorized'}), 401
    return jsonify(_profile_payload(user))


@api_bp.route('/api/vivus_cli_profile', methods=['GET'])
def vivus_cli_profile():
    """Profile lookup for API-key (Console) sessions. Resolves the x-api-key
    header (or Bearer) to a user and returns the same profile shape."""
    user = None
    raw_key = request.headers.get('x-api-key') or ''
    if raw_key:
        api_key_obj = ApiKey.lookup(raw_key)
        user = api_key_obj.user if api_key_obj else None
    if user is None:
        user = _oauth_user_from_bearer()
    if user is None:
        return jsonify({'error': 'unauthorized'}), 401
    return jsonify(_profile_payload(user))
