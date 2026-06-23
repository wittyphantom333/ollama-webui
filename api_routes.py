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
    EventRecord,
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

    Bounds size by trimming the transcript array (dropping the OLDEST messages),
    never by slicing the JSON string — a raw slice corrupts the JSON and makes
    the stored transcript unparseable/unreadable.
    """
    import json as _json
    try:
        s = _json.dumps(inner, ensure_ascii=False)
    except Exception:
        return _json.dumps({'_error': 'unserializable payload'})
    if len(s) <= limit:
        return s
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
        base['_truncated'] = 'transcript omitted (too large)'
        return _json.dumps(base, ensure_ascii=False)[:limit]
    return s[:limit]


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
    flags = (user.feature_flags or {}) if user else {}
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
        for k in ('description', 'platform', 'version', 'datetime'):
            mm = _re.search(r'"' + k + r'"\s*:\s*"([^"]*)"', payload_str)
            if mm:
                out['meta'][k] = mm.group(1)
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
    return render_template(
        'admin_users.html',
        users=users,
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
