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
from models import db, ApiKey, UsageRecord, SiteSettings, CloudProvider

api_bp = Blueprint('api', __name__, template_folder='templates')


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
    db.session.commit()

    return jsonify({'ok': True}), 200


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
    all_records = base_q.filter(UsageRecord.tool_names != None).all()
    tool_counts = {}
    for r in all_records:
        if r.tool_names:
            for t in r.tool_names.split(','):
                t = t.strip()
                if t:
                    tool_counts[t] = tool_counts.get(t, 0) + 1
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
    return render_template('admin_users.html', users=users)


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
