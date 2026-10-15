from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, Response
from flask_login import LoginManager, login_required, current_user
import requests
import json
import os
import re
import time
import hashlib
import subprocess
from threading import Lock
from dotenv import load_dotenv
import base64
from flask_wtf.csrf import CSRFProtect
import markdown

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///vivus.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
csrf = CSRFProtect(app)

# Database and login
from models import db, User
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Register blueprints
from auth import auth_bp
from api_routes import api_bp
from oauth_routes import oauth_bp
app.register_blueprint(auth_bp)
app.register_blueprint(api_bp)
app.register_blueprint(oauth_bp)

# Exempt proxy-facing API endpoints from CSRF (they use API keys)
csrf.exempt(api_bp)


# Timestamps are stored as UTC (models._utcnow). Render the UTC instant into a
# <time> element and let base.html's script restate it in the browser's zone —
# the server has no way to know the viewer's offset, and the box's own TZ is not
# it. The server-rendered body is the UTC fallback for no-JS.
from markupsafe import Markup, escape
from models import utc_iso


@app.template_filter('localdt')
def localdt_filter(value, fmt='%Y-%m-%d %H:%M', placeholder='—'):
    if value is None:
        return placeholder
    return Markup(
        f'<time datetime="{escape(utc_iso(value))}" data-local="{escape(fmt)}">'
        f'{escape(value.strftime(fmt))}</time>'
    )


# Every range picker renders from this one list (see api_routes.DATE_PRESETS).
from api_routes import DATE_PRESETS
app.jinja_env.globals['DATE_PRESETS'] = DATE_PRESETS

# --- Request timing (logs slow routes so we can spot regressions) ---
import logging
_perf_log = app.logger
_SLOW_REQUEST_MS = int(os.getenv('SLOW_REQUEST_MS', '250'))

@app.before_request
def _perf_start():
    request._perf_t0 = time.monotonic()

@app.after_request
def _perf_end(response):
    t0 = getattr(request, '_perf_t0', None)
    if t0 is not None:
        dur_ms = (time.monotonic() - t0) * 1000.0
        if dur_ms >= _SLOW_REQUEST_MS:
            _perf_log.warning(
                'slow %s %s -> %d in %.0fms (%s bytes)',
                request.method, request.path, response.status_code, dur_ms,
                response.calculate_content_length() or '?',
            )
        response.headers['X-Response-Time-Ms'] = f'{dur_ms:.1f}'
    return response

# Create tables on first run
with app.app_context():
    db.create_all()
    # Idempotent column add for existing DBs. db.create_all() creates missing
    # tables but never ALTERs an existing one, so a newly added model column
    # (users.feature_flags) must be backfilled here. SQLite ADD COLUMN is fast
    # and safe; NOT NULL requires a constant default on a populated table.
    from sqlalchemy import inspect as _sa_inspect, text as _sa_text
    try:
        _user_cols = {c['name'] for c in _sa_inspect(db.engine).get_columns('users')}
        if 'feature_flags' not in _user_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE users ADD COLUMN feature_flags JSON NOT NULL DEFAULT '{}'"
            ))
            db.session.commit()
            app.logger.info('migrated: added users.feature_flags column')
        # group_id FK (nullable) — links a user to a Group config profile.
        if 'group_id' not in _user_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE users ADD COLUMN group_id INTEGER REFERENCES groups(id)"
            ))
            db.session.commit()
            app.logger.info('migrated: added users.group_id column')
        # Text tool-call salvage diagnostics on usage_records (salvaged flag,
        # recovered tool names, and a capped raw-text copy for failure analysis).
        _ur_cols = {c['name'] for c in _sa_inspect(db.engine).get_columns('usage_records')}
        if 'salvaged' not in _ur_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE usage_records ADD COLUMN salvaged BOOLEAN DEFAULT 0"
            ))
            db.session.commit()
            app.logger.info('migrated: added usage_records.salvaged column')
        if 'salvaged_tools' not in _ur_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE usage_records ADD COLUMN salvaged_tools VARCHAR(500)"
            ))
            db.session.commit()
            app.logger.info('migrated: added usage_records.salvaged_tools column')
        if 'raw_text' not in _ur_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE usage_records ADD COLUMN raw_text TEXT"
            ))
            db.session.commit()
            app.logger.info('migrated: added usage_records.raw_text column')
        if 'classifier_denied' not in _ur_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE usage_records ADD COLUMN classifier_denied BOOLEAN DEFAULT 0"
            ))
            db.session.commit()
            app.logger.info('migrated: added usage_records.classifier_denied column')
        if 'session_id' not in _ur_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE usage_records ADD COLUMN session_id VARCHAR(64)"
            ))
            db.session.execute(_sa_text(
                "CREATE INDEX IF NOT EXISTS ix_usage_records_session_id "
                "ON usage_records (session_id)"
            ))
            db.session.commit()
            app.logger.info('migrated: added usage_records.session_id column')
        # Tool-result correlation: the tool_use and its tool_result always
        # arrive in separate proxy requests, so the result is UPDATEd onto
        # the existing tool_calls row (found by tool_use_id) later rather
        # than inserted with the call itself.
        _tc_cols = {c['name'] for c in _sa_inspect(db.engine).get_columns('tool_calls')}
        if 'tool_use_id' not in _tc_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE tool_calls ADD COLUMN tool_use_id VARCHAR(100)"
            ))
            db.session.commit()
            app.logger.info('migrated: added tool_calls.tool_use_id column')
        if 'result_content' not in _tc_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE tool_calls ADD COLUMN result_content TEXT"
            ))
            db.session.commit()
            app.logger.info('migrated: added tool_calls.result_content column')
        if 'result_is_error' not in _tc_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE tool_calls ADD COLUMN result_is_error BOOLEAN DEFAULT 0"
            ))
            db.session.commit()
            app.logger.info('migrated: added tool_calls.result_is_error column')
        # Group-based portal permissions (manage_users, view_usage, etc. — see
        # GROUP_CAPABILITIES/has_permission() in models.py, which applies the
        # manage_models-defaults-True fallback in Python, not here).
        _grp_cols = {c['name'] for c in _sa_inspect(db.engine).get_columns('groups')}
        if 'permissions' not in _grp_cols:
            db.session.execute(_sa_text(
                "ALTER TABLE groups ADD COLUMN permissions JSON NOT NULL DEFAULT '{}'"
            ))
            db.session.commit()
            app.logger.info('migrated: added groups.permissions column')
    except Exception as _mig_err:  # pragma: no cover - best-effort migration
        db.session.rollback()
        app.logger.warning('schema migration check failed: %s', _mig_err)

# Ollama API base URL
OLLAMA_API_BASE = os.getenv('OLLAMA_API_BASE', 'http://127.0.0.1:11434')
OLLAMA_API_URL = f"{OLLAMA_API_BASE}/api"

def ollama_headers():
    """Return headers for Ollama API requests, injecting the cloud token when configured."""
    try:
        from models import SiteSettings
        token = SiteSettings.get('ollama_token')
        if token:
            return {'Authorization': f'Bearer {token}'}
    except Exception:
        pass
    return {}

# App configuration
PORT = int(os.getenv('PORT', 5050))
HOST = os.getenv('HOST', '127.0.0.1')

# ---------------------------------------------------------------------------
# Ollama call discipline
# ---------------------------------------------------------------------------
# Every requests.* call to Ollama must specify a timeout. Without one, an
# Ollama instance that's busy generating will block the call indefinitely,
# and with the dev Flask server (or even gunicorn under load) that stalls
# the entire portal. Metadata calls (/version, /tags, /ps, /show) are
# expected to be sub-second; we fail fast and fall back to cached or empty
# data. Mutations (pull/create/delete/unload) get generous budgets because
# they can legitimately take a while. Inference (chat/generate) gets the
# longest budget but still bounded so a stuck request doesn't pin a worker.
OLLAMA_META_TIMEOUT = 3        # /version /tags /ps /show
OLLAMA_UNLOAD_TIMEOUT = 10     # /generate with keep_alive=0
OLLAMA_LOAD_TIMEOUT = 300      # /generate with no prompt — cold-loading a 27B off disk is slow
OLLAMA_DELETE_TIMEOUT = 30     # /delete
OLLAMA_INFER_TIMEOUT = 600     # /chat /generate (non-streaming)
OLLAMA_CREATE_TIMEOUT = 600    # /create (non-streaming)
OLLAMA_PULL_TIMEOUT = 900      # /pull (non-streaming, large downloads)
OLLAMA_STREAM_CONNECT = 5      # streaming endpoints: connect-only timeout
GITHUB_TIMEOUT = 5             # api.github.com release lookups
OLLAMA_UPDATE_TIMEOUT = 300    # official install.sh re-run (binary swap + service restart)

# In-process TTL cache for the cheap metadata calls hammered by every page
# load. Each gunicorn worker caches independently — cross-worker drift is
# bounded by the (short) TTLs and invisible to users. Keyed by
# method+path+body so /show calls cache per-model.
_OLLAMA_TTLS = {
    '/version': 300,   # changes only on Ollama upgrade
    '/tags':    30,    # model list
    '/ps':      5,     # running models — stay fresh
    '/show':    60,    # per-model metadata
}
_OLLAMA_CACHE_MAX = 256
_ollama_cache = {}   # key -> (data, expiry_monotonic)
_ollama_cache_lock = Lock()

def _cache_key(method, path, body):
    if body:
        body_hash = hashlib.md5(
            json.dumps(body, sort_keys=True).encode()
        ).hexdigest()
    else:
        body_hash = ''
    return f"{method}:{path}:{body_hash}"

def cached_ollama(path, method='GET', body=None, ttl=None):
    """Bounded, cached Ollama metadata call.

    Returns the parsed JSON dict on success, or None on timeout / non-200 /
    connection error / JSON-decode error. Callers must handle None by
    rendering a degraded page instead of treating it as success.

    TTL is per-path (see _OLLAMA_TTLS) or `ttl` override. Cache is shared
    across requests within one worker process.
    """
    if ttl is None:
        ttl = _OLLAMA_TTLS.get(path, 30)
    key = _cache_key(method, path, body)
    now = time.monotonic()
    with _ollama_cache_lock:
        hit = _ollama_cache.get(key)
        if hit and hit[1] > now:
            return hit[0]
    try:
        url = OLLAMA_API_URL + path
        headers = ollama_headers()
        if method == 'GET':
            resp = requests.get(url, headers=headers, timeout=OLLAMA_META_TIMEOUT)
        else:
            resp = requests.post(url, headers=headers, json=body or {}, timeout=OLLAMA_META_TIMEOUT)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (requests.Timeout, requests.RequestException, ValueError):
        return None
    with _ollama_cache_lock:
        _ollama_cache[key] = (data, now + ttl)
        # Bounded prune — drop the half closest to expiry when we overflow.
        if len(_ollama_cache) > _OLLAMA_CACHE_MAX:
            sorted_keys = sorted(_ollama_cache.items(), key=lambda kv: kv[1][1])
            for k, _ in sorted_keys[: _OLLAMA_CACHE_MAX // 2]:
                _ollama_cache.pop(k, None)
    return data

def invalidate_ollama_cache(path):
    """Drop all cached entries for a given Ollama API path (any method/body),
    so the next cached_ollama() call is forced to hit Ollama fresh instead of
    serving a stale cached value. Used after actions that change server state
    out-of-band from the cache (e.g. updating the Ollama binary — the /version
    response changes without any request going through cached_ollama itself).
    """
    prefix_variants = (f"GET:{path}:", f"POST:{path}:")
    with _ollama_cache_lock:
        for k in [k for k in _ollama_cache if k.startswith(prefix_variants)]:
            _ollama_cache.pop(k, None)

@app.route('/')
@login_required
def index():
    # Cached: this fires on every page load; without the cache, even the home
    # page hangs while Ollama is mid-generation.
    version_data = cached_ollama('/version')
    current_version = (version_data or {}).get('version', 'Unknown')
    return render_template('index.html', version=current_version)

@app.route('/models')
@login_required
def models():
    try:
        from datetime import datetime
        
        models_data = cached_ollama('/tags')
        if models_data is not None:
            models_list = models_data.get('models', [])
            
            # Calculate how long ago each model was modified
            for model in models_list:
                if model.get('modified_at'):
                    try:
                        # Parse ISO 8601 format
                        modified_time = datetime.fromisoformat(model['modified_at'].replace('Z', '+00:00'))
                        now = datetime.now().astimezone()
                        
                        # Calculate time difference in seconds
                        time_diff = (now - modified_time).total_seconds()
                        
                        if time_diff < 60:
                            model['modified_ago'] = f"{int(time_diff)} seconds ago"
                        elif time_diff < 3600:
                            model['modified_ago'] = f"{int(time_diff // 60)} minutes ago"
                        elif time_diff < 86400:
                            model['modified_ago'] = f"{int(time_diff // 3600)} hours ago"
                        elif time_diff < 604800: # 7 days
                            model['modified_ago'] = f"{int(time_diff // 86400)} days ago"
                        elif time_diff < 2592000: # 30 days
                            model['modified_ago'] = f"{int(time_diff // 604800)} weeks ago"
                        else:
                            model['modified_ago'] = f"{int(time_diff // 2592000)} months ago"
                    except Exception:
                        model['modified_ago'] = 'Unknown'
                else:
                    model['modified_ago'] = 'Unknown'
            
            # Get sort params from request
            sort_by = request.args.get('sort', 'name')
            sort_order = request.args.get('order', 'asc')
            
            # Handle sorting
            if sort_by == 'name':
                models_list.sort(key=lambda x: x.get('name', '').lower(), reverse=(sort_order == 'desc'))
            elif sort_by == 'size':
                models_list.sort(key=lambda x: x.get('size', 0), reverse=(sort_order == 'desc'))
            elif sort_by == 'modified':
                models_list.sort(key=lambda x: x.get('modified_at', ''), reverse=(sort_order == 'desc'))
            
            return render_template('models.html', models=models_list, sort_by=sort_by, sort_order=sort_order)
        else:
            flash("Ollama did not respond in time. Showing an empty model list.", "warning")
            return render_template('models.html', models=[], sort_by='name', sort_order='asc')
    except Exception as e:
        flash(f"Error connecting to Ollama API: {str(e)}", "danger")
        return render_template('models.html', models=[], sort_by='name', sort_order='asc')

@app.route('/model-settings')
@login_required
def model_settings():
    proxy_url = os.getenv('PROXY_BASE_URL', 'http://127.0.0.1:4089').rstrip('/')
    try:
        response = requests.get(f'{proxy_url}/v1/model-settings', timeout=OLLAMA_META_TIMEOUT)
        response.raise_for_status()
        models_with_settings = response.json()['models']
        if not isinstance(models_with_settings, list):
            raise ValueError('Invalid model settings response')
    except (requests.RequestException, ValueError, KeyError) as exc:
        app.logger.warning('Proxy model settings unavailable: %s', exc)
        return render_template('model_settings.html', models=[], unavailable=True)
    return render_template('model_settings.html', models=models_with_settings, unavailable=False)

@app.route('/models/<path:model_name>')
@login_required
def model_detail(model_name):
    model_info = cached_ollama('/show', method='POST', body={"model": model_name})
    if model_info is None:
        flash("Ollama did not respond in time. Try again in a moment.", "warning")
        return redirect(url_for('models'))
    return render_template('model_detail.html', model=model_info, model_name=model_name)

@app.route('/models/delete/<path:model_name>', methods=['POST'])
@login_required
def delete_model(model_name):
    if not current_user.has_permission('manage_models'):
        flash('You do not have permission to manage models.', 'danger')
        return redirect(url_for('models'))
    try:
        response = requests.delete(f"{OLLAMA_API_URL}/delete", headers=ollama_headers(), json={"model": model_name}, timeout=OLLAMA_DELETE_TIMEOUT)
        if response.status_code == 200:
            flash(f"Model {model_name} deleted successfully", "success")
        else:
            flash(f"Error deleting model: {response.status_code}", "danger")
    except requests.Timeout:
        flash("Delete request timed out — Ollama may still be processing it.", "warning")
    except Exception as e:
        flash(f"Error connecting to Ollama API: {str(e)}", "danger")
    return redirect(url_for('models'))

@app.route('/models/update/<path:model_name>')
@login_required
def update_model(model_name):
    if not current_user.has_permission('manage_models'):
        flash('You do not have permission to manage models.', 'danger')
        return redirect(url_for('models'))
    try:
        # Re-pull the model to get the latest version
        response = requests.post(f"{OLLAMA_API_URL}/pull", headers=ollama_headers(), json={"model": model_name, "stream": False}, timeout=OLLAMA_PULL_TIMEOUT)
        if response.status_code == 200:
            flash(f"Model {model_name} updated successfully", "success")
        else:
            flash(f"Error updating model: {response.status_code}", "danger")
    except requests.Timeout:
        flash("Pull timed out after 15 minutes. The download may still complete in the background; check again shortly.", "warning")
    except Exception as e:
        flash(f"Error connecting to Ollama API: {str(e)}", "danger")
    return redirect(url_for('models'))

# ---------------------------------------------------------------------------
# Hugging Face model references
# ---------------------------------------------------------------------------
# Ollama pulls any GGUF repo on the Hub as `hf.co/{owner}/{repo}:{tag}`, where
# the tag is a quantization (Q4_K_M) or a full .gguf filename. People paste
# browser URLs or file names instead, and the Hub answers 401 "Invalid username
# or password" for everything it won't serve anonymously -- private, gated AND
# simply misspelled -- so a typo reads as "this model needs a login". Normalize
# what we can and explain the rest before starting a multi-GB download.
HF_HOSTS = ('hf.co', 'huggingface.co')
HF_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
HF_QUANT_RE = re.compile(r'(?:^|[-_.])((?:I?Q\d[A-Za-z0-9_]*)|BF16|F16|F32)\.gguf$', re.I)
HF_TIMEOUT = 8
# Where Ollama keeps the identity the Hub authenticates for private pulls. The
# systemd install runs as the `ollama` user; a user-run server uses $HOME.
OLLAMA_PUBKEY_PATHS = (
    '/usr/share/ollama/.ollama/id_ed25519.pub',
    os.path.expanduser('~/.ollama/id_ed25519.pub'),
)


def normalize_model_ref(raw):
    """Turn a pasted Hugging Face URL into the reference Ollama expects.

    Only an explicit hf.co/huggingface.co prefix triggers a rewrite: bare
    `owner/model` is a valid Ollama library name too, and rewriting it would
    break ollama.com namespaced pulls.
    """
    ref = (raw or '').strip().strip('"\'')
    if not ref:
        return ''
    ref = re.sub(r'^https?://', '', ref, flags=re.I)
    ref = ref.split('?', 1)[0].split('#', 1)[0].rstrip('/')

    host, sep, path = ref.partition('/')
    if not sep or host.lower() not in HF_HOSTS:
        return ref

    parts = [p for p in path.split('/') if p]
    if len(parts) < 2:
        return ref
    owner, repo = parts[0], parts[1]
    repo, _, tag = repo.partition(':')
    # .../blob/main/file.gguf and .../resolve/main/file.gguf both name a file,
    # and the Hub accepts a full filename as the tag.
    if len(parts) >= 5 and parts[2] in ('blob', 'resolve'):
        tag = parts[-1]
    return f"hf.co/{owner}/{repo}" + (f":{tag}" if tag else '')


def _split_hf_ref(ref):
    """(owner, repo, tag) for an hf.co reference, or None if it isn't one."""
    host, sep, path = (ref or '').partition('/')
    if not sep or host.lower() not in HF_HOSTS:
        return None
    parts = path.split('/')
    if len(parts) != 2:
        return None
    owner, repo = parts
    repo, _, tag = repo.partition(':')
    # Keeps user input out of the URL path we build below.
    if not HF_NAME_RE.match(owner) or not HF_NAME_RE.match(repo):
        return None
    return owner, repo, tag


def hf_preflight(ref):
    """Explain up front why a Hugging Face reference won't pull; None if it will.

    Asks the Hub the same question Ollama is about to: does this manifest
    resolve anonymously? A failure is then diagnosed against the model API so
    the user gets "wrong quant" / "gated" / "no such repo" instead of 401.
    """
    split = _split_hf_ref(ref)
    if split is None:
        return None
    owner, repo, tag = split

    if repo.lower().endswith('.gguf'):
        return (f"'{owner}/{repo}' is a FILE, not a repository. The quantization goes after a "
                f"colon, e.g. hf.co/{owner}/<repo-name>:{repo}")

    try:
        manifest = requests.get(
            f"https://huggingface.co/v2/{owner}/{repo}/manifests/{tag or 'latest'}",
            timeout=HF_TIMEOUT,
        )
    except requests.RequestException:
        return None  # Hub unreachable from here; let the real pull decide
    if manifest.status_code == 200:
        return None

    info = None
    try:
        resp = requests.get(f"https://huggingface.co/api/models/{owner}/{repo}", timeout=HF_TIMEOUT)
        if resp.status_code == 200:
            info = resp.json()
    except (requests.RequestException, ValueError):
        pass

    if info is None:
        return (f"Hugging Face won't serve {owner}/{repo} anonymously (HTTP {manifest.status_code}). "
                "It answers identically for private, gated and misspelled repos, so check the repo id "
                "first — then see 'Private or gated repos' on the pull page.")

    if info.get('gated'):
        return (f"{owner}/{repo} is gated ({info['gated']}). Accept its licence on huggingface.co "
                "using the account that holds this server's Ollama SSH key — see 'Private or gated "
                "repos' on the pull page.")

    ggufs = [s.get('rfilename', '') for s in info.get('siblings', [])
             if s.get('rfilename', '').lower().endswith('.gguf')]
    if not ggufs:
        return (f"{owner}/{repo} has no GGUF files, so Ollama can't pull it. Look for a -GGUF "
                "conversion of the model instead.")

    quants = []
    for name in ggufs:
        match = HF_QUANT_RE.search(name)
        quant = match.group(1) if match else name
        if quant not in quants:
            quants.append(quant)
    # Suggest Q4_K_M when it exists: alphabetical order would otherwise point at
    # F16, which is several times the download for no practical gain here.
    suggestion = next((q for q in quants if q.upper() == 'Q4_K_M'), quants[0])
    return (f"{owner}/{repo} has no '{tag or 'latest'}' build. Available: {', '.join(quants[:12])}. "
            f"Try hf.co/{owner}/{repo}:{suggestion}")


def ollama_public_key():
    """Ollama's public key, which the Hub matches to an account for private pulls."""
    for path in OLLAMA_PUBKEY_PATHS:
        try:
            with open(path) as handle:
                key = handle.read().strip()
        except OSError:
            continue
        if key:
            return key
    return None


@app.route('/pull', methods=['GET', 'POST'])
@login_required
def pull_model():
    if not current_user.has_permission('manage_models'):
        flash('You do not have permission to manage models.', 'danger')
        return redirect(url_for('models'))
    if request.method == 'POST':
        model_name = normalize_model_ref(request.form.get('model_name'))
        problem = hf_preflight(model_name)
        if problem:
            flash(problem, "danger")
            return redirect(url_for('pull_model'))
        try:
            response = requests.post(f"{OLLAMA_API_URL}/pull", headers=ollama_headers(), json={"model": model_name, "stream": False}, timeout=OLLAMA_PULL_TIMEOUT)
            if response.status_code == 200:
                flash(f"Model {model_name} pulled successfully", "success")
            else:
                flash(f"Error pulling model: {response.status_code}", "danger")
            return redirect(url_for('models'))
        except requests.Timeout:
            flash("Pull timed out after 15 minutes. The download may still complete in the background.", "warning")
            return redirect(url_for('models'))
        except Exception as e:
            flash(f"Error connecting to Ollama API: {str(e)}", "danger")
            return redirect(url_for('pull_model'))
    return render_template(
        'pull_model.html',
        ollama_ssh_key=ollama_public_key() if current_user.is_admin else None,
    )


@app.route('/pull/stream', methods=['POST'])
@login_required
def pull_model_stream():
    """Relay Ollama's pull progress to the browser as NDJSON, one line per update.

    The plain /pull route above posts with stream=False, so Ollama returns
    nothing until the entire download completes -- which is why that page shows
    no progress. Ollama emits {status, digest, total, completed} lines while
    downloading; this just forwards them so the client can render a bar.
    """
    raw_name = (request.form.get('model_name') or '').strip()
    model_name = normalize_model_ref(raw_name)
    if not model_name:
        return jsonify({'error': 'model_name is required'}), 400

    if not current_user.has_permission('manage_models'):
        return jsonify({'error': 'You do not have permission to manage models.'}), 403

    # The client only surfaces errors carried inside the stream (a non-200 here
    # renders as a bare "Request failed"), so report preflight failures as the
    # first NDJSON line instead.
    problem = hf_preflight(model_name)
    if problem:
        return Response(json.dumps({'error': problem}) + '\n', mimetype='application/x-ndjson')

    def generate():
        if model_name != raw_name:
            yield json.dumps({'status': f'Resolved to {model_name}'}) + '\n'
        try:
            with requests.post(
                f"{OLLAMA_API_URL}/pull",
                headers=ollama_headers(),
                json={"model": model_name, "stream": True},
                stream=True,
                timeout=OLLAMA_PULL_TIMEOUT,
            ) as resp:
                if resp.status_code != 200:
                    yield json.dumps({'error': f'Ollama returned HTTP {resp.status_code}'}) + '\n'
                    return
                # decode_unicode is unreliable here: Ollama sends
                # application/x-ndjson with no charset, so requests leaves the
                # lines as bytes and the concat below would blow up.
                for line in resp.iter_lines():
                    if not line:
                        continue
                    if isinstance(line, bytes):
                        line = line.decode('utf-8', 'replace')
                    yield line + '\n'
        except requests.Timeout:
            yield json.dumps({'error': 'Pull timed out. The download may still be running on the server.'}) + '\n'
        except Exception as exc:
            yield json.dumps({'error': str(exc)}) + '\n'

    return Response(
        generate(),
        mimetype='application/x-ndjson',
        # X-Accel-Buffering: nginx fronts this host and would otherwise buffer
        # the whole response, defeating the streaming entirely.
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )

@app.route('/create', methods=['GET'])
@login_required
def create_model_page():
    if not current_user.has_permission('manage_models'):
        flash('You do not have permission to manage models.', 'danger')
        return redirect(url_for('models'))
    tags_data = cached_ollama('/tags')
    if tags_data is None:
        flash("Ollama did not respond in time. Showing an empty model list.", "warning")
        return render_template('create_model.html', models=[])
    return render_template('create_model.html', models=tags_data.get('models', []))

@app.route('/create-model', methods=['GET', 'POST'])
@login_required
def create_model():
    # For GET requests, redirect to the create model page
    if request.method == 'GET':
        return redirect(url_for('create_model_page'))

    if not current_user.has_permission('manage_models'):
        if request.content_type and 'application/json' in request.content_type:
            return jsonify({'error': 'You do not have permission to manage models.'}), 403
        flash('You do not have permission to manage models.', 'danger')
        return redirect(url_for('models'))

    # Handle POST requests
    # Handle both form data and JSON data
    if request.content_type and 'application/json' in request.content_type:
        # JSON request (from streaming)
        data = request.get_json()
        model_name = data.get('model_name') if data else None
        creation_method = data.get('creation_method') if data else None
        system_prompt = data.get('system_prompt') if data else None
        template = data.get('template') if data else None
        stream = data.get('stream') == 'on' if data else False
        from_model = data.get('from_model') if data else None
        quantize = data.get('quantize') if data else None
    else:
        # Form data request (non-streaming)
        model_name = request.form.get('model_name')
        creation_method = request.form.get('creation_method')
        system_prompt = request.form.get('system_prompt')
        template = request.form.get('template')
        stream = 'stream' in request.form
        from_model = request.form.get('from_model')
        quantize = request.form.get('quantize')
    
    if not model_name:
        flash("Model name is required", "danger")
        return redirect(url_for('create_model_page'))
    
    if not creation_method:
        flash("Creation method is required", "danger")
        return redirect(url_for('create_model_page'))
    
    # Prepare the payload
    payload = {
        "model": model_name,
        "stream": stream
    }
    
    # Add optional parameters if provided
    if system_prompt:
        payload["system"] = system_prompt
    
    if template:
        payload["template"] = template
    
    # Handle creation method
    if creation_method == 'from_model':
        if not from_model:
            flash("Base model is required when creating from an existing model", "danger")
            return redirect(url_for('create_model_page'))
        
        payload["from"] = from_model
        
        # Add quantize if specified
        if quantize:
            payload["quantize"] = quantize
    
    # Handle file-based creation (placeholder for future implementation)
    elif creation_method == 'from_files':
        flash("Creating models from files is not yet implemented in the web interface", "warning")
        return redirect(url_for('create_model_page'))
    
    try:
        if stream:
            return Response(stream_create_model(payload), mimetype='text/event-stream')
        else:
            # Call Ollama API to create the model (non-streaming)
            response = requests.post(f"{OLLAMA_API_URL}/create", headers=ollama_headers(), json=payload, timeout=OLLAMA_CREATE_TIMEOUT)
            
            if response.status_code == 200:
                flash(f"Model {model_name} created successfully", "success")
            else:
                flash(f"Error creating model: {response.status_code} - {response.text}", "danger")
            
            return redirect(url_for('models'))
    except requests.Timeout:
        flash("Create request timed out after 10 minutes. The model may still be building — refresh the model list shortly.", "warning")
        return redirect(url_for('models'))
    except Exception as e:
        flash(f"Error connecting to Ollama API: {str(e)}", "danger")
        return redirect(url_for('create_model_page'))

def stream_create_model(payload):
    """Stream the model creation process from Ollama API."""
    try:
        # Make streaming request to Ollama API
        response = requests.post(
            f"{OLLAMA_API_URL}/create",
            headers=ollama_headers(),
            json=payload,
            stream=True,
            timeout=(OLLAMA_STREAM_CONNECT, None)
        )
        
        if response.status_code != 200:
            error_msg = f"Error from Ollama API: {response.status_code}"
            if hasattr(response, 'text'):
                error_msg += f" - {response.text}"
            yield f"data: {json.dumps({'error': error_msg})}\n\n"
            return
        
        for line in response.iter_lines():
            if line:
                try:
                    # Forward the API response directly to the client
                    yield f"data: {line.decode('utf-8')}\n\n"
                except Exception:
                    continue
        
        # Send a final success message
        yield f"data: {json.dumps({'done': True, 'message': 'Model created successfully'})}\n\n"
        
    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"

@app.route('/running-models')
@login_required
def running_models():
    try:
        from datetime import datetime
        
        models_data = cached_ollama('/ps')
        if models_data is not None:
            models = models_data.get('models', [])
            
            # Add expires_in calculation
            for model in models:
                if model.get('expires_at'):
                    # Check if it's the "never expires" sentinel value
                    if model['expires_at'].startswith('0001-01-01'):
                        model['expires_in'] = 'Never'
                    else:
                        # Parse the expiration time
                        try:
                            # Parse ISO 8601 format
                            expiry_time = datetime.fromisoformat(model['expires_at'].replace('Z', '+00:00'))
                            now = datetime.now().astimezone()
                            
                            # Calculate time difference in seconds
                            time_diff = (expiry_time - now).total_seconds()
                            
                            if time_diff <= 0:
                                model['expires_in'] = 'Expired'
                            elif time_diff < 60:
                                model['expires_in'] = f"{int(time_diff)} seconds"
                            elif time_diff < 3600:
                                model['expires_in'] = f"{int(time_diff // 60)} minutes"
                            elif time_diff < 86400:
                                model['expires_in'] = f"{int(time_diff // 3600)} hours"
                            else:
                                model['expires_in'] = f"{int(time_diff // 86400)} days"
                        except Exception:
                            model['expires_in'] = 'Unknown'
                else:
                    model['expires_in'] = 'Never'
            
            return render_template('running_models.html', models=models)
        else:
            flash("Ollama did not respond in time. Try again in a moment.", "warning")
            return render_template('running_models.html', models=[])
    except Exception as e:
        flash(f"Error connecting to Ollama API: {str(e)}", "danger")
        return render_template('running_models.html', models=[])

@app.route('/models/unload/<path:model_name>', methods=['POST'])
@login_required
def unload_model(model_name):
    if not current_user.has_permission('manage_models'):
        flash('You do not have permission to manage models.', 'danger')
        return redirect(url_for('models'))
    try:
        # Unload model by setting keep_alive to 0
        payload = {
            "model": model_name,
            "prompt": "",
            "keep_alive": "0"
        }
        response = requests.post(f"{OLLAMA_API_URL}/generate", headers=ollama_headers(), json=payload, timeout=OLLAMA_UNLOAD_TIMEOUT)

        if response.status_code == 200:
            flash(f"Model {model_name} unloaded successfully", "success")
        else:
            flash(f"Error unloading model: {response.status_code}", "danger")
    except requests.Timeout:
        flash("Unload request timed out. The model may still be unloading in the background.", "warning")
    except Exception as e:
        flash(f"Error connecting to Ollama API: {str(e)}", "danger")

    return redirect(url_for('running_models'))


# Offered in the load/keep-alive UI. Ollama accepts seconds as a number or a Go
# duration string; -1 keeps the model resident until something evicts it.
KEEP_ALIVE_CHOICES = [('5m', '5 minutes'), ('30m', '30 minutes'), ('1h', '1 hour'),
                      ('4h', '4 hours'), ('8h', '8 hours'), ('-1', 'Until unloaded')]
DEFAULT_KEEP_ALIVE = '4h'
app.jinja_env.globals['KEEP_ALIVE_CHOICES'] = KEEP_ALIVE_CHOICES
app.jinja_env.globals['DEFAULT_KEEP_ALIVE'] = DEFAULT_KEEP_ALIVE


@app.route('/models/load/<path:model_name>', methods=['POST'])
@login_required
def load_model(model_name):
    if not current_user.has_permission('manage_models'):
        flash('You do not have permission to manage models.', 'danger')
        return redirect(url_for('models'))

    keep_alive = request.form.get('keep_alive', DEFAULT_KEEP_ALIVE)
    if keep_alive not in dict(KEEP_ALIVE_CHOICES):
        keep_alive = DEFAULT_KEEP_ALIVE
    try:
        ka = int(keep_alive)        # '-1' must go as a number; durations stay strings
    except ValueError:
        ka = keep_alive

    try:
        # No prompt: Ollama loads the model into VRAM and returns without generating.
        payload = {"model": model_name, "keep_alive": ka}
        response = requests.post(f"{OLLAMA_API_URL}/generate", headers=ollama_headers(),
                                 json=payload, timeout=OLLAMA_LOAD_TIMEOUT)
        if response.status_code == 200:
            label = dict(KEEP_ALIVE_CHOICES)[keep_alive]
            flash(f"Model {model_name} loaded — staying resident for {label.lower()}. "
                  "An agent request will reset this to the proxy's own keep-alive.", "success")
        else:
            flash(f"Error loading model: {response.status_code}", "danger")
    except requests.Timeout:
        flash("Load request timed out. The model may still be loading in the background.", "warning")
    except Exception as e:
        flash(f"Error connecting to Ollama API: {str(e)}", "danger")

    return redirect(request.referrer or url_for('running_models'))


@app.route('/chat')
@login_required
def chat():
    # Get available models for the dropdown
    tags_data = cached_ollama('/tags')
    if tags_data is None:
        flash("Ollama did not respond in time. Model list may be empty.", "warning")
        return render_template('chat.html', models=[])
    return render_template('chat.html', models=tags_data.get('models', []))

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    data = request.get_json()
    model = data.get('model')
    message = data.get('message')
    conversation = data.get('conversation', [])
    stream = data.get('stream', False)
    
    # Format message for Ollama API
    messages = conversation + [{"role": "user", "content": message}]
    
    if stream:
        return stream_chat_response(model, messages)
    
    try:
        response = requests.post(
            f"{OLLAMA_API_URL}/chat",
            headers=ollama_headers(),
            json={"model": model, "messages": messages, "stream": False, "keep_alive": -1},
            timeout=OLLAMA_INFER_TIMEOUT
        )
        
        if response.status_code == 200:
            result = response.json()
            # Extract assistant's message from the response
            assistant_message = result.get('message', {}).get('content', '')
            return jsonify({
                "response": assistant_message,
                "conversation": messages + [{"role": "assistant", "content": assistant_message}]
            })
        else:
            return jsonify({"error": f"Error from Ollama API: {response.status_code}"}), 500
    except requests.Timeout:
        return jsonify({"error": "Ollama did not respond within the timeout. The model may be loading or busy."}), 504
    except Exception as e:
        return jsonify({"error": f"Error connecting to Ollama API: {str(e)}"}), 500

def stream_chat_response(model, messages):
    def generate():
        assistant_message = ""
        try:
            # Make streaming request to Ollama API
            response = requests.post(
                f"{OLLAMA_API_URL}/chat",
                headers=ollama_headers(),
                json={"model": model, "messages": messages, "stream": True, "keep_alive": -1},
                stream=True,
                timeout=(OLLAMA_STREAM_CONNECT, None)
            )
            
            if response.status_code != 200:
                error_msg = f"Error from Ollama API: {response.status_code}"
                yield f"data: {json.dumps({'error': error_msg})}\n\n"
                return
                
            for line in response.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line)
                        if 'message' in chunk and 'content' in chunk['message']:
                            # Get the content delta
                            content_delta = chunk['message']['content']
                            assistant_message += content_delta
                            yield f"data: {json.dumps({'delta': content_delta, 'content': assistant_message})}\n\n"
                    except json.JSONDecodeError:
                        continue
            
            # Send the final message with the complete conversation
            final_conversation = messages + [{"role": "assistant", "content": assistant_message}]
            yield f"data: {json.dumps({'done': True, 'conversation': final_conversation})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            
    return app.response_class(generate(), mimetype='text/event-stream')

@app.route('/generate')
@login_required
def generate():
    # Get available models for the dropdown
    tags_data = cached_ollama('/tags')
    if tags_data is None:
        flash("Ollama did not respond in time. Model list may be empty.", "warning")
        return render_template('generate.html', models=[])
    return render_template('generate.html', models=tags_data.get('models', []))

@app.route('/api/generate', methods=['POST'])
@login_required
def api_generate():
    data = request.get_json()
    model = data.get('model')
    prompt = data.get('prompt')
    system = data.get('system', '')
    options = data.get('options', {})
    
    # Build request payload
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": -1
    }
    
    if system:
        payload["system"] = system
    
    # Convert string values to appropriate types for Ollama API
    if options:
        processed_options = {}
        for key, value in options.items():
            if key in ['num_ctx', 'num_predict', 'num_keep', 'seed', 'top_k']:
                # Convert to integer
                try:
                    processed_options[key] = int(value) if value != '' and value is not None else None
                except (ValueError, TypeError):
                    continue
            elif key in ['temperature', 'top_p', 'repeat_penalty', 'typical_p']:
                # Convert to float
                try:
                    processed_options[key] = float(value) if value != '' and value is not None else None
                except (ValueError, TypeError):
                    continue
            elif key in ['repeat_last_n']:
                # Convert to integer, handle -1 for no limit
                try:
                    processed_options[key] = int(value) if value != '' and value is not None else None
                except (ValueError, TypeError):
                    continue
            elif value != '' and value is not None:  # For other string options
                processed_options[key] = value
        
        # Only add options if we have valid ones
        if processed_options:
            payload["options"] = processed_options
    
    try:
        response = requests.post(f"{OLLAMA_API_URL}/generate", headers=ollama_headers(), json=payload, timeout=OLLAMA_INFER_TIMEOUT)
        
        if response.status_code == 200:
            result = response.json()
            return jsonify(result)
        else:
            return jsonify({"error": f"Error from Ollama API: {response.status_code}"}), 500
    except requests.Timeout:
        return jsonify({"error": "Ollama did not respond within the timeout. The model may be loading or busy."}), 504
    except Exception as e:
        return jsonify({"error": f"Error connecting to Ollama API: {str(e)}"}), 500

@app.route('/help')
@login_required
def help_page():
    return render_template('help.html')

@app.route('/model_help')
def model_help():
    return render_template('model_help.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/version')
@login_required
def version():
    current_version = "Unknown"
    latest_version = "Unknown"
    update_available = False
    release_date = "Unknown"
    changelog_markdown = None

    # Get current version from Ollama API (cached)
    version_data = cached_ollama('/version')
    if version_data:
        current_version = version_data.get('version', 'Unknown')
    else:
        flash("Ollama did not respond when fetching version.", "warning")

    # Get latest version from GitHub releases
    try:
        github_response = requests.get("https://api.github.com/repos/ollama/ollama/releases/latest", timeout=GITHUB_TIMEOUT)
        if github_response.status_code == 200:
            github_data = github_response.json()
            latest_version = github_data.get('tag_name', 'Unknown')
            if latest_version.startswith('v'):
                latest_version = latest_version[1:]  # Remove 'v' prefix if present

            # Get release date
            if github_data.get('published_at'):
                from datetime import datetime
                try:
                    published_date = datetime.fromisoformat(github_data['published_at'].replace('Z', '+00:00'))
                    release_date = published_date.strftime('%B %d, %Y')
                except:
                    release_date = "Unknown"

            # Get raw markdown from release body and convert to HTML
            if github_data.get('body'):
                try:
                    # Convert markdown to HTML
                    changelog_markdown = markdown.markdown(github_data['body'], extensions=['extra'])
                except Exception:
                    # If conversion fails, use the raw markdown
                    changelog_markdown = github_data['body']

            # Check if update is available
            if current_version != "Unknown" and latest_version != "Unknown":
                current_parts = current_version.split('.')
                latest_parts = latest_version.split('.')

                # Compare version numbers
                for i in range(max(len(current_parts), len(latest_parts))):
                    current_num = int(current_parts[i]) if i < len(current_parts) else 0
                    latest_num = int(latest_parts[i]) if i < len(latest_parts) else 0

                    if latest_num > current_num:
                        update_available = True
                        break
                    elif current_num > latest_num:
                        break

        else:
            flash(f"Error fetching latest version from GitHub: {github_response.status_code}", "info")
    except Exception as e:
        flash(f"Error connecting to GitHub API: {str(e)}", "info")

    return render_template('version.html',
                          version=current_version,
                          latest_version=latest_version,
                          update_available=update_available,
                          release_date=release_date,
                          changelog_markdown=changelog_markdown)

@app.route('/admin/ollama/update', methods=['POST'])
@login_required
def update_ollama():
    """Re-run Ollama's official install script on THIS server to update the
    binary in place, then restart ollama.service. This is the standard,
    Ollama-documented way to update a Linux install (the script detects an
    existing install and upgrades it; it also handles the systemd restart
    itself, invoking sudo internally if not already root).

    Admin-only: this restarts a shared service used by every user currently
    running an inference request, and executes a remote install script with
    root privileges (via passwordless sudo for the service account).
    """
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('version'))

    try:
        result = subprocess.run(
            ['sh', '-c', 'curl -fsSL https://ollama.com/install.sh | sh'],
            capture_output=True, text=True, timeout=OLLAMA_UPDATE_TIMEOUT,
        )
        app.logger.info(
            'ollama update by %s: exit=%s\n%s',
            current_user.username, result.returncode, (result.stdout + result.stderr).strip(),
        )
        # Flash messages render as a single line in the UI (no <pre>/newline
        # handling), so keep this to a short status — full installer output
        # isn't dumped here, only the failure case's last line (the part
        # most likely to explain what went wrong).
        if result.returncode == 0:
            # The /version cache entry is now stale (Ollama's version changed
            # without going through cached_ollama) — drop it so the version
            # page reflects the new binary immediately instead of the old
            # cached value for up to 5 more minutes.
            invalidate_ollama_cache('/version')
            flash('Ollama update finished successfully — check the version below.', 'success')
        else:
            last_line = (result.stdout + result.stderr).strip().splitlines()[-1:] or ['(no output)']
            flash(f'Ollama update FAILED (exit code {result.returncode}): {last_line[0][:300]}', 'danger')
    except subprocess.TimeoutExpired:
        flash(
            f'Update timed out after {OLLAMA_UPDATE_TIMEOUT}s. It may still be running in the '
            'background (large downloads can be slow) — check the version page again shortly.',
            'warning',
        )
    except Exception as e:
        flash(f'Error running Ollama update: {e}', 'danger')

    return redirect(url_for('version'))

# The parse_github_release_notes function is no longer used since we're displaying raw markdown

@app.route('/api/check-updates')
def check_updates():
    """API endpoint to check for available updates"""
    try:
        # Get current version (cached)
        version_data = cached_ollama('/version')
        if version_data is None:
            return jsonify({"error": "Ollama is unreachable or busy."}), 504
        current_version = version_data.get('version', 'Unknown')
        
        # Get latest version from GitHub
        try:
            github_response = requests.get("https://api.github.com/repos/ollama/ollama/releases/latest", timeout=GITHUB_TIMEOUT)
            if github_response.status_code == 200:
                github_data = github_response.json()
                latest_version = github_data.get('tag_name', 'Unknown')
                if latest_version.startswith('v'):
                    latest_version = latest_version[1:]  # Remove 'v' prefix if present
                
                # Check if update is available
                update_available = False
                if current_version != "Unknown" and latest_version != "Unknown":
                    current_parts = current_version.split('.')
                    latest_parts = latest_version.split('.')
                    
                    # Compare version numbers
                    for i in range(max(len(current_parts), len(latest_parts))):
                        current_num = int(current_parts[i]) if i < len(current_parts) else 0
                        latest_num = int(latest_parts[i]) if i < len(latest_parts) else 0
                        
                        if latest_num > current_num:
                            update_available = True
                            break
                        elif current_num > latest_num:
                            break
                
                # Get release date
                release_date = "Unknown"
                if github_data.get('published_at'):
                    from datetime import datetime
                    try:
                        published_date = datetime.fromisoformat(github_data['published_at'].replace('Z', '+00:00'))
                        release_date = published_date.strftime('%B %d, %Y')
                    except:
                        pass
                
                # Get download URLs
                assets = github_data.get('assets', [])
                download_urls = {}
                for asset in assets:
                    name = asset.get('name', '')
                    if name.endswith('.dmg'):
                        download_urls['macos'] = asset.get('browser_download_url')
                    elif name.endswith('.msi'):
                        download_urls['windows'] = asset.get('browser_download_url')
                    elif 'linux' in name.lower() and name.endswith('.tar.gz'):
                        download_urls['linux'] = asset.get('browser_download_url')
                
                return jsonify({
                    "current_version": current_version,
                    "latest_version": latest_version,
                    "update_available": update_available,
                    "release_date": release_date,
                    "download_urls": download_urls,
                    "release_url": github_data.get('html_url')
                })
            else:
                return jsonify({"error": f"Error fetching GitHub data: {github_response.status_code}"}), 500
        except Exception as e:
            return jsonify({"error": f"Error checking for updates: {str(e)}"}), 500
    
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host=HOST, port=PORT, debug=True)
