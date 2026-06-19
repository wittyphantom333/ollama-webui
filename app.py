from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, Response
from flask_login import LoginManager, login_required, current_user
import requests
import json
import os
import time
import hashlib
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
OLLAMA_DELETE_TIMEOUT = 30     # /delete
OLLAMA_INFER_TIMEOUT = 600     # /chat /generate (non-streaming)
OLLAMA_CREATE_TIMEOUT = 600    # /create (non-streaming)
OLLAMA_PULL_TIMEOUT = 900      # /pull (non-streaming, large downloads)
OLLAMA_STREAM_CONNECT = 5      # streaming endpoints: connect-only timeout
GITHUB_TIMEOUT = 5             # api.github.com release lookups

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

@app.route('/pull', methods=['GET', 'POST'])
@login_required
def pull_model():
    if request.method == 'POST':
        model_name = request.form.get('model_name')
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
    return render_template('pull_model.html')

@app.route('/create', methods=['GET'])
@login_required
def create_model_page():
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
