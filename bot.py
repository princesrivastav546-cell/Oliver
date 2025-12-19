import os
import logging
import asyncio
import subprocess
import signal
import sys
import json
import threading
import shutil
import time
import secrets
from urllib.parse import quote, unquote
from pathlib import Path

import psutil
from flask import Flask, request, render_template_string, jsonify, abort
from telegram import (
    Update,
    ReplyKeyboardMarkup,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    WebAppInfo,
)
from telegram.ext import (
    ApplicationBuilder,
    ContextTypes,
    CommandHandler,
    MessageHandler,
    filters,
    ConversationHandler,
    CallbackQueryHandler,
)

# ================= CONFIGURATION =================
TOKEN = os.environ.get("TOKEN")
ADMIN_ID = int(os.environ.get("ADMIN_ID", "0"))
BASE_URL = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8080")

UPLOAD_DIR = "scripts"
os.makedirs(UPLOAD_DIR, exist_ok=True)

USERS_FILE = "allowed_users.json"
OWNERSHIP_FILE = "ownership.json"

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

running_processes = {}  # {target_id: {"process": Popen, "log": log_path, "started_at": epoch}}

# ================= ID HELPERS =================
def is_user_file_id(tid: str) -> bool:
    # u<uid>|filename.ext
    return (
        isinstance(tid, str)
        and tid.startswith("u")
        and ("|" in tid)
        and tid.count("|") == 1
        and tid.split("|", 1)[0][1:].isdigit()
    )

def is_repo_id(tid: str) -> bool:
    # repoName|path/to/file.ext (not user file id)
    return ("|" in tid) and (not is_user_file_id(tid))

def safe_q(s: str) -> str:
    return quote(s, safe="")

def safe_status_url(tid: str, key: str) -> str:
    return f"{BASE_URL}/status?script={safe_q(tid)}&key={safe_q(key)}"

# ================= DATA STORE =================
def _read_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _write_json(path: str, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)

def get_allowed_users():
    return _read_json(USERS_FILE, [])

def save_allowed_user(uid: int) -> bool:
    users = get_allowed_users()
    if uid not in users:
        users.append(uid)
        _write_json(USERS_FILE, users)
        return True
    return False

def remove_allowed_user(uid: int) -> bool:
    users = get_allowed_users()
    if uid in users:
        users.remove(uid)
        _write_json(USERS_FILE, users)
        return True
    return False

def load_ownership():
    return _read_json(OWNERSHIP_FILE, {})

def save_ownership_record(target_id: str, record: dict):
    data = load_ownership()
    data[target_id] = record
    _write_json(OWNERSHIP_FILE, data)

def delete_ownership(target_id: str):
    data = load_ownership()
    if target_id in data:
        del data[target_id]
        _write_json(OWNERSHIP_FILE, data)

def get_owner(target_id: str):
    return load_ownership().get(target_id, {}).get("owner")

def get_app_key(target_id: str):
    return load_ownership().get(target_id, {}).get("key")

def set_last_run(target_id: str, value: bool):
    data = load_ownership()
    if target_id in data:
        data[target_id]["last_run"] = bool(value)
        _write_json(OWNERSHIP_FILE, data)

# ================= PATH RESOLUTION =================
def resolve_paths(target_id: str):
    """
    target_id formats:
    1) user file: u<uid>|filename.py
       work_dir: scripts/<uid>/
       env:      scripts/<uid>/.env
       req:      scripts/<uid>/requirements.txt
    2) repo: repoName|path/to/file.py
       work_dir: scripts/<repoName>/
       env:      scripts/<repoName>/.env
       req:      scripts/<repoName>/requirements.txt
    3) legacy: filename.py (scripts/filename.py)
    """
    if is_user_file_id(target_id):
        u, filename = target_id.split("|", 1)
        uid = u[1:]
        work_dir = os.path.join(UPLOAD_DIR, uid)
        script_path = filename
        env_path = os.path.join(work_dir, ".env")
        req_path = os.path.join(work_dir, "requirements.txt")
        full_script_path = os.path.join(work_dir, script_path)
        return work_dir, script_path, env_path, req_path, full_script_path

    if is_repo_id(target_id):
        repo, file = target_id.split("|", 1)
        work_dir = os.path.join(UPLOAD_DIR, repo)
        script_path = file
        env_path = os.path.join(work_dir, ".env")
        req_path = os.path.join(work_dir, "requirements.txt")
        full_script_path = os.path.join(work_dir, script_path)
        return work_dir, script_path, env_path, req_path, full_script_path

    work_dir = UPLOAD_DIR
    script_path = target_id
    env_path = os.path.join(work_dir, f"{target_id}.env")
    req_path = os.path.join(work_dir, f"{target_id}_req.txt")
    full_script_path = os.path.join(work_dir, target_id)
    return work_dir, script_path, env_path, req_path, full_script_path

# ================= SECURITY HELPERS =================
def within_dir(base: str, p: str) -> bool:
    base_abs = os.path.abspath(base)
    p_abs = os.path.abspath(p)
    return p_abs.startswith(base_abs + os.sep) or p_abs == base_abs

def list_files_safe(work_dir: str, max_files: int = 400):
    out = []
    base = Path(work_dir)
    if not base.exists():
        return out
    for path in base.rglob("*"):
        if len(out) >= max_files:
            break
        if path.is_file():
            rel = str(path.relative_to(base))
            # block giant/unsafe folders
            if rel.startswith(".git/") or rel.startswith("node_modules/"):
                continue
            if rel.endswith(".pyc"):
                continue
            out.append(rel)
    out.sort()
    return out

# ================= COMMAND DETECTION =================
def resolve_run_command(work_dir: str, script_rel: str | None):
    """
    Auto-detects best command:
    - If package.json exists and has scripts.start and (script_rel is None OR script_rel endswith .js):
        npm start
    - If script_rel given:
        by extension: node/bash/python
    - If script_rel not given:
        tries common entry files inside work_dir
    """
    pkg = os.path.join(work_dir, "package.json")
    if os.path.exists(pkg):
        try:
            with open(pkg, "r", encoding="utf-8") as f:
                pkgj = json.load(f)
            scripts = pkgj.get("scripts", {})
            if "start" in scripts and (script_rel is None or script_rel.endswith(".js")):
                return ["npm", "start"], None
        except Exception:
            pass

    def by_ext(path_rel: str):
        ext = path_rel.split(".")[-1].lower()
        if ext == "js":
            return ["node", path_rel]
        if ext == "sh":
            return ["bash", path_rel]
        return ["python", "-u", path_rel]

    if script_rel:
        return by_ext(script_rel), script_rel

    # no script provided: pick common entry
    candidates = [
        "main.py", "app.py", "server.py", "bot.py",
        "index.js", "server.js",
        "start.sh",
    ]
    for c in candidates:
        if os.path.exists(os.path.join(work_dir, c)):
            return by_ext(c), c

    # fallback: first runnable file
    for f in list_files_safe(work_dir, max_files=200):
        if f.endswith((".py", ".js", ".sh")):
            return by_ext(f), f

    return None, None

# ================= PROCESS MANAGEMENT =================
def build_env(env_path: str):
    custom_env = os.environ.copy()
    if os.path.exists(env_path):
        with open(env_path, encoding="utf-8", errors="ignore") as f:
            for l in f:
                l = l.strip()
                if not l or l.startswith("#") or "=" not in l:
                    continue
                k, v = l.split("=", 1)
                custom_env[k.strip()] = v.strip().strip('"').strip("'")
    return custom_env

def restart_process_background(target_id: str):
    work_dir, script_path, env_path, _, _ = resolve_paths(target_id)

    # stop previous
    if target_id in running_processes:
        try:
            os.killpg(os.getpgid(running_processes[target_id]["process"].pid), signal.SIGTERM)
        except Exception:
            pass

    # decide command
    record = load_ownership().get(target_id, {})
    entry = record.get("entry")  # may be None
    if is_repo_id(target_id):
        # for repo mode, entry can be record["entry"] (relative file)
        cmd, chosen = resolve_run_command(work_dir, entry)
    elif is_user_file_id(target_id):
        cmd, chosen = resolve_run_command(work_dir, script_path)
    else:
        cmd, chosen = resolve_run_command(work_dir, script_path)

    if not cmd:
        logger.error("No runnable entry found.")
        return

    # save chosen entry for next auto-start (only for repo)
    if is_repo_id(target_id):
        data = load_ownership()
        if target_id in data:
            data[target_id]["entry"] = chosen
            _write_json(OWNERSHIP_FILE, data)

    os.makedirs(work_dir, exist_ok=True)
    custom_env = build_env(env_path)

    # log file per app
    log_path = os.path.join(UPLOAD_DIR, f"{target_id.replace('|','_')}.log")
    log_file = open(log_path, "a", encoding="utf-8")  # append keeps history

    try:
        proc = subprocess.Popen(
            cmd,
            env=custom_env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=work_dir,
            preexec_fn=os.setsid,
        )
        running_processes[target_id] = {"process": proc, "log": log_path, "started_at": time.time()}
        set_last_run(target_id, True)
    except Exception as e:
        logger.error(f"Failed to start: {e}")

def stop_process(target_id: str):
    if target_id in running_processes:
        try:
            os.killpg(os.getpgid(running_processes[target_id]["process"].pid), signal.SIGTERM)
        except Exception:
            pass
        try:
            del running_processes[target_id]
        except Exception:
            pass
    set_last_run(target_id, False)

def clear_log(target_id: str):
    log_path = os.path.join(UPLOAD_DIR, f"{target_id.replace('|','_')}.log")
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("")
    except Exception:
        pass

def auto_start_last_run_apps():
    data = load_ownership()
    for tid, meta in data.items():
        if meta.get("last_run") is True:
            try:
                restart_process_background(tid)
            except Exception as e:
                logger.error(f"Auto-start failed for {tid}: {e}")

# ================= DEP INSTALL =================
async def install_dependencies(work_dir: str, update: Update):
    msg = None
    try:
        req = os.path.join(work_dir, "requirements.txt")
        if os.path.exists(req):
            msg = await update.message.reply_text("⏳ Installing Python Deps...")
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "pip", "install", "-r", "requirements.txt",
                cwd=work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

        pkg = os.path.join(work_dir, "package.json")
        if os.path.exists(pkg):
            if not msg:
                msg = await update.message.reply_text("⏳ Installing Node Deps...")
            else:
                await msg.edit_text("⏳ Installing Node Deps...")
            proc = await asyncio.create_subprocess_exec(
                "npm", "install",
                cwd=work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

        if msg:
            await msg.edit_text("✅ Dependencies Installed!")
    except Exception as e:
        if msg:
            await msg.edit_text(f"❌ Error: {e}")

# ================= TELEGRAM DECORATORS =================
def restricted(func):
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        uid = update.effective_user.id
        if uid != ADMIN_ID and uid not in get_allowed_users():
            await update.message.reply_text("⛔ Access Denied.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapped

def super_admin_only(func):
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        if update.effective_user.id != ADMIN_ID:
            await update.message.reply_text("⛔ Super Admin Only.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapped

# ================= KEYBOARDS =================
def main_menu_keyboard(uid: int):
    rows = [
        ["📤 Upload File", "🌐 Clone from Git"],
        ["📂 My Hosted Apps", "📊 Server Stats"],
        ["🆘 Help"],
    ]
    if uid == ADMIN_ID:
        rows.insert(2, ["🛠 Admin Panel"])
    return ReplyKeyboardMarkup(rows, resize_keyboard=True)

def extras_keyboard():
    return ReplyKeyboardMarkup([["➕ Add Deps", "📝 Type Env Vars"], ["🚀 RUN NOW", "🔙 Cancel"]], resize_keyboard=True)

def git_extras_keyboard():
    return ReplyKeyboardMarkup([["📝 Type Env Vars"], ["📂 Select File to Run", "🔙 Cancel"]], resize_keyboard=True)

# ================= FLASK APP =================
app = Flask(__name__)

HOME_HTML = """
<!DOCTYPE html><html>
<head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Bot Host</title></head>
<body style="font-family:sans-serif">
<h3>🤖 Bot Host is Alive</h3>
<p>Use Telegram bot to manage apps.</p>
</body></html>
"""

@app.route("/")
def home():
    return HOME_HTML, 200

@app.route("/status")
def status():
    script = request.args.get("script", "")
    key = request.args.get("key", "")
    if not script:
        return "Specify script", 400

    # secure key required
    real_key = get_app_key(script)
    if not real_key or key != real_key:
        return "⛔ Forbidden", 403

    if script in running_processes and running_processes[script]["process"].poll() is None:
        return f"✅ {script} is running.", 200
    return f"❌ {script} is stopped.", 404

# ---------- Logs UI (Feature 2) ----------
LOGS_HTML = """
<!DOCTYPE html><html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Logs</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
body{margin:0;font-family:sans-serif;background:#0b0d10;color:#e8e8e8}
.header{padding:10px;background:#161a20;display:flex;gap:8px;align-items:center;position:sticky;top:0}
.btn{padding:8px 10px;border:0;border-radius:8px;background:#2b90ff;color:#fff;font-weight:700}
.small{opacity:.75;font-size:12px}
pre{margin:0;padding:12px;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,monospace;font-size:12px}
</style>
</head>
<body>
<div class="header">
  <button class="btn" onclick="loadLogs()">🔄 Refresh</button>
  <span class="small">Last {{lines}} lines</span>
</div>
<pre id="logbox">Loading...</pre>
<script>
var tg = window.Telegram.WebApp; tg.expand();
async function loadLogs(){
  const r = await fetch('/api/logs?id={{tid}}&uid={{uid}}&lines={{lines}}');
  const t = await r.text();
  document.getElementById('logbox').textContent = t;
}
loadLogs();
</script>
</body></html>
"""

@app.route("/logs")
def logs_ui():
    tid = request.args.get("id", "")
    uid = int(request.args.get("uid", "0"))
    lines = int(request.args.get("lines", "200"))
    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return "⛔ Access Denied", 403
    return render_template_string(LOGS_HTML, tid=safe_q(tid), uid=uid, lines=lines)

@app.route("/api/logs")
def logs_api():
    tid = unquote(request.args.get("id", ""))
    uid = int(request.args.get("uid", "0"))
    lines = int(request.args.get("lines", "200"))
    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return "⛔ Access Denied", 403

    log_path = os.path.join(UPLOAD_DIR, f"{tid.replace('|','_')}.log")
    if not os.path.exists(log_path):
        return "No logs.", 200

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read().splitlines()[-max(50, min(lines, 1000)):]
        return "\n".join(data) if data else "(empty)", 200
    except Exception:
        return "Failed to read logs.", 200

# ---------- File Manager UI (Feature 8) ----------
FILES_HTML = """
<!DOCTYPE html><html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Files</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
body{margin:0;font-family:sans-serif;background:#0b0d10;color:#e8e8e8}
.header{padding:10px;background:#161a20;position:sticky;top:0}
input,button{padding:10px;border-radius:10px;border:0}
button{background:#2b90ff;color:#fff;font-weight:700}
.list{padding:10px;display:flex;flex-direction:column;gap:8px}
.item{padding:10px;border-radius:10px;background:#131821;display:flex;justify-content:space-between;gap:10px;align-items:center}
a{color:#8bd3ff;text-decoration:none;font-weight:700}
.small{opacity:.75;font-size:12px}
.row{display:flex;gap:8px;margin-top:8px}
</style>
</head>
<body>
<div class="header">
  <div class="small">App: {{tid_plain}}</div>
  <div class="row">
    <input id="newname" placeholder="new file e.g. test.py" style="flex:1;background:#0f141d;color:#fff">
    <button onclick="createFile()">➕ Create</button>
  </div>
</div>
<div class="list" id="list">Loading...</div>
<script>
var tg=window.Telegram.WebApp; tg.expand();
async function loadFiles(){
  const r = await fetch('/api/files?id={{tid}}&uid={{uid}}');
  const j = await r.json();
  if(!j.ok){ document.getElementById('list').textContent=j.message; return; }
  const div=document.getElementById('list');
  div.innerHTML='';
  j.files.forEach(f=>{
    const el=document.createElement('div');
    el.className='item';
    const left=document.createElement('div');
    left.innerHTML = '<div>'+f+'</div><div class="small">tap to edit</div>';
    const a=document.createElement('a');
    a.href = '{{base}}/editor?id={{tid_plain_enc}}&file='+encodeURIComponent(f)+'&uid={{uid}}';
    a.textContent='✏️ Edit';
    el.appendChild(left); el.appendChild(a);
    div.appendChild(el);
  });
}
async function createFile(){
  const name=document.getElementById('newname').value.trim();
  if(!name){ tg.showAlert('Enter file name'); return; }
  const r = await fetch('/api/create_file', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id:'{{tid_plain}}', uid: {{uid}}, name: name})
  });
  const j=await r.json();
  if(j.ok){ document.getElementById('newname').value=''; loadFiles(); }
  else tg.showAlert(j.message||'Failed');
}
loadFiles();
</script>
</body></html>
"""

@app.route("/files")
def files_ui():
    tid = request.args.get("id", "")
    uid = int(request.args.get("uid", "0"))
    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return "⛔ Access Denied", 403
    return render_template_string(
        FILES_HTML,
        tid=safe_q(tid),
        tid_plain=tid,
        tid_plain_enc=safe_q(tid),
        uid=uid,
        base=BASE_URL,
    )

@app.route("/api/files")
def files_api():
    tid = unquote(request.args.get("id", ""))
    uid = int(request.args.get("uid", "0"))
    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return jsonify({"ok": False, "message": "Access Denied"}), 403

    work_dir, _, _, _, _ = resolve_paths(tid)
    files = list_files_safe(work_dir)
    return jsonify({"ok": True, "files": files})

@app.route("/api/create_file", methods=["POST"])
def api_create_file():
    data = request.json or {}
    tid = data.get("id", "")
    uid = int(data.get("uid", 0))
    name = (data.get("name") or "").strip()

    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return jsonify({"ok": False, "message": "Access Denied"}), 403
    if not name or ".." in name or name.startswith("/") or name.startswith("\\"):
        return jsonify({"ok": False, "message": "Invalid name"}), 400

    work_dir, _, _, _, _ = resolve_paths(tid)
    target = os.path.join(work_dir, name)
    if not within_dir(work_dir, target):
        return jsonify({"ok": False, "message": "Security block"}), 400

    os.makedirs(os.path.dirname(target), exist_ok=True)
    if os.path.exists(target):
        return jsonify({"ok": False, "message": "File already exists"}), 400

    with open(target, "w", encoding="utf-8") as f:
        f.write("")
    return jsonify({"ok": True})

# ---------- Env Vars UI (Feature 9) ----------
ENV_HTML = """
<!DOCTYPE html><html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Env Vars</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
body{margin:0;font-family:sans-serif;background:#0b0d10;color:#e8e8e8}
.header{padding:10px;background:#161a20;position:sticky;top:0}
.box{padding:10px}
.row{display:flex;gap:8px;margin-bottom:8px}
input{flex:1;padding:10px;border-radius:10px;border:0;background:#0f141d;color:#fff}
button{padding:10px;border-radius:10px;border:0;background:#2b90ff;color:#fff;font-weight:700}
.item{padding:10px;border-radius:10px;background:#131821;margin-bottom:8px;display:flex;justify-content:space-between;gap:10px;align-items:center}
.k{font-weight:800}
.small{opacity:.7;font-size:12px}
</style>
</head>
<body>
<div class="header">
  <div class="small">Edit Env for {{tid_plain}}</div>
  <div class="row">
    <input id="k" placeholder="KEY">
    <input id="v" placeholder="VALUE">
    <button onclick="saveKV()">💾 Save</button>
  </div>
</div>
<div class="box" id="list">Loading...</div>
<script>
var tg=window.Telegram.WebApp; tg.expand();
async function loadEnv(){
  const r = await fetch('/api/env?id={{tid}}&uid={{uid}}');
  const j = await r.json();
  if(!j.ok){ document.getElementById('list').textContent=j.message; return; }
  const div=document.getElementById('list'); div.innerHTML='';
  Object.keys(j.env).sort().forEach(k=>{
    const item=document.createElement('div'); item.className='item';
    const left=document.createElement('div');
    left.innerHTML='<div class="k">'+k+'</div><div class="small">'+(j.env[k] ? '••••••' : '')+'</div>';
    const btn=document.createElement('button');
    btn.textContent='🗑️ Delete';
    btn.onclick=()=>delK(k);
    item.appendChild(left); item.appendChild(btn);
    item.onclick=()=>{ document.getElementById('k').value=k; document.getElementById('v').value=j.env[k]; };
    div.appendChild(item);
  });
}
async function saveKV(){
  const k=document.getElementById('k').value.trim();
  const v=document.getElementById('v').value;
  if(!k){ tg.showAlert('KEY required'); return; }
  const r = await fetch('/api/env_save', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id:'{{tid_plain}}', uid: {{uid}}, key:k, value:v})
  });
  const j=await r.json();
  if(j.ok){ tg.showAlert('Saved'); loadEnv(); }
  else tg.showAlert(j.message||'Failed');
}
async function delK(k){
  const r = await fetch('/api/env_delete', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id:'{{tid_plain}}', uid: {{uid}}, key:k})
  });
  const j=await r.json();
  if(j.ok){ loadEnv(); } else tg.showAlert(j.message||'Failed');
}
loadEnv();
</script>
</body></html>
"""

def parse_env_file(env_path: str) -> dict:
    out = {}
    if not os.path.exists(env_path):
        return out
    with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def write_env_file(env_path: str, env: dict):
    os.makedirs(os.path.dirname(env_path), exist_ok=True)
    lines = []
    for k in sorted(env.keys()):
        lines.append(f"{k}={env[k]}")
    with open(env_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

@app.route("/env")
def env_ui():
    tid = request.args.get("id", "")
    uid = int(request.args.get("uid", "0"))
    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return "⛔ Access Denied", 403
    return render_template_string(ENV_HTML, tid=safe_q(tid), tid_plain=tid, uid=uid)

@app.route("/api/env")
def env_api():
    tid = unquote(request.args.get("id", ""))
    uid = int(request.args.get("uid", "0"))
    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return jsonify({"ok": False, "message": "Access Denied"}), 403
    work_dir, _, env_path, _, _ = resolve_paths(tid)
    if not os.path.exists(work_dir):
        return jsonify({"ok": False, "message": "Workdir missing"}), 400
    env = parse_env_file(env_path)
    return jsonify({"ok": True, "env": env})

@app.route("/api/env_save", methods=["POST"])
def env_save_api():
    data = request.json or {}
    tid = data.get("id", "")
    uid = int(data.get("uid", 0))
    k = (data.get("key") or "").strip()
    v = (data.get("value") or "").strip()
    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return jsonify({"ok": False, "message": "Access Denied"}), 403
    if not k or any(c in k for c in [" ", "\n", "\r", "\t"]):
        return jsonify({"ok": False, "message": "Invalid KEY"}), 400

    work_dir, _, env_path, _, _ = resolve_paths(tid)
    env = parse_env_file(env_path)
    env[k] = v
    write_env_file(env_path, env)
    return jsonify({"ok": True})

@app.route("/api/env_delete", methods=["POST"])
def env_delete_api():
    data = request.json or {}
    tid = data.get("id", "")
    uid = int(data.get("uid", 0))
    k = (data.get("key") or "").strip()
    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return jsonify({"ok": False, "message": "Access Denied"}), 403
    work_dir, _, env_path, _, _ = resolve_paths(tid)
    env = parse_env_file(env_path)
    if k in env:
        del env[k]
        write_env_file(env_path, env)
    return jsonify({"ok": True})

# ---------- Editor (single file, but now used with File Manager) ----------
EDITOR_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Universal Editor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://telegram.org/js/telegram-web-app.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/theme/dracula.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/python/python.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/javascript/javascript.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/shell/shell.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/dockerfile/dockerfile.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/properties/properties.min.js"></script>
    <style>
        body { margin: 0; padding: 0; background: #282a36; color: #f8f8f2; font-family: sans-serif; display: flex; flex-direction: column; height: 100vh; }
        .header { padding: 10px; background: #44475a; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #6272a4; }
        .header h3 { margin: 0; font-size: 14px; color: #8be9fd; }
        .btn { background: #50fa7b; color: #282a36; border: none; padding: 8px 15px; border-radius: 5px; font-weight: bold; cursor: pointer; }
        .CodeMirror { flex-grow: 1; font-size: 13px; }
    </style>
</head>
<body>
    <div class="header">
        <h3>📄 {{ filename }}</h3>
        <button class="btn" onclick="saveCode()">💾 Save & Restart</button>
    </div>
    <textarea id="code_area">{{ code }}</textarea>
    <script>
        var tg = window.Telegram.WebApp;
        tg.expand(); 
        
        var fname = "{{ filename }}".toLowerCase();
        var mode = "python";
        if(fname.endsWith(".js") || fname.endsWith(".json")) mode = "javascript";
        if(fname.endsWith(".sh")) mode = "shell";
        if(fname.includes("dockerfile")) mode = "dockerfile";
        if(fname.endsWith(".env") || fname.endsWith(".txt")) mode = "properties";

        var editor = CodeMirror.fromTextArea(document.getElementById("code_area"), {
            mode: mode, theme: "dracula", lineNumbers: true
        });

        function saveCode() {
            fetch('/save_code', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ 
                    target_id: "{{ target_id }}", 
                    filename: "{{ filename }}",
                    code: editor.getValue(),
                    uid: {{uid}}
                })
            })
            .then(r => r.json())
            .then(data => {
                if(data.status === 'success') {
                    tg.showAlert("✅ Saved & Restarting...");
                    tg.close();
                } else {
                    tg.showAlert("❌ Error: " + data.message);
                }
            });
        }
    </script>
</body>
</html>
"""

@app.route("/editor")
def editor_page():
    tid = request.args.get("id", "")
    filename = request.args.get("file", "")
    uid = int(request.args.get("uid", "0"))

    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return "⛔ Access Denied", 403

    work_dir, _, _, _, _ = resolve_paths(tid)
    file_path = os.path.join(work_dir, filename)

    if not within_dir(work_dir, file_path):
        return "⛔ Security Block.", 400

    content = ""
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

    return render_template_string(
        EDITOR_HTML, code=content, target_id=safe_q(tid), filename=filename, uid=uid
    )

@app.route("/save_code", methods=["POST"])
def save_code():
    data = request.json or {}
    tid = unquote(data.get("target_id", ""))
    filename = data.get("filename", "")
    code = data.get("code", "")
    uid = int(data.get("uid", 0))

    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return jsonify({"status": "error", "message": "Access Denied"}), 403

    work_dir, _, _, _, _ = resolve_paths(tid)
    file_path = os.path.join(work_dir, filename)
    if not within_dir(work_dir, file_path):
        return jsonify({"status": "error", "message": "Security Block"}), 400

    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)

        # smart install
        if filename == "requirements.txt" or filename.endswith(".txt"):
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", file_path])
        elif filename == "package.json":
            subprocess.check_call(["npm", "install"], cwd=work_dir)

        # restart app
        restart_process_background(tid)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# ---------- Resource Stats API (Feature 3) ----------
@app.route("/api/app_stats")
def app_stats_api():
    tid = request.args.get("id", "")
    uid = int(request.args.get("uid", "0"))
    owner = get_owner(tid)
    if uid != ADMIN_ID and uid != owner:
        return jsonify({"ok": False, "message": "Access Denied"}), 403

    info = {"ok": True, "running": False, "cpu": 0.0, "ram_mb": 0.0, "uptime_s": 0}
    if tid in running_processes:
        p = running_processes[tid]["process"]
        if p.poll() is None:
            info["running"] = True
            info["uptime_s"] = int(time.time() - running_processes[tid].get("started_at", time.time()))
            try:
                proc = psutil.Process(p.pid)
                # cpu_percent needs warm-up; return current snapshot
                info["cpu"] = float(proc.cpu_percent(interval=0.0))
                info["ram_mb"] = float(proc.memory_info().rss / (1024 * 1024))
            except Exception:
                pass
    return jsonify(info)

# ================= RUN FLASK =================
def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

# ================= TELEGRAM BOT HANDLERS =================
WAIT_FILE, WAIT_EXTRAS, WAIT_ENV_TEXT = range(3)
WAIT_URL, WAIT_GIT_EXTRAS, WAIT_GIT_ENV_TEXT, WAIT_SELECT_FILE = range(3, 7)

@restricted
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 **Mega Hosting Bot**", reply_markup=main_menu_keyboard(update.effective_user.id), parse_mode="Markdown")

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🚫 Cancelled.", reply_markup=main_menu_keyboard(update.effective_user.id))
    return ConversationHandler.END

# ---- Upload flow ----
@restricted
async def upload_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📤 Send file (.py, .js, .sh)", reply_markup=ReplyKeyboardMarkup([["🔙 Cancel"]], resize_keyboard=True))
    return WAIT_FILE

async def receive_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.text == "🔙 Cancel":
        return await cancel(update, context)

    doc = update.message.document
    if not doc:
        return WAIT_FILE

    tgfile = await doc.get_file()
    fname = doc.file_name
    uid = update.effective_user.id

    if not fname.endswith((".py", ".js", ".sh")):
        await update.message.reply_text("❌ Invalid type. Only .py/.js/.sh")
        return WAIT_FILE

    # per-user folder (no overwrite)
    user_dir = os.path.join(UPLOAD_DIR, str(uid))
    os.makedirs(user_dir, exist_ok=True)

    path = os.path.join(user_dir, fname)
    await tgfile.download_to_drive(path)

    unique_id = f"u{uid}|{fname}"
    key = secrets.token_urlsafe(16)

    save_ownership_record(unique_id, {
        "owner": uid,
        "type": "file",
        "key": key,
        "last_run": False,
        "entry": fname,  # for user-file, entry is filename
        "created_at": int(time.time()),
    })

    context.user_data.update({"type": "file", "target_id": unique_id, "work_dir": user_dir})
    await update.message.reply_text("✅ Saved.", reply_markup=extras_keyboard())
    return WAIT_EXTRAS

async def receive_extras(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = update.message.text

    if txt == "🚀 RUN NOW":
        return await execute_logic(update, context)
    if txt == "🔙 Cancel":
        return await cancel(update, context)

    if txt == "📝 Type Env Vars":
        await update.message.reply_text("📝 Type env lines (KEY=VALUE).", reply_markup=ReplyKeyboardMarkup([["🔙 Cancel"]], resize_keyboard=True))
        return WAIT_ENV_TEXT

    if txt == "➕ Add Deps":
        await update.message.reply_text("📂 Send `requirements.txt` or `package.json`")
        context.user_data["wait"] = "deps"
        return WAIT_EXTRAS

    return WAIT_EXTRAS

async def receive_env_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.text == "🔙 Cancel":
        return await cancel(update, context)

    tid = context.user_data.get("target_id")
    if not tid:
        await update.message.reply_text("❌ No target selected.")
        return ConversationHandler.END

    work_dir, _, env_path, _, _ = resolve_paths(tid)
    os.makedirs(work_dir, exist_ok=True)

    with open(env_path, "a", encoding="utf-8") as f:
        if os.path.exists(env_path) and os.path.getsize(env_path) > 0:
            f.write("\n")
        f.write(update.message.text.strip())

    if context.user_data.get("type") == "repo":
        await update.message.reply_text("✅ Saved.", reply_markup=git_extras_keyboard())
        return WAIT_GIT_EXTRAS

    await update.message.reply_text("✅ Saved.", reply_markup=extras_keyboard())
    return WAIT_EXTRAS

async def receive_extra_files(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get("wait") != "deps":
        return WAIT_EXTRAS

    doc = update.message.document
    if not doc:
        return WAIT_EXTRAS

    tgfile = await doc.get_file()
    fname = doc.file_name
    tid = context.user_data.get("target_id")
    work_dir = context.user_data.get("work_dir")

    if not work_dir and tid:
        work_dir, *_ = resolve_paths(tid)
    if not work_dir:
        await update.message.reply_text("❌ Workdir not found.")
        context.user_data["wait"] = None
        return WAIT_EXTRAS

    if fname not in ("requirements.txt", "package.json"):
        await update.message.reply_text("❌ Only requirements.txt or package.json allowed.")
        return WAIT_EXTRAS

    os.makedirs(work_dir, exist_ok=True)
    save_path = os.path.join(work_dir, fname)
    await tgfile.download_to_drive(save_path)

    msg = await update.message.reply_text("⏳ Installing Dependencies...")
    try:
        if fname == "requirements.txt":
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "pip", "install", "-r", "requirements.txt",
                cwd=work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
        else:
            proc = await asyncio.create_subprocess_exec(
                "npm", "install",
                cwd=work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
        await msg.edit_text("✅ Installed!")
    except Exception as e:
        await msg.edit_text(f"❌ Error: {e}")

    context.user_data["wait"] = None
    await update.message.reply_text("Next?", reply_markup=extras_keyboard())
    return WAIT_EXTRAS

# ---- Git flow ----
@restricted
async def git_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🌐 Send Git URL", reply_markup=ReplyKeyboardMarkup([["🔙 Cancel"]], resize_keyboard=True))
    return WAIT_URL

async def receive_git_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text
    if url == "🔙 Cancel":
        return await cancel(update, context)

    uid = update.effective_user.id
    base_repo = url.split("/")[-1].replace(".git", "")
    repo_name = f"{base_repo}_u{uid}"
    repo_path = os.path.join(UPLOAD_DIR, repo_name)

    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)

    try:
        subprocess.check_call(["git", "clone", url, repo_path])
        await install_dependencies(repo_path, update)

        # create record now; entry chosen later by selection (or auto-detect)
        tid = f"{repo_name}|PLACEHOLDER"
        key = secrets.token_urlsafe(16)
        save_ownership_record(tid, {
            "owner": uid,
            "type": "repo",
            "key": key,
            "last_run": False,
            "entry": None,
            "created_at": int(time.time()),
        })

        context.user_data.update({"repo_path": repo_path, "repo_name": repo_name, "target_id": tid, "type": "repo", "work_dir": repo_path})
        await update.message.reply_text("⚙️ Setup done. Now select file to run.", reply_markup=git_extras_keyboard())
        return WAIT_GIT_EXTRAS
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")
        return ConversationHandler.END

async def receive_git_extras(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = update.message.text
    if txt == "🔙 Cancel":
        return await cancel(update, context)
    if txt == "📝 Type Env Vars":
        await update.message.reply_text("📝 Type env lines (KEY=VALUE).", reply_markup=ReplyKeyboardMarkup([["🔙 Cancel"]], resize_keyboard=True))
        return WAIT_GIT_ENV_TEXT
    if txt == "📂 Select File to Run":
        return await show_file_selection(update, context)
    return WAIT_GIT_EXTRAS

async def show_file_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    repo_path = context.user_data.get("repo_path")
    if not repo_path:
        await update.message.reply_text("❌ Repo not found.")
        return ConversationHandler.END

    files = []
    for f in list_files_safe(repo_path):
        if f.endswith((".py", ".js", ".sh")):
            files.append(f)

    if not files:
        await update.message.reply_text("❌ No runnable files found.")
        return ConversationHandler.END

    keyboard = [[InlineKeyboardButton(f, callback_data=f"sel_run_{f}")] for f in files[:20]]
    await update.message.reply_text("👇 Select file to RUN:", reply_markup=InlineKeyboardMarkup(keyboard))
    return WAIT_SELECT_FILE

async def select_git_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    filename = q.data.split("sel_run_")[1]

    repo_name = context.user_data.get("repo_name")
    # replace placeholder record with real tid
    old_tid = context.user_data.get("target_id")  # repo|PLACEHOLDER
    new_tid = f"{repo_name}|{filename}"

    data = load_ownership()
    old = data.get(old_tid, {})
    if old:
        data[new_tid] = old
        data[new_tid]["entry"] = filename
        del data[old_tid]
        _write_json(OWNERSHIP_FILE, data)
    else:
        # fallback: create
        save_ownership_record(new_tid, {
            "owner": update.effective_user.id,
            "type": "repo",
            "key": secrets.token_urlsafe(16),
            "last_run": False,
            "entry": filename,
            "created_at": int(time.time()),
        })

    context.user_data["target_id"] = new_tid
    await q.edit_message_text(f"✅ Selected `{filename}`", parse_mode="Markdown")
    return await execute_logic(q, context)

# ---- Execute (launch) ----
async def execute_logic(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg_func = update.message.reply_text if getattr(update, "message", None) else update.callback_query.message.reply_text
    tid = context.user_data.get("target_id", context.user_data.get("fallback_id"))
    if not tid:
        await msg_func("❌ No target selected.")
        return ConversationHandler.END

    restart_process_background(tid)
    key = get_app_key(tid) or "no-key"

    await msg_func(
        "🚀 **Launched!**\n"
        f"🔒 **Secure URL:** `{safe_status_url(tid, key)}`",
        parse_mode="Markdown",
        reply_markup=main_menu_keyboard(update.effective_user.id),
    )
    return ConversationHandler.END

# ---- List & Manage ----
@restricted
async def list_hosted(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    ownership = load_ownership()
    if not ownership:
        return await update.message.reply_text("📂 Empty.")

    keyboard = []
    for tid, meta in ownership.items():
        owner_id = meta.get("owner")
        if uid == ADMIN_ID or uid == owner_id:
            is_running = tid in running_processes and running_processes[tid]["process"].poll() is None
            status = "🟢" if is_running else "🔴"
            label = f"{status} {tid}"
            if uid == ADMIN_ID and uid != owner_id:
                label += f" (👤 {owner_id})"
            keyboard.append([InlineKeyboardButton(label, callback_data=f"man_{tid}")])

    if not keyboard:
        return await update.message.reply_text("📂 No apps.")
    await update.message.reply_text("📂 Select App:", reply_markup=InlineKeyboardMarkup(keyboard))

def app_manage_buttons(tid: str, uid: int):
    owner = get_owner(tid)
    is_running = tid in running_processes and running_processes[tid]["process"].poll() is None
    key = get_app_key(tid) or ""
    status = "🟢 Running" if is_running else "🔴 Stopped"

    text = f"⚙️ **App:** `{tid}`\nStatus: {status}"
    if uid == ADMIN_ID:
        text += f"\n👤 **Owner:** `{owner}`"
    if key:
        text += f"\n🔒 **Secure URL:** `{safe_status_url(tid, key)}`"

    btns = []
    row1 = []
    if is_running:
        row1.append(InlineKeyboardButton("🛑 Stop", callback_data=f"stop_{tid}"))
    row1.append(InlineKeyboardButton("🚀 Run/Restart", callback_data=f"rerun_{tid}"))
    btns.append(row1)

    # web UIs
    btns.append([
        InlineKeyboardButton("📜 Logs (Web)", web_app=WebAppInfo(url=f"{BASE_URL}/logs?id={safe_q(tid)}&uid={uid}&lines=250")),
        InlineKeyboardButton("📁 Files", web_app=WebAppInfo(url=f"{BASE_URL}/files?id={safe_q(tid)}&uid={uid}")),
    ])
    btns.append([
        InlineKeyboardButton("🔑 Env Vars", web_app=WebAppInfo(url=f"{BASE_URL}/env?id={safe_q(tid)}&uid={uid}")),
        InlineKeyboardButton("📊 Stats", callback_data=f"stats_{tid}"),
    ])

    btns.append([
        InlineKeyboardButton("🧹 Clear Logs", callback_data=f"clrlog_{tid}"),
        InlineKeyboardButton("🗑️ Delete", callback_data=f"del_{tid}"),
    ])
    return text, InlineKeyboardMarkup(btns)

async def manage_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    uid = update.effective_user.id

    if data.startswith("man_"):
        tid = data.split("man_")[1]
        owner = get_owner(tid)
        if uid != ADMIN_ID and uid != owner:
            return await q.message.reply_text("⛔ Not yours.")

        text, markup = app_manage_buttons(tid, uid)
        return await q.edit_message_text(text, reply_markup=markup, parse_mode="Markdown")

    if data.startswith("stop_"):
        tid = data.split("stop_")[1]
        owner = get_owner(tid)
        if uid != ADMIN_ID and uid != owner:
            return await q.message.reply_text("⛔ Not yours.")
        stop_process(tid)
        return await q.edit_message_text(f"🛑 Stopped `{tid}`", parse_mode="Markdown")

    if data.startswith("rerun_"):
        tid = data.split("rerun_")[1]
        owner = get_owner(tid)
        if uid != ADMIN_ID and uid != owner:
            return await q.message.reply_text("⛔ Not yours.")
        context.user_data["fallback_id"] = tid
        await q.delete_message()
        return await execute_logic(update, context)

    if data.startswith("clrlog_"):
        tid = data.split("clrlog_")[1]
        owner = get_owner(tid)
        if uid != ADMIN_ID and uid != owner:
            return await q.message.reply_text("⛔ Not yours.")
        clear_log(tid)
        return await q.message.reply_text("✅ Logs cleared.")

    if data.startswith("stats_"):
        tid = data.split("stats_")[1]
        owner = get_owner(tid)
        if uid != ADMIN_ID and uid != owner:
            return await q.message.reply_text("⛔ Not yours.")
        # compute stats
        resp = app.test_client().get(f"/api/app_stats?id={safe_q(tid)}&uid={uid}")
        j = resp.get_json() if resp.is_json else {}
        if not j.get("ok"):
            return await q.message.reply_text("❌ Could not fetch stats.")
        if not j.get("running"):
            return await q.message.reply_text("🔴 App is not running.")
        return await q.message.reply_text(
            f"📊 **Stats for** `{tid}`\n"
            f"CPU: `{j.get('cpu', 0):.2f}%`\n"
            f"RAM: `{j.get('ram_mb', 0):.2f} MB`\n"
            f"Uptime: `{j.get('uptime_s', 0)}s`",
            parse_mode="Markdown"
        )

    if data.startswith("del_"):
        tid = data.split("del_")[1]
        owner = get_owner(tid)
        if uid != ADMIN_ID and uid != owner:
            return await q.message.reply_text("⛔ Not yours.")

        stop_process(tid)
        delete_ownership(tid)

        work_dir, script_path, _, _, _ = resolve_paths(tid)
        # delete file/folder safely
        if is_repo_id(tid):
            shutil.rmtree(work_dir, ignore_errors=True)
        elif is_user_file_id(tid):
            try:
                os.remove(os.path.join(work_dir, script_path))
            except Exception:
                pass
        else:
            try:
                os.remove(os.path.join(UPLOAD_DIR, tid))
            except Exception:
                pass
        return await q.edit_message_text(f"🗑️ Deleted `{tid}`", parse_mode="Markdown")

# ---- Server Stats ----
@restricted
async def server_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # light stats
    total = len(load_ownership())
    running = sum(1 for tid in running_processes if running_processes[tid]["process"].poll() is None)
    await update.message.reply_text(f"📊 Apps: {total}\n🟢 Running: {running}")

# ---- Admin Panel (Feature 4) ----
@restricted
async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("⛔ Admin only.")
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🛑 Stop ALL", callback_data="admin_stop_all"),
         InlineKeyboardButton("🔄 Restart ALL last-run", callback_data="admin_restart_all")],
        [InlineKeyboardButton("🧹 Clear ALL logs", callback_data="admin_clear_logs")],
    ])
    await update.message.reply_text("🛠 Admin Panel", reply_markup=kb)

async def admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id != ADMIN_ID:
        return await q.message.reply_text("⛔ Admin only.")

    if q.data == "admin_stop_all":
        for tid in list(running_processes.keys()):
            stop_process(tid)
        return await q.edit_message_text("🛑 Stopped all running apps.")

    if q.data == "admin_restart_all":
        # start only last_run True
        auto_start_last_run_apps()
        return await q.edit_message_text("🔄 Restart requested for last-run apps.")

    if q.data == "admin_clear_logs":
        for tid in load_ownership().keys():
            clear_log(tid)
        return await q.edit_message_text("🧹 Cleared logs for all apps.")

# ---- Help ----
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🆘 **Help**\n"
        "- Upload a file or clone repo\n"
        "- Run app and get secure status URL\n"
        "- Manage: Logs/Files/Env/Stats\n"
        "Contact: @platoonleaderr",
        parse_mode="Markdown",
    )

# ---- Admin allowlist commands ----
@super_admin_only
async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await update.message.reply_text("Usage: /add <user_id>")
    if save_allowed_user(int(context.args[0])):
        await update.message.reply_text("✅ Added.")

@super_admin_only
async def remove_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await update.message.reply_text("Usage: /remove <user_id>")
    if remove_allowed_user(int(context.args[0])):
        await update.message.reply_text("🗑️ Removed.")

# ================= MAIN =================
if __name__ == "__main__":
    # start Flask (Render Web Service)
    t = threading.Thread(target=run_flask, daemon=True)
    t.start()

    if not TOKEN:
        print("❌ ERROR: TOKEN env var not set")
        sys.exit(1)

    # Feature 1: Auto-start last-run apps on boot
    try:
        auto_start_last_run_apps()
    except Exception as e:
        logger.error(f"Auto-start on boot failed: {e}")

    app_bot = ApplicationBuilder().token(TOKEN).build()

    conv_file = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex("^📤 Upload File$"), upload_start)],
        states={
            WAIT_FILE: [
                MessageHandler(filters.Regex("^🔙 Cancel$"), cancel),
                MessageHandler(filters.Document.ALL, receive_file),
            ],
            WAIT_EXTRAS: [
                MessageHandler(filters.Regex("^🔙 Cancel$"), cancel),
                MessageHandler(filters.Regex("^(🚀 RUN NOW|➕ Add Deps|📝 Type Env Vars)$"), receive_extras),
                MessageHandler(filters.Document.ALL, receive_extra_files),
            ],
            WAIT_ENV_TEXT: [
                MessageHandler(filters.Regex("^🔙 Cancel$"), cancel),
                MessageHandler(filters.TEXT, receive_env_text),
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        per_message=False,
    )

    conv_git = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex("^🌐 Clone from Git$"), git_start)],
        states={
            WAIT_URL: [
                MessageHandler(filters.Regex("^🔙 Cancel$"), cancel),
                MessageHandler(filters.TEXT, receive_git_url),
            ],
            WAIT_GIT_EXTRAS: [
                MessageHandler(filters.Regex("^🔙 Cancel$"), cancel),
                MessageHandler(filters.Regex("^(📝 Type Env Vars|📂 Select File to Run)$"), receive_git_extras),
            ],
            WAIT_GIT_ENV_TEXT: [
                MessageHandler(filters.Regex("^🔙 Cancel$"), cancel),
                MessageHandler(filters.TEXT, receive_env_text),
            ],
            WAIT_SELECT_FILE: [CallbackQueryHandler(select_git_file)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        per_message=False,
    )

    app_bot.add_handler(CommandHandler("start", start))
    app_bot.add_handler(CommandHandler("add", add_user))
    app_bot.add_handler(CommandHandler("remove", remove_user))

    app_bot.add_handler(conv_file)
    app_bot.add_handler(conv_git)

    app_bot.add_handler(MessageHandler(filters.Regex("^📂 My Hosted Apps$"), list_hosted))
    app_bot.add_handler(MessageHandler(filters.Regex("^📊 Server Stats$"), server_stats))
    app_bot.add_handler(MessageHandler(filters.Regex("^🆘 Help$"), help_command))
    app_bot.add_handler(MessageHandler(filters.Regex("^🛠 Admin Panel$"), admin_panel))

    app_bot.add_handler(CallbackQueryHandler(admin_callback, pattern="^admin_"))
    app_bot.add_handler(CallbackQueryHandler(manage_callback))
    print("Bot is up and running!")
    app_bot.run_polling()
