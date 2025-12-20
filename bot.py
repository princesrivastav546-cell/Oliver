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
from flask import Flask, request, render_template_string, jsonify
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

running_processes = {}  # {target_id: {"process": Popen, "log": path, "started_at": epoch, "last_alert": epoch}}

# ---------- ALERT/HEALTH SETTINGS (Feature F) ----------
ENABLE_ALERTS = os.environ.get("ENABLE_ALERTS", "1") == "1"
HEALTHCHECK_INTERVAL_SEC = int(os.environ.get("HEALTHCHECK_INTERVAL_SEC", "20"))
ALERT_COOLDOWN_SEC = int(os.environ.get("ALERT_COOLDOWN_SEC", "180"))

# thresholds (set env vars if you want)
CPU_ALERT_PERCENT = float(os.environ.get("CPU_ALERT_PERCENT", "85"))
RAM_ALERT_MB = float(os.environ.get("RAM_ALERT_MB", "350"))


# ================= ID HELPERS =================
def is_user_file_id(tid: str) -> bool:
    return (
        isinstance(tid, str)
        and tid.startswith("u")
        and ("|" in tid)
        and tid.count("|") == 1
        and tid.split("|", 1)[0][1:].isdigit()
    )

def is_repo_id(tid: str) -> bool:
    return ("|" in tid) and (not is_user_file_id(tid))

def safe_q(s: str) -> str:
    return quote(s, safe="")

def safe_status_url(tid: str, key: str) -> str:
    return f"{BASE_URL}/status?script={safe_q(tid)}&key={safe_q(key)}"


# ================= JSON STORE =================
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

def get_entry(target_id: str):
    return load_ownership().get(target_id, {}).get("entry")


# ================= PATH RESOLUTION =================
def resolve_paths(target_id: str):
    """
    user file: u<uid>|filename.py  -> scripts/<uid>/
    repo: repoName|path/to/file.py -> scripts/<repoName>/
    legacy: filename.py -> scripts/
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


# ================= FILE UTILS =================
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
            if rel.startswith(".git/") or rel.startswith("node_modules/"):
                continue
            if rel.endswith(".pyc"):
                continue
            out.append(rel)
    out.sort()
    return out


# ================= RUN COMMAND DETECTION =================
def resolve_run_command(work_dir: str, script_rel: str | None):
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

    candidates = ["main.py", "app.py", "server.py", "bot.py", "index.js", "server.js", "start.sh"]
    for c in candidates:
        if os.path.exists(os.path.join(work_dir, c)):
            return by_ext(c), c

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

    entry = get_entry(target_id)

    if is_repo_id(target_id):
        cmd, chosen = resolve_run_command(work_dir, entry)
    elif is_user_file_id(target_id):
        cmd, chosen = resolve_run_command(work_dir, script_path)
    else:
        cmd, chosen = resolve_run_command(work_dir, script_path)

    if not cmd:
        logger.error("No runnable entry found.")
        return

    # persist chosen for repo
    if is_repo_id(target_id):
        data = load_ownership()
        if target_id in data:
            data[target_id]["entry"] = chosen
            _write_json(OWNERSHIP_FILE, data)

    os.makedirs(work_dir, exist_ok=True)
    custom_env = build_env(env_path)

    log_path = os.path.join(UPLOAD_DIR, f"{target_id.replace('|','_')}.log")
    log_file = open(log_path, "a", encoding="utf-8")

    try:
        proc = subprocess.Popen(
            cmd,
            env=custom_env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=work_dir,
            preexec_fn=os.setsid,
        )
        running_processes[target_id] = {
            "process": proc,
            "log": log_path,
            "started_at": time.time(),
            "last_alert": 0,
        }
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

def tail_log(target_id: str, lines: int = 50) -> str:
    log_path = os.path.join(UPLOAD_DIR, f"{target_id.replace('|','_')}.log")
    if not os.path.exists(log_path):
        return "(no log file)"
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read().splitlines()[-max(10, min(lines, 400)):]
        return "\n".join(data) if data else "(empty)"
    except Exception:
        return "(failed to read log)"

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
        rows.insert(2, ["🛠 Owner Panel"])
    return ReplyKeyboardMarkup(rows, resize_keyboard=True)

def extras_keyboard():
    return ReplyKeyboardMarkup([["➕ Add Deps", "📝 Type Env Vars"], ["🚀 RUN NOW", "🔙 Cancel"]], resize_keyboard=True)

def git_extras_keyboard():
    return ReplyKeyboardMarkup([["📝 Type Env Vars"], ["📂 Select File to Run", "🔙 Cancel"]], resize_keyboard=True)


# ================= FLASK APP =================
app = Flask(__name__)

@app.route("/")
def home():
    return "🤖 Bot Host is Alive!", 200

@app.route("/status")
def status():
    script = request.args.get("script", "")
    key = request.args.get("key", "")
    if not script:
        return "Specify script", 400

    real_key = get_app_key(script)
    if not real_key or key != real_key:
        return "⛔ Forbidden", 403

    if script in running_processes and running_processes[script]["process"].poll() is None:
        return f"✅ {script} is running.", 200
    return f"❌ {script} is stopped.", 404

# ---- Logs UI (optional web) ----
LOGS_HTML = """
<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Logs</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
body{margin:0;font-family:sans-serif;background:#0b0d10;color:#e8e8e8}
.header{padding:10px;background:#161a20;display:flex;gap:8px;align-items:center;position:sticky;top:0}
.btn{padding:8px 10px;border:0;border-radius:8px;background:#2b90ff;color:#fff;font-weight:700}
.small{opacity:.75;font-size:12px}
pre{margin:0;padding:12px;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,monospace;font-size:12px}
</style></head>
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
</script></body></html>
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

    return tail_log(tid, lines), 200

# ---- Files listing API (for your file manager if needed) ----
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


def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)


# ================= HEALTHCHECK + ALERTS (Feature F) =================
async def send_alert(bot, chat_id: int, text: str):
    try:
        await bot.send_message(chat_id=chat_id, text=text, disable_web_page_preview=True)
    except Exception as e:
        logger.error(f"Failed to send alert to {chat_id}: {e}")

def can_alert(tid: str) -> bool:
    meta = running_processes.get(tid, {})
    last = meta.get("last_alert", 0)
    return (time.time() - last) >= ALERT_COOLDOWN_SEC

def mark_alerted(tid: str):
    if tid in running_processes:
        running_processes[tid]["last_alert"] = time.time()

async def watchdog_loop(app_bot):
    """
    - If app stopped/crashed -> alert owner + admin and (optional) auto restart it (since you already have last_run)
    - If high CPU/RAM -> alert (cooldown)
    """
    if not ENABLE_ALERTS:
        logger.info("Alerts disabled (ENABLE_ALERTS!=1).")
        return

    logger.info("Watchdog started.")
    while True:
        try:
            ownership = load_ownership()
            # only watch apps that are marked last_run True
            watch_list = [tid for tid, meta in ownership.items() if meta.get("last_run") is True]

            for tid in watch_list:
                # is it running?
                rp = running_processes.get(tid)
                is_running = False
                pid = None
                if rp and rp["process"].poll() is None:
                    is_running = True
                    pid = rp["process"].pid

                # stopped/crashed
                if not is_running:
                    if can_alert(tid):
                        owner_id = ownership.get(tid, {}).get("owner", ADMIN_ID)
                        msg = (
                            f"⚠️ App DOWN\n"
                            f"App: {tid}\n"
                            f"Owner: {owner_id}\n"
                            f"Action: Restarting now..."
                        )
                        await send_alert(app_bot.bot, ADMIN_ID, msg)
                        if owner_id and owner_id != ADMIN_ID:
                            await send_alert(app_bot.bot, owner_id, msg)
                        mark_alerted(tid)

                    # auto-restart
                    restart_process_background(tid)
                    continue

                # resource checks
                try:
                    proc = psutil.Process(pid)
                    cpu = proc.cpu_percent(interval=0.0)
                    ram_mb = proc.memory_info().rss / (1024 * 1024)

                    if (cpu >= CPU_ALERT_PERCENT or ram_mb >= RAM_ALERT_MB) and can_alert(tid):
                        owner_id = ownership.get(tid, {}).get("owner", ADMIN_ID)
                        msg = (
                            f"🚨 High Resource Usage\n"
                            f"App: {tid}\n"
                            f"CPU: {cpu:.2f}% (threshold {CPU_ALERT_PERCENT}%)\n"
                            f"RAM: {ram_mb:.2f} MB (threshold {RAM_ALERT_MB} MB)"
                        )
                        await send_alert(app_bot.bot, ADMIN_ID, msg)
                        if owner_id and owner_id != ADMIN_ID:
                            await send_alert(app_bot.bot, owner_id, msg)
                        mark_alerted(tid)

                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Watchdog loop error: {e}")

        await asyncio.sleep(HEALTHCHECK_INTERVAL_SEC)


# ================= TELEGRAM FLOWS =================
WAIT_FILE, WAIT_EXTRAS, WAIT_ENV_TEXT = range(3)
WAIT_URL, WAIT_GIT_EXTRAS, WAIT_GIT_ENV_TEXT, WAIT_SELECT_FILE = range(3, 7)

@restricted
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Mega Hosting Bot",
        reply_markup=main_menu_keyboard(update.effective_user.id),
    )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🚫 Cancelled.", reply_markup=main_menu_keyboard(update.effective_user.id))
    return ConversationHandler.END

# ---- Upload ----
@restricted
async def upload_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📤 Send file (.py, .js, .sh)",
        reply_markup=ReplyKeyboardMarkup([["🔙 Cancel"]], resize_keyboard=True),
    )
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

    user_dir = os.path.join(UPLOAD_DIR, str(uid))
    os.makedirs(user_dir, exist_ok=True)

    path = os.path.join(user_dir, fname)
    await tgfile.download_to_drive(path)

    unique_id = f"u{uid}|{fname}"
    key = secrets.token_urlsafe(16)

    save_ownership_record(
        unique_id,
        {
            "owner": uid,
            "type": "file",
            "key": key,
            "last_run": False,
            "entry": fname,
            "created_at": int(time.time()),
        },
    )

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
        await update.message.reply_text(
            "📝 Type env lines (KEY=VALUE).",
            reply_markup=ReplyKeyboardMarkup([["🔙 Cancel"]], resize_keyboard=True),
        )
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


# ---- Git ----
@restricted
async def git_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🌐 Send Git URL",
        reply_markup=ReplyKeyboardMarkup([["🔙 Cancel"]], resize_keyboard=True),
    )
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

        # placeholder record
        tid = f"{repo_name}|PLACEHOLDER"
        key = secrets.token_urlsafe(16)
        save_ownership_record(
            tid,
            {"owner": uid, "type": "repo", "key": key, "last_run": False, "entry": None, "created_at": int(time.time())},
        )

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

    files = [f for f in list_files_safe(repo_path) if f.endswith((".py", ".js", ".sh"))]
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
    old_tid = context.user_data.get("target_id")
    new_tid = f"{repo_name}|{filename}"

    data = load_ownership()
    old = data.get(old_tid, {})
    if old:
        data[new_tid] = old
        data[new_tid]["entry"] = filename
        del data[old_tid]
        _write_json(OWNERSHIP_FILE, data)
    else:
        save_ownership_record(
            new_tid,
            {"owner": update.effective_user.id, "type": "repo", "key": secrets.token_urlsafe(16), "last_run": False, "entry": filename, "created_at": int(time.time())},
        )

    context.user_data["target_id"] = new_tid
    await q.edit_message_text(f"✅ Selected `{filename}`", parse_mode="Markdown")
    return await execute_logic(q, context)


# ---- Execute ----
async def execute_logic(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg_func = update.message.reply_text if getattr(update, "message", None) else update.callback_query.message.reply_text
    tid = context.user_data.get("target_id", context.user_data.get("fallback_id"))
    if not tid:
        await msg_func("❌ No target selected.")
        return ConversationHandler.END

    restart_process_background(tid)
    key = get_app_key(tid) or "no-key"

    await msg_func(
        "🚀 Launched!\n" f"🔒 Secure URL:\n{safe_status_url(tid, key)}",
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

    text = f"⚙️ App: {tid}\nStatus: {status}"
    if uid == ADMIN_ID:
        text += f"\nOwner: {owner}"
    if key:
        text += f"\nSecure URL:\n{safe_status_url(tid, key)}"

    btns = []
    row1 = []
    if is_running:
        row1.append(InlineKeyboardButton("🛑 Stop", callback_data=f"stop_{tid}"))
    row1.append(InlineKeyboardButton("🚀 Run/Restart", callback_data=f"rerun_{tid}"))
    btns.append(row1)

    btns.append([
        InlineKeyboardButton("📜 Logs (Web)", web_app=WebAppInfo(url=f"{BASE_URL}/logs?id={safe_q(tid)}&uid={uid}&lines=250")),
        InlineKeyboardButton("🧹 Clear Logs", callback_data=f"clrlog_{tid}"),
    ])
    btns.append([InlineKeyboardButton("🗑️ Delete", callback_data=f"del_{tid}")])
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
        return await q.edit_message_text(text, reply_markup=markup)

    if data.startswith("stop_"):
        tid = data.split("stop_")[1]
        owner = get_owner(tid)
        if uid != ADMIN_ID and uid != owner:
            return await q.message.reply_text("⛔ Not yours.")
        stop_process(tid)
        return await q.edit_message_text(f"🛑 Stopped: {tid}")

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

    if data.startswith("del_"):
        tid = data.split("del_")[1]
        owner = get_owner(tid)
        if uid != ADMIN_ID and uid != owner:
            return await q.message.reply_text("⛔ Not yours.")

        stop_process(tid)
        delete_ownership(tid)

        work_dir, script_path, _, _, _ = resolve_paths(tid)
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

        return await q.edit_message_text(f"🗑️ Deleted: {tid}")


# ---- Server Stats ----
@restricted
async def server_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    total = len(load_ownership())
    running = sum(1 for tid in running_processes if running_processes[tid]["process"].poll() is None)
    await update.message.reply_text(f"📊 Apps: {total}\n🟢 Running: {running}")


# ================= OWNER PANEL (what you asked) =================
@restricted
async def owner_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await update.message.reply_text("⛔ Owner only.")

    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("👥 View Access List", callback_data="own_access")],
        [InlineKeyboardButton("🧾 View Apps & Owners", callback_data="own_apps")],
        [InlineKeyboardButton("🟢 View Running", callback_data="own_running"),
         InlineKeyboardButton("🔴 View Down", callback_data="own_down")],
        [InlineKeyboardButton("🛑 Stop ALL", callback_data="own_stop_all"),
         InlineKeyboardButton("🔄 Restart ALL last-run", callback_data="own_restart_all")],
    ])
    await update.message.reply_text("🛠 Owner Panel", reply_markup=kb)

async def owner_panel_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id != ADMIN_ID:
        return await q.message.reply_text("⛔ Owner only.")

    ownership = load_ownership()

    if q.data == "own_access":
        allowed = get_allowed_users()
        text = "👥 **Access List**\n"
        text += f"- Owner (ADMIN_ID): `{ADMIN_ID}`\n"
        if allowed:
            text += "- Allowed users:\n" + "\n".join([f"  • `{u}`" for u in allowed])
        else:
            text += "- Allowed users: *(none)*"
        return await q.message.reply_text(text, parse_mode="Markdown")

    if q.data == "own_apps":
        if not ownership:
            return await q.message.reply_text("No apps.")
        lines = ["🧾 **Apps & Owners**"]
        for tid, meta in ownership.items():
            lines.append(f"• `{tid}`  → 👤 `{meta.get('owner')}`  | last_run={meta.get('last_run')}")
        return await q.message.reply_text("\n".join(lines[:80]), parse_mode="Markdown")

    if q.data == "own_running":
        lines = ["🟢 **Running Apps**"]
        any_ = False
        for tid in ownership.keys():
            ok = tid in running_processes and running_processes[tid]["process"].poll() is None
            if ok:
                any_ = True
                lines.append(f"• `{tid}`")
        if not any_:
            lines.append("_None_")
        return await q.message.reply_text("\n".join(lines), parse_mode="Markdown")

    if q.data == "own_down":
        lines = ["🔴 **Down Apps** (last_run=True but not running)"]
        any_ = False
        for tid, meta in ownership.items():
            if meta.get("last_run") is True:
                ok = tid in running_processes and running_processes[tid]["process"].poll() is None
                if not ok:
                    any_ = True
                    lines.append(f"• `{tid}`")
        if not any_:
            lines.append("_None_")
        return await q.message.reply_text("\n".join(lines), parse_mode="Markdown")

    if q.data == "own_stop_all":
        for tid in list(running_processes.keys()):
            stop_process(tid)
        return await q.message.reply_text("🛑 Stopped all running apps.")

    if q.data == "own_restart_all":
        auto_start_last_run_apps()
        return await q.message.reply_text("🔄 Restart requested for last-run apps.")


# ---- Help ----
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🆘 Help\nContact: @platoonleaderr")


# ================= MAIN =================
if __name__ == "__main__":
    # start Flask
    t = threading.Thread(target=run_flask, daemon=True)
    t.start()

    if not TOKEN:
        print("❌ ERROR: TOKEN env var not set")
        sys.exit(1)

    # auto-start apps
    try:
        auto_start_last_run_apps()
    except Exception as e:
        logger.error(f"Auto-start on boot failed: {e}")

    app_bot = ApplicationBuilder().token(TOKEN).build()

    # start watchdog/alerts (Feature F)
    try:
        app_bot.create_task(watchdog_loop(app_bot))
    except Exception as e:
        logger.error(f"Watchdog start failed: {e}")

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
    app_bot.add_handler(conv_file)
    app_bot.add_handler(conv_git)

    app_bot.add_handler(MessageHandler(filters.Regex("^📂 My Hosted Apps$"), list_hosted))
    app_bot.add_handler(MessageHandler(filters.Regex("^📊 Server Stats$"), server_stats))
    app_bot.add_handler(MessageHandler(filters.Regex("^🆘 Help$"), help_command))
    app_bot.add_handler(MessageHandler(filters.Regex("^🛠 Owner Panel$"), owner_panel))

    app_bot.add_handler(CallbackQueryHandler(owner_panel_callback, pattern="^own_"))
    app_bot.add_handler(CallbackQueryHandler(manage_callback))

    print("Bot is up and running!")
    app_bot.run_polling()
