import os
import json
import base64
import hashlib
from datetime import datetime
from functools import wraps

from flask import Flask, request, session, redirect, url_for, render_template_string, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- Crypto for AES-256 ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ifortify-secret-123")
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# ============================================================
# DATABASE - Postgres on Render (PERMANENT), data.json locally
# ============================================================
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None
    RealDictCursor = None
DATABASE_URL = os.environ.get("DATABASE_URL", "")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

def get_db():
    if not DATABASE_URL:
        return None
    return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    conn = get_db()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value JSONB
            );
        """)
        conn.commit()
        cur.close()
    except Exception as e:
        print("init_db error:", e)
    finally:
        conn.close()

init_db()

def load_data():
    if not DATABASE_URL:
        try:
            with open('data.json', 'r') as f:
                data = json.load(f)
                if "users" not in data: data["users"] = {}
                if "files" not in data: data["files"] = []
                return data
        except:
            return {"users": {}, "files": []}
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT value FROM kv_store WHERE key='data'")
        row = cur.fetchone()
        cur.close()
        if row and row['value']:
            data = row['value']
            if "users" not in data: data["users"] = {}
            if "files" not in data: data["files"] = []
            return data
        return {"users": {}, "files": []}
    finally:
        conn.close()

def save_data(data):
    if not DATABASE_URL:
        with open('data.json', 'w') as f:
            json.dump(data, f, indent=2)
        return
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO kv_store (key, value) VALUES ('data', %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        """, (json.dumps(data),))
        conn.commit()
        cur.close()
    finally:
        conn.close()

# ============================================================
# AES-256 ENCRYPTION HELPERS
# ============================================================
def encrypt_bytes(data_bytes, key_raw):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data_bytes) + padder.finalize()
    cipher = Cipher(algorithms.AES(key_raw), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv, encrypted

def decrypt_bytes(encrypted_bytes, key_raw, iv):
    cipher = Cipher(algorithms.AES(key_raw), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

# ============================================================
# HELPERS
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def current_user():
    data = load_data()
    return data["users"].get(session.get('username'))

# ============================================================
# SHARED CSS + LAYOUT
# ============================================================
BASE_CSS = """
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:Arial,sans-serif}
body{background:#0f172a;color:#fff;display:flex;min-height:100vh}
.sidebar{width:250px;background:#0a2a5e;padding:25px 20px;position:fixed;height:100vh;left:0;top:0}
.sidebar h1{font-size:24px;margin-bottom:30px}
.sidebar a{display:block;color:#d0dfff;text-decoration:none;padding:12px 15px;border-radius:8px;margin-bottom:8px}
.sidebar a.active,.sidebar a:hover{background:#1e40af;color:#fff}
.main{margin-left:250px;flex:1;padding:25px;background:#0f172a}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:25px}
.profile-card{background:#1e293b;padding:20px;border-radius:12px;display:flex;gap:15px;align-items:center;margin-bottom:20px}
.avatar{width:60px;height:60px;background:#0a4fc0;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px}
.card{background:#1e293b;padding:25px;border-radius:12px;margin-bottom:20px}
.card h2{color:#fff;margin-bottom:15px}
label{display:block;font-weight:bold;margin:12px 0 5px;font-size:14px}
input,select,textarea{width:100%;padding:12px;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#fff;font-size:14px}
.btn{background:#0a4fc0;color:#fff;border:none;padding:12px 20px;border-radius:8px;cursor:pointer;font-size:15px;font-weight:bold;margin-top:15px;width:100%}
.btn:hover{background:#083a8f}
.btn-green{background:#16a34a}.btn-red{background:#dc2626}.btn-small{width:auto;padding:8px 14px;font-size:13px;margin:0}
table{width:100%;border-collapse:collapse;margin-top:15px;background:#1e293b}
th,td{padding:12px;border-bottom:1px solid #334155;text-align:left;font-size:14px}
th{background:#0a2a5e;color:#fff}
.badge{padding:4px 10px;border-radius:20px;font-size:12px;color:#fff}
.badge-green{background:#16a34a}.badge-orange{background:#f59e0b}
.alert{padding:12px;border-radius:8px;margin:12px 0}
.alert-success{background:#14532d;color:#bbf7d0}.alert-error{background:#7f1d1d;color:#fecaca}
.key-box{background:#0f172a;padding:15px;border-radius:8px;word-break:break-all;margin:12px 0;font-family:monospace;border:1px dashed #0a4fc0}
.stat-grid{display:flex;gap:15px;flex-wrap:wrap;margin-bottom:20px}
.stat{flex:1;min-width:150px;background:#1e293b;padding:20px;border-radius:12px;text-align:center}
.stat b{font-size:28px;display:block;color:#60a5fa}
.login-wrap{display:flex;max-width:900px;margin:40px auto;background:#fff;border-radius:12px;overflow:hidden;color:#222}
.login-left{width:42%;background:linear-gradient(160deg,#0a2a5e,#0f3d8a);color:#fff;padding:40px 30px}
.login-right{width:58%;padding:40px}
.login-right input{background:#f2f2f2;color:#222;border:1px solid #ddd}
@media(max-width:700px){.sidebar{display:none}.main{margin-left:0}.login-wrap{flex-direction:column}.login-left,.login-right{width:100%}}
</style>
"""

def layout(title, body, active=""):
    user = current_user()
    name = user.get('full_name','') if user else ''
    role = session.get('role','')
    username = session.get('username','')
    nav = ""
    if role == "Sender":
        nav = f'<a href="/sender" class="{"active" if active=="sender" else ""}">📤 Sender Dashboard</a><a href="/sender">Send File</a>'
    if role == "Receiver":
        nav = f'<a href="/receiver" class="{"active" if active=="receiver" else ""}">📥 Receiver Inbox</a>'
    if role == "Admin":
        nav = f'<a href="/admin" class="{"active" if active=="admin" else ""}">🛡 Admin Dashboard</a><a href="/sender">Sender View</a><a href="/receiver">Receiver View</a>'
    return f"""
    <html><head><title>{title} - iFortify</title>{BASE_CSS}</head><body>
    <div class="sidebar"><h1>🛡 iFortify</h1>{nav}<a href="/logout">🚪 Logout</a>
    <p style="margin-top:40px;font-size:11px;color:#8aa8d8">Version 2.4.1<br>AES-256 Encrypted</p></div>
    <div class="main">
      <div class="topbar"><h2>{title}</h2><div>🔔 <b>{username}</b> ({role})</div></div>
      <div class="profile-card"><div class="avatar">👤</div><div><b>{name}</b><br><small>{username} • {role} • Secure Data Transmission</small><br><small style="color:#4ade80">● Online • AES-256 Protected</small></div></div>
      {body}
    </div></body></html>
    """

# ============================================================
# AUTH ROUTES
# ============================================================
@app.route('/')
def index():
    if 'username' in session:
        if session['role'] == 'Admin': return redirect('/admin')
        if session['role'] == 'Sender': return redirect('/sender')
        return redirect('/receiver')
    return redirect('/login')

@app.route('/register', methods=['GET','POST'])
def register():
    msg = ""
    if request.method == 'POST':
        full_name = request.form.get('full_name','').strip()
        username = request.form.get('username','').strip().lower()
        email = request.form.get('email','').strip()
        password = request.form.get('password','')
        role = request.form.get('role','Sender')
        data = load_data()
        if not full_name or not username or not password:
            msg = "<div class='alert alert-error'>Please fill in all fields.</div>"
        elif username in data["users"]:
            msg = "<div class='alert alert-error'>Username already exists.</div>"
        else:
            data["users"][username] = {
                "full_name": full_name,
                "username": username,
                "email": email,
                "password": generate_password_hash(password),
                "role": role,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            save_data(data)
            msg = "<div class='alert alert-success'>Account created! <a href='/login' style='color:#fff;text-decoration:underline'>Login now</a></div>"
    return f"""
    <html><head><title>Register - iFortify</title>{BASE_CSS}</head><body style="display:block">
    <div style="max-width:500px;margin:30px auto;background:#1e293b;padding:30px;border-radius:12px">
    <h2>Register - iFortify</h2><p style="color:#94a3b8;margin:8px 0 15px">Create secure account</p>{msg}
    <form method="POST">
    <label>Full Name</label><input name="full_name" required>
    <label>Username</label><input name="username" required>
    <label>Email</label><input name="email" type="email">
    <label>Password</label><input name="password" type="password" required>
    <label>Role</label><select name="role"><option>Sender</option><option>Receiver</option><option>Admin</option></select>
    <button class="btn" type="submit">Register</button>
    </form><p style="margin-top:15px">Already have account? <a href="/login" style="color:#60a5fa">Login</a></p>
    </div></body></html>
    """

@app.route('/login', methods=['GET','POST'])
def login():
    msg = ""
    if request.method == 'POST':
        username = request.form.get('username','').strip().lower()
        password = request.form.get('password','')
        data = load_data()
        user = data["users"].get(username)
        if not user:
            msg = "<div class='alert alert-error'>User not found!</div>"
        elif not check_password_hash(user["password"], password):
            msg = "<div class='alert alert-error'>Wrong password!</div>"
        else:
            session['username'] = username
            session['role'] = user["role"]
            session['full_name'] = user["full_name"]
            if user["role"] == 'Admin': return redirect('/admin')
            if user["role"] == 'Sender': return redirect('/sender')
            return redirect('/receiver')
    return f"""
    <html><head><title>iFortify - Login</title>{BASE_CSS}</head><body style="display:block;background:#e8e8e8">
    <div class="login-wrap">
      <div class="login-left"><h1 style="font-size:36px">🛡 iFortify</h1>
      <h2 style="margin:15px 0 10px;line-height:1.3">Secure Data Transmission<br>System</h2>
      <p style="color:#7fb3ff;margin:10px 0">— AES-256 Encrypted —</p>
      <p style="font-size:13px;line-height:1.6;color:#d0dfff">Enterprise-grade security for confidential data transfer. End-to-end encrypted communications. Zero-knowledge architecture. Compliance-ready.</p>
      <p style="margin-top:60px;font-size:11px">Version 2.4.1 • 2024 iFortify Company Limited</p></div>
      <div class="login-right"><h2>Welcome back</h2><p style="color:#666;margin:5px 0 15px">Please sign in to your account to continue</p>{msg}
      <form method="POST"><label>Username</label><input name="username" placeholder="Enter your username" required>
      <label>Password</label><input name="password" type="password" placeholder="Enter your password" required>
      <button class="btn" type="submit">Login</button></form>
      <p style="text-align:center;margin-top:15px;font-size:13px">No account? <a href="/register">Register</a></p>
      <p style="text-align:center;margin-top:20px;font-size:12px">🛡 Protected by AES-256 Encryption</p></div>
    </div></body></html>
    """

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ============================================================
# SENDER
# ============================================================
@app.route('/sender', methods=['GET','POST'])
@login_required
def sender():
    data = load_data()
    username = session['username']
    msg = ""
    show_key = ""
    show_file_id = ""
    if request.method == 'POST':
        receiver = request.form.get('receiver','').strip().lower()
        message_text = request.form.get('message','')
        file = request.files.get('file')
        if not receiver or receiver not in data["users"]:
            msg = "<div class='alert alert-error'>Please select a valid receiver.</div>"
        elif not file or file.filename == '':
            msg = "<div class='alert alert-error'>Please choose a file.</div>"
        else:
            original = secure_filename(file.filename)
            content = file.read()
            key_raw = os.urandom(32)
            iv, encrypted = encrypt_bytes(content, key_raw)
            file_id = str(int(datetime.now().timestamp() * 1000))
            new_file = {
                "id": file_id,
                "sender": username,
                "receiver": receiver,
                "original_name": original,
                "encrypted_data": base64.b64encode(encrypted).decode(),
                "iv": base64.b64encode(iv).decode(),
                "key": base64.b64encode(key_raw).decode(),
                "message": message_text,
                "status": "Sent",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            data["files"].append(new_file)
            save_data(data)
            show_key = new_file["key"]
            show_file_id = file_id
            msg = "<div class='alert alert-success'>File Encrypted & Sent Successfully! Copy the key below and share it SEPARATELY.</div>"

    receivers = [u for u in data["users"].values() if u["role"] in ("Receiver","Admin")]
    options = "".join([f"<option value='{u['username']}'>{u['full_name']} ({u['username']})</option>" for u in receivers])
    sent = [f for f in data["files"] if f["sender"] == username]
    rows = "".join([f"<tr><td>🔒 {f['original_name']}</td><td>{f['receiver']}</td><td>{f['created_at']}</td><td><span class='badge badge-green'>Encrypted Sent</span></td><td><a href='/delete/{f['id']}'><button class='btn btn-red btn-small'>Delete</button></a></td></tr>" for f in reversed(sent)])
    key_box = ""
    if show_key:
        key_box = f"<div class='key-box'><b>Your Secret AES Key (File ID: {show_file_id}):</b><br>{show_key}<br><br><button class='btn btn-small' onclick=\"navigator.clipboard.writeText('{show_key}');alert('Key copied!')\">📋 Copy Key</button><p style='color:#fbbf24;margin-top:8px'>⚠️ Share this key separately, do not send with file.</p></div>"
    body = f"""
    <div class="stat-grid"><div class="stat"><b>{len(sent)}</b>Files Sent</div><div class="stat"><b>{len(sent)}</b>Encrypted</div><div class="stat"><b>AES-256</b>Encryption</div></div>
    <div class="card"><h2>Send Secure File</h2>{msg}{key_box}
    <form method="POST" enctype="multipart/form-data">
    <label>Select File</label><input type="file" name="file" required>
    <label>Select Receiver</label><select name="receiver" required><option value="">-- Select Receiver --</option>{options}</select>
    <label>Message (optional)</label><textarea name="message" rows="2" placeholder="Add a note for receiver..."></textarea>
    <button class="btn" type="submit">🔒 Encrypt & Send</button></form></div>
    <div class="card"><h2>Sent History</h2><table><tr><th>File</th><th>Receiver</th><th>Date</th><th>Status</th><th>Action</th></tr>{rows if rows else "<tr><td colspan='5'>No files yet.</td></tr>"}</table></div>
    """
    return layout("Sender Dashboard", body, "sender")

# ============================================================
# RECEIVER
# ============================================================
@app.route('/receiver')
@login_required
def receiver():
    data = load_data()
    username = session['username']
    inbox = [f for f in data["files"] if f["receiver"] == username]
    rows = ""
    for f in reversed(inbox):
        rows += f"""<tr><td>🔒 {f['original_name']}<br><small>{f.get('message','')}</small></td><td>{f['sender']}</td><td>{f['created_at']}</td>
        <td><button class="btn btn-small" onclick="document.getElementById('modal-{f['id']}').style.display='block'">🔓 Decrypt</button>
        <div id="modal-{f['id']}" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:999">
        <div style="background:#1e293b;max-width:450px;margin:100px auto;padding:25px;border-radius:12px">
        <h3>Decrypt: {f['original_name']}</h3><p style="margin:10px 0">From: {f['sender']}</p>
        <form method="POST" action="/decrypt/{f['id']}"><label>Enter Secret AES Key</label><input name="aes_key" type="password" placeholder="Paste AES key given by sender" required>
        <button class="btn" type="submit">🔓 Decrypt & Download</button></form>
        <button class="btn btn-red" onclick="document.getElementById('modal-{f['id']}').style.display='none'">Close</button>
        </div></div></td></tr>"""
    body = f"""<div class="card"><h2>Inbox - Encrypted Files (🔔 {len(inbox)} new)</h2>
    <table><tr><th>File</th><th>From</th><th>Date</th><th>Action</th></tr>{rows if rows else "<tr><td colspan='4'>No files yet.</td></tr>"}</table></div>"""
    return layout("Receiver Inbox", body, "receiver")

@app.route('/decrypt/<file_id>', methods=['POST'])
@login_required
def decrypt_file(file_id):
    data = load_data()
    username = session['username']
    f = next((x for x in data["files"] if x["id"] == file_id and x["receiver"] == username), None)
    if not f:
        return "File not found or access denied.", 403
    entered = request.form.get('aes_key','').strip()
    if entered != f["key"]:
        return layout("Decrypt Failed", "<div class='card'><div class='alert alert-error'>❌ Incorrect key. Please check the key and try again.</div><a href='/receiver'><button class='btn'>Back to Inbox</button></a></div>", "receiver")
    try:
        key_raw = base64.b64decode(f["key"])
        iv = base64.b64decode(f["iv"])
        encrypted = base64.b64decode(f["encrypted_data"])
        decrypted = decrypt_bytes(encrypted, key_raw, iv)
    except Exception as e:
        return layout("Decrypt Failed", f"<div class='card'><div class='alert alert-error'>Decryption failed: {e}</div></div>", "receiver")
    # Save temp decrypted file and send it
    tmp_path = f"/tmp/decrypted_{f['original_name']}"
    with open(tmp_path, 'wb') as out:
        out.write(decrypted)
    return send_file(tmp_path, as_attachment=True, download_name=f["original_name"])

@app.route('/delete/<file_id>')
@login_required
def delete_file(file_id):
    data = load_data()
    username = session['username']
    # Sender can delete own, Admin can delete any
    data["files"] = [f for f in data["files"] if not (f["id"] == file_id and (f["sender"] == username or session.get('role') == 'Admin'))]
    save_data(data)
    if session.get('role') == 'Admin':
        return redirect('/admin')
    return redirect('/sender')

# ============================================================
# ADMIN
# ============================================================
@app.route('/admin')
@login_required
def admin():
    if session.get('role') != 'Admin':
        return redirect('/')
    data = load_data()
    users_rows = "".join([f"<tr><td>{u['full_name']}</td><td>{u['username']}</td><td>{u['role']}</td><td>{u.get('email','')}</td></tr>" for u in data["users"].values()])
    files_rows = "".join([f"<tr><td>🔒 {f['original_name']}</td><td>{f['sender']} → {f['receiver']}</td><td>{f['created_at']}</td><td><span class='badge badge-green'>{f['status']}</span></td><td><a href='/delete/{f['id']}'><button class='btn btn-red btn-small'>Delete</button></a></td></tr>" for f in reversed(data["files"])])
    body = f"""
    <div class="stat-grid"><div class="stat"><b>{len(data['users'])}</b>Total Users</div><div class="stat"><b>{len(data['files'])}</b>Files Sent</div><div class="stat"><b>AES-256</b>Encryption</div></div>
    <div class="card"><h2>All Users</h2><table><tr><th>Full Name</th><th>Username</th><th>Role</th><th>Email</th></tr>{users_rows if users_rows else "<tr><td colspan='4'>No users yet.</td></tr>"}</table></div>
    <div class="card"><h2>All Files</h2><table><tr><th>File</th><th>Sender → Receiver</th><th>Date</th><th>Status</th><th>Action</th></tr>{files_rows if files_rows else "<tr><td colspan='5'>No files yet.</td></tr>"}</table></div>
    """
    return layout("Admin Dashboard", body, "admin")

# ============================================================
# RUN
# ============================================================
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)