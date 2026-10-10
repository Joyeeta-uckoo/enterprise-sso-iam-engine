import os
import uuid
import datetime
import time
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, render_template_string, redirect
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import mysql.connector

app = Flask(__name__, static_folder="static")
CORS(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-iam-key-change-in-prod")
DB_HOST = os.getenv("DB_HOST", "db")
DB_USER = os.getenv("DB_USER", "sso_user")
DB_PASS = os.getenv("DB_PASS", "sso_pass")
DB_NAME = os.getenv("DB_NAME", "sso_db")
ISSUER_URL = os.getenv("ISSUER_URL", "http://localhost:5001")

def get_db():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )

def init_db():
    for _ in range(10):
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES LIKE 'users'")
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            if result:
                break
        except mysql.connector.Error:
            time.sleep(2)

def log_event(event, target, status):
    ip = request.remote_addr
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO security_logs (event, target, status, ip_address) VALUES (%s, %s, %s, %s)",
            (event, target, status, ip)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error:
        pass

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"message": "Authorization token missing"}), 401
        
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM revoked_tokens WHERE jti = %s", (payload.get("jti"),))
            if cursor.fetchone():
                cursor.close()
                conn.close()
                return jsonify({"message": "Token has been revoked/logged out"}), 401
            
            cursor.close()
            conn.close()
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if getattr(request, "user", {}).get("role") != "admin":
            log_event("RBAC_CHECK", request.path, "DENIED")
            return jsonify({"message": "Forbidden: Admin privileges required"}), 403
        return f(*args, **kwargs)
    return decorated

# --- STATIC ROUTING ---
@app.route("/")
def index_page():
    return send_from_directory("static", "index.html")

@app.route("/dashboard")
def dashboard_page():
    return send_from_directory("static", "dashboard.html")

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "SSO & OIDC Engine Active"}), 200

# --- CORE AUTHENTICATION ENDPOINTS ---
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "user")

    if not username or not email or not password:
        return jsonify({"message": "Missing required fields"}), 400

    hashed_pw = generate_password_hash(password)

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_pw, role)
        )
        conn.commit()
        cursor.close()
        conn.close()
        log_event("USER_REGISTER", email, "SUCCESS")
        return jsonify({"message": "User registered successfully"}), 201
    except mysql.connector.Error as err:
        log_event("USER_REGISTER", email, "FAILED")
        return jsonify({"message": f"Database error: {err.msg}"}), 400

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Missing credentials"}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        cursor.close()
        conn.close()
        log_event("USER_LOGIN", email or "unknown", "FAILED")
        return jsonify({"message": "Invalid credentials"}), 401

    jti = str(uuid.uuid4())
    token_payload = {
        "jti": jti,
        "iss": ISSUER_URL,
        "sub": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
    }
    access_token = jwt.encode(token_payload, SECRET_KEY, algorithm="HS256")

    refresh_token = str(uuid.uuid4())
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    user_agent = request.headers.get("User-Agent", "Unknown")[:250]

    cursor_write = conn.cursor()
    cursor_write.execute(
        "INSERT INTO refresh_tokens (user_id, token, ip_address, user_agent, expires_at) VALUES (%s, %s, %s, %s, %s)",
        (user["id"], refresh_token, request.remote_addr, user_agent, expires_at)
    )
    conn.commit()
    cursor_write.close()
    cursor.close()
    conn.close()

    log_event("USER_LOGIN", email, "SUCCESS")

    return jsonify({
        "message": "Authentication successful",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "role": user["role"],
        "username": user["username"]
    }), 200

@app.route("/api/refresh", methods=["POST"])
def refresh():
    data = request.get_json() or {}
    refresh_token = data.get("refresh_token")

    if not refresh_token:
        return jsonify({"message": "Refresh token required"}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT r.*, u.username, u.email, u.role FROM refresh_tokens r JOIN users u ON r.user_id = u.id WHERE r.token = %s",
        (refresh_token,)
    )
    record = cursor.fetchone()

    if not record:
        cursor.close()
        conn.close()
        return jsonify({"message": "Invalid refresh token"}), 401

    if record["expires_at"].replace(tzinfo=datetime.timezone.utc) < datetime.datetime.now(datetime.timezone.utc):
        cursor_close = conn.cursor()
        cursor_close.execute("DELETE FROM refresh_tokens WHERE token = %s", (refresh_token,))
        conn.commit()
        cursor_close.close()
        cursor.close()
        conn.close()
        return jsonify({"message": "Refresh token expired"}), 401

    jti = str(uuid.uuid4())
    token_payload = {
        "jti": jti,
        "iss": ISSUER_URL,
        "sub": record["user_id"],
        "username": record["username"],
        "email": record["email"],
        "role": record["role"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
    }
    new_access_token = jwt.encode(token_payload, SECRET_KEY, algorithm="HS256")
    
    cursor.close()
    conn.close()

    log_event("TOKEN_REFRESH", record["email"], "SUCCESS")
    return jsonify({"access_token": new_access_token}), 200

# --- ACTIVE SESSION MANAGEMENT ENDPOINTS ---
@app.route("/api/user/sessions", methods=["GET"])
@token_required
def get_user_sessions():
    user_id = request.user.get("sub")
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, ip_address, user_agent, created_at FROM refresh_tokens WHERE user_id = %s ORDER BY created_at DESC",
        (user_id,)
    )
    sessions = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({"sessions": sessions}), 200

@app.route("/api/user/sessions/<int:session_id>", methods=["DELETE"])
@token_required
def revoke_user_session(session_id):
    user_id = request.user.get("sub")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM refresh_tokens WHERE id = %s AND user_id = %s", (session_id, user_id))
    conn.commit()
    cursor.close()
    conn.close()
    log_event("SESSION_REVOKE", f"SessionID:{session_id}", "SUCCESS")
    return jsonify({"message": "Session terminated successfully"}), 200

@app.route("/api/admin/sessions/<int:session_id>", methods=["DELETE"])
@token_required
@admin_required
def admin_revoke_session(session_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM refresh_tokens WHERE id = %s", (session_id,))
    conn.commit()
    cursor.close()
    conn.close()
    log_event("ADMIN_SESSION_TERMINATE", f"SessionID:{session_id}", "SUCCESS")
    return jsonify({"message": "Admin forced session termination"}), 200

# --- OAUTH 2.0 & OPENID CONNECT (OIDC) PROTOCOL ENGINE ---
@app.route("/.well-known/openid-configuration", methods=["GET"])
def oidc_config():
    return jsonify({
        "issuer": ISSUER_URL,
        "authorization_endpoint": f"{ISSUER_URL}/oauth/authorize",
        "token_endpoint": f"{ISSUER_URL}/oauth/token",
        "userinfo_endpoint": f"{ISSUER_URL}/oauth/userinfo",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"]
    }), 200

@app.route("/oauth/authorize", methods=["GET", "POST"])
def oauth_authorize():
    if request.method == "GET":
        client_id = request.args.get("client_id")
        redirect_uri = request.args.get("redirect_uri")
        response_type = request.args.get("response_type", "code")

        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM oauth_clients WHERE client_id = %s", (client_id,))
        client = cursor.fetchone()
        cursor.close()
        conn.close()

        if not client or client["redirect_uri"] != redirect_uri or response_type != "code":
            return jsonify({"error": "Invalid client_id or redirect_uri mismatch"}), 400

        login_form = f'''
        <!DOCTYPE html>
        <html>
        <head><title>OIDC SSO Consent Portal</title></head>
        <body style="font-family:sans-serif; background:#121212; color:#fff; display:flex; justify-content:center; align-items:center; height:100vh;">
            <div style="background:#1e1e1e; padding:30px; border-radius:8px; width:360px; text-align:center;">
                <h2 style="color:#00e676;">Authorize {client['client_name']}</h2>
                <p style="font-size:0.9em; color:#bbb;">The app is requesting permission to access your SSO Identity Profile.</p>
                <form method="POST">
                    <input type="hidden" name="client_id" value="{client_id}">
                    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                    <input type="email" name="email" placeholder="Email" style="width:100%; padding:10px; margin:8px 0; background:#2a2a2a; color:#fff; border:1px solid #333;" required><br>
                    <input type="password" name="password" placeholder="Password" style="width:100%; padding:10px; margin:8px 0; background:#2a2a2a; color:#fff; border:1px solid #333;" required><br>
                    <button type="submit" style="width:100%; padding:10px; background:#00e676; border:none; color:#000; font-weight:bold; cursor:pointer; margin-top:10px;">Authorize & Sign In</button>
                </form>
            </div>
        </body>
        </html>
        '''
        return render_template_string(login_form)

    email = request.form.get("email")
    password = request.form.get("password")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        cursor.close()
        conn.close()
        return "Invalid credentials provided for OAuth authorization", 401

    auth_code = str(uuid.uuid4())
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)

    cursor_write = conn.cursor()
    cursor_write.execute(
        "INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, expires_at) VALUES (%s, %s, %s, %s, %s)",
        (auth_code, client_id, user["id"], redirect_uri, expires_at)
    )
    conn.commit()
    cursor_write.close()
    cursor.close()
    conn.close()

    log_event("OAUTH_AUTHORIZE", email, "SUCCESS")
    return redirect(f"{redirect_uri}?code={auth_code}")

@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    redirect_uri = request.form.get("redirect_uri")

    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM oauth_clients WHERE client_id = %s AND client_secret = %s", (client_id, client_secret))
    client = cursor.fetchone()

    if not client:
        cursor.close()
        conn.close()
        return jsonify({"error": "invalid_client"}), 401

    cursor.execute("SELECT * FROM oauth_codes WHERE code = %s AND used = FALSE", (code,))
    code_record = cursor.fetchone()

    if not code_record or code_record["redirect_uri"] != redirect_uri:
        cursor.close()
        conn.close()
        return jsonify({"error": "invalid_grant"}), 400

    cursor_write = conn.cursor()
    cursor_write.execute("UPDATE oauth_codes SET used = TRUE WHERE id = %s", (code_record["id"],))
    conn.commit()
    cursor_write.close()

    cursor.execute("SELECT * FROM users WHERE id = %s", (code_record["user_id"],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    now = datetime.datetime.now(datetime.timezone.utc)
    
    id_token_claims = {
        "iss": ISSUER_URL,
        "sub": str(user["id"]),
        "aud": client_id,
        "exp": now + datetime.timedelta(hours=1),
        "iat": now,
        "email": user["email"],
        "preferred_username": user["username"],
        "role": user["role"]
    }
    id_token = jwt.encode(id_token_claims, SECRET_KEY, algorithm="HS256")

    access_token_claims = {
        "jti": str(uuid.uuid4()),
        "iss": ISSUER_URL,
        "sub": user["id"],
        "role": user["role"],
        "exp": now + datetime.timedelta(minutes=30)
    }
    access_token = jwt.encode(access_token_claims, SECRET_KEY, algorithm="HS256")

    log_event("OIDC_TOKEN_ISSUED", user["email"], "SUCCESS")

    return jsonify({
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 1800
    }), 200

@app.route("/oauth/userinfo", methods=["GET"])
@token_required
def oidc_userinfo():
    user_id = request.user.get("sub")
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({"error": "user_not_found"}), 404

    return jsonify({
        "sub": str(user["id"]),
        "email": user["email"],
        "preferred_username": user["username"],
        "role": user["role"]
    }), 200

@app.route("/oauth/callback/demo", methods=["GET"])
def demo_callback():
    code = request.args.get("code")
    return jsonify({
        "message": "Demo Application Received Authorization Code from IdP!",
        "received_code": code,
        "next_step": "Exchange this code at POST /oauth/token for OIDC ID Tokens"
    }), 200

# --- AUDIT LOGS & LOGOUT ENDPOINTS ---
@app.route("/api/user/profile", methods=["GET"])
@token_required
def profile():
    return jsonify({
        "message": "Protected profile accessed",
        "user_info": request.user
    }), 200

@app.route("/api/admin/audit-logs", methods=["GET"])
@token_required
@admin_required
def admin_audit_logs():
    log_event("RBAC_CHECK", "/api/admin/audit-logs", "GRANTED")
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT event, target, status, ip_address, timestamp FROM security_logs ORDER BY id DESC LIMIT 50")
    logs = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify({
        "message": "Admin Security Portal Accessed",
        "audit_logs": logs
    }), 200

@app.route("/api/logout", methods=["POST"])
@token_required
def logout():
    jti = request.user.get("jti")
    email = request.user.get("email")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO revoked_tokens (jti) VALUES (%s)", (jti,))
    conn.commit()
    cursor.close()
    conn.close()

    log_event("TOKEN_REVOKE", email, "SUCCESS")
    return jsonify({"message": "Successfully logged out & token revoked"}), 200

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)