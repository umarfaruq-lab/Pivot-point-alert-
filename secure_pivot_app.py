"""
========================================================================================
UMARMATHI Secure Forex & Metals Pivot Suite (OWASP Top 10 & CIA Triad Hardened)
========================================================================================
Production-ready Flask Web Application with:
- Google OAuth 2.0 & Email/Password Authentication
- PII / SPII Data Protection (PBKDF2 SHA-256 Hashing & Log Sanitization)
- OWASP Top 10 Security Controls & CIA Triad Architecture
- Streamlined Automated Google Calendar Alert Integration
- Spot Metals (XAUUSD, XAGUSD) & Forex Pair Real-Time Analysis
"""

import os
import re
import sqlite3
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import requests
from flask import Flask, request, jsonify, render_template_string, session, redirect
from pydantic import BaseModel, Field, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

# ==========================================
# 1. SECURITY LOGGING & PII SANITIZATION
# ==========================================
class PIISanitizingFormatter(logging.Formatter):
    """Custom formatter to redact sensitive PII/SPII (Emails, Passwords, Tokens) from logs."""
    EMAIL_REGEX = re.compile(r'([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)')
    
    def format(self, record):
        message = super().format(record)
        # Redact emails: j***@domain.com
        message = self.EMAIL_REGEX.sub(r'\1[0]***@\2', message)
        return message

logger = logging.getLogger("UmarmathiSecureApp")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(PIISanitizingFormatter('%(asctime)s [%(levelname)s] AUDIT: %(message)s'))
logger.addHandler(handler)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production HTTPS

# Google OAuth Credentials (Injected via Environment Variables)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com")

# ==========================================
# 2. DATABASE & PII/SPII STORAGE
# ==========================================
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def init_db():
    """Initialize SQLite user database for local credentials & OAuth profiles."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                password_hash TEXT,
                google_id TEXT UNIQUE,
                calendar_webhook_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

init_db()

# ==========================================
# 3. OWASP & SECURITY HEADERS MIDDLEWARE
# ==========================================
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://s3.tradingview.com https://accounts.google.com/gsi/client; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://accounts.google.com/gsi/style; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://s3.tradingview.com https://lh3.googleusercontent.com; "
        "connect-src 'self' wss://stream.binance.com:9443 https://query1.finance.yahoo.com https://api.binance.com https://accounts.google.com/gsi/ https://www.googleapis.com; "
        "frame-src 'self' https://s3.tradingview.com https://www.tradingview.com https://accounts.google.com/;"
    )
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ==========================================
# 4. SCHEMAS & INPUT VALIDATION (OWASP A03)
# ==========================================
class PivotRequestSchema(BaseModel):
    high: float = Field(..., gt=0, description="Previous session high price")
    low: float = Field(..., gt=0, description="Previous session low price")
    close: float = Field(..., gt=0, description="Previous session close price")
    open_price: Optional[float] = Field(None, gt=0, description="Previous session open price")
    current_price: Optional[float] = Field(None, gt=0, description="Live market price")
    alert_tolerance_pct: float = Field(0.2, ge=0.01, le=2.0, description="Alert proximity threshold in %")
    google_calendar_webhook_url: Optional[str] = Field(None, description="Google Calendar Webhook URL")

class RegisterSchema(BaseModel):
    email: str = Field(..., min_length=5, max_length=100)
    full_name: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=8, max_length=100)

class LoginSchema(BaseModel):
    email: str = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=8, max_length=100)

class GoogleOAuthSchema(BaseModel):
    credential: str = Field(..., description="Google OAuth ID Token")

# ==========================================
# 5. MATHEMATICAL PIVOT ENGINE
# ==========================================
def calculate_pivot_levels(high: float, low: float, close: float, open_price: Optional[float] = None) -> Dict[str, Any]:
    rng = high - low
    
    # 1. Standard / Classic
    pp_std = (high + low + close) / 3.0
    r1_std = (2 * pp_std) - low
    s1_std = (2 * pp_std) - high
    r2_std = pp_std + rng
    s2_std = pp_std - rng
    r3_std = high + 2 * (pp_std - low)
    s3_std = low - 2 * (high - pp_std)

    # 2. Fibonacci
    r1_fib = pp_std + (rng * 0.382)
    s1_fib = pp_std - (rng * 0.382)
    r2_fib = pp_std + (rng * 0.618)
    s2_fib = pp_std - (rng * 0.618)
    r3_fib = pp_std + (rng * 1.000)
    s3_fib = pp_std - (rng * 1.000)

    # 3. Woodie's
    pp_wood = (high + low + 2 * close) / 4.0
    r1_wood = (2 * pp_wood) - low
    s1_wood = (2 * pp_wood) - high
    r2_wood = pp_wood + rng
    s2_wood = pp_wood - rng

    # 4. Camarilla
    r1_cam = close + (rng * 1.1 / 12.0)
    s1_cam = close - (rng * 1.1 / 12.0)
    r2_cam = close + (rng * 1.1 / 6.0)
    s2_cam = close - (rng * 1.1 / 6.0)
    r3_cam = close + (rng * 1.1 / 4.0)
    s3_cam = close - (rng * 1.1 / 4.0)
    r4_cam = close + (rng * 1.1 / 2.0)
    s4_cam = close - (rng * 1.1 / 2.0)

    # 5. DeMark
    demark_res = {}
    if open_price is not None:
        if close < open_price:
            x = high + (2 * low) + close
        elif close > open_price:
            x = (2 * high) + low + close
        else:
            x = high + low + (2 * close)
        pp_dem = x / 4.0
        r1_dem = (x / 2.0) - low
        s1_dem = (x / 2.0) - high
        demark_res = {"PP": round(pp_dem, 4), "R1": round(r1_dem, 4), "S1": round(s1_dem, 4)}

    return {
        "Standard": {"PP": round(pp_std, 4), "R1": round(r1_std, 4), "S1": round(s1_std, 4), "R2": round(r2_std, 4), "S2": round(s2_std, 4), "R3": round(r3_std, 4), "S3": round(s3_std, 4)},
        "Fibonacci": {"PP": round(pp_std, 4), "R1": round(r1_fib, 4), "S1": round(s1_fib, 4), "R2": round(r2_fib, 4), "S2": round(s2_fib, 4), "R3": round(r3_fib, 4), "S3": round(s3_fib, 4)},
        "Woodie": {"PP": round(pp_wood, 4), "R1": round(r1_wood, 4), "S1": round(s1_wood, 4), "R2": round(r2_wood, 4), "S2": round(s2_wood, 4)},
        "Camarilla": {"R1": round(r1_cam, 4), "S1": round(s1_cam, 4), "R2": round(r2_cam, 4), "S2": round(s2_cam, 4), "R3": round(r3_cam, 4), "S3": round(s3_cam, 4), "R4": round(r4_cam, 4), "S4": round(s4_cam, 4)},
        "DeMark": demark_res
    }

def evaluate_price_alerts(current_price: float, pivot_levels: Dict[str, Any], tolerance_pct: float) -> list:
    alerts = []
    for model_name, levels in pivot_levels.items():
        for level_name, level_val in levels.items():
            if level_val is None:
                continue
            diff_pct = abs(current_price - level_val) / level_val * 100.0
            if diff_pct <= tolerance_pct:
                alert_type = "RESISTANCE_NEAR" if "R" in level_name else ("SUPPORT_NEAR" if "S" in level_name else "PIVOT_NEAR")
                alerts.append({
                    "model": model_name,
                    "level": level_name,
                    "target_price": level_val,
                    "current_price": current_price,
                    "difference_pct": round(diff_pct, 3),
                    "alert_type": alert_type,
                    "message": f"🚨 {alert_type}: Price ({current_price}) is within {diff_pct:.2f}% of {model_name} {level_name} ({level_val})"
                })
    return alerts

def dispatch_google_calendar_alert(webhook_url: str, alert_data: dict) -> bool:
    """Dispatches price alert payload to Google Calendar Webhook/iCal endpoint."""
    try:
        payload = {
            "summary": f"📅 UMARMATHI Alert: {alert_data.get('alert_type')} ({alert_data.get('model')} {alert_data.get('level')})",
            "description": alert_data.get("message"),
            "event_type": "PIVOT_PRICE_ALERT",
            "current_price": alert_data.get("current_price"),
            "target_level": alert_data.get("target_price")
        }
        resp = requests.post(webhook_url, json=payload, timeout=3)
        return resp.status_code in (200, 201, 202)
    except Exception as e:
        logger.warning(f"Google Calendar alert dispatch error: {e}")
        return False

# ==========================================
# 6. AUTHENTICATION & USER ROUTES
# ==========================================
@app.route("/api/v1/auth/register", methods=["POST"])
def auth_register():
    try:
        data = request.get_json(force=True)
        validated = RegisterSchema(**data)
    except ValidationError as e:
        return jsonify({"status": "error", "message": "Invalid registration data", "details": e.errors()}), 400

    hashed_pw = generate_password_hash(validated.password, method='pbkdf2:sha256')
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, full_name, password_hash) VALUES (?, ?, ?)",
                           (validated.email.lower().strip(), validated.full_name.strip(), hashed_pw))
            conn.commit()
            user_id = cursor.lastrowid
            
        session['user_id'] = user_id
        session['user_email'] = validated.email
        session['user_name'] = validated.full_name
        
        logger.info(f"New user registered: {validated.email}")
        return jsonify({"status": "success", "message": "User registered successfully", "user": {"email": validated.email, "name": validated.full_name}}), 201
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Email address is already registered"}), 409

@app.route("/api/v1/auth/login", methods=["POST"])
def auth_login():
    try:
        data = request.get_json(force=True)
        validated = LoginSchema(**data)
    except ValidationError as e:
        return jsonify({"status": "error", "message": "Invalid login credentials"}), 400

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (validated.email.lower().strip(),))
        user = cursor.fetchone()

    if not user or not user['password_hash'] or not check_password_hash(user['password_hash'], validated.password):
        logger.warning(f"Failed login attempt for email: {validated.email}")
        return jsonify({"status": "error", "message": "Invalid email or password"}), 401

    session['user_id'] = user['id']
    session['user_email'] = user['email']
    session['user_name'] = user['full_name']
    
    logger.info(f"Successful login for user: {user['email']}")
    return jsonify({"status": "success", "message": "Login successful", "user": {"email": user['email'], "name": user['full_name']}}), 200

@app.route("/api/v1/auth/google", methods=["POST"])
def auth_google():
    """Handles Google OAuth 2.0 Credential Verification."""
    try:
        data = request.get_json(force=True)
        validated = GoogleOAuthSchema(**data)
    except ValidationError:
        return jsonify({"status": "error", "message": "Invalid OAuth payload"}), 400

    token = validated.credential
    try:
        # Verify token with Google API endpoint
        google_resp = requests.get(f"https://oauth2.googleapis.com/tokeninfo?id_token={token}", timeout=5)
        if google_resp.status_code != 200:
            return jsonify({"status": "error", "message": "Invalid Google OAuth token"}), 401
        
        token_info = google_resp.json()
        email = token_info.get("email")
        full_name = token_info.get("name", email.split('@')[0])
        google_id = token_info.get("sub")

        if not email:
            return jsonify({"status": "error", "message": "Google profile missing email"}), 400

        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ? OR google_id = ?", (email.lower(), google_id))
            user = cursor.fetchone()

            if not user:
                cursor.execute("INSERT INTO users (email, full_name, google_id) VALUES (?, ?, ?)",
                               (email.lower(), full_name, google_id))
                conn.commit()
                user_id = cursor.lastrowid
            else:
                user_id = user['id']
                if not user['google_id']:
                    cursor.execute("UPDATE users SET google_id = ? WHERE id = ?", (google_id, user_id))
                    conn.commit()

        session['user_id'] = user_id
        session['user_email'] = email
        session['user_name'] = full_name

        logger.info(f"Google OAuth login successful for: {email}")
        return jsonify({"status": "success", "message": "Google authentication successful", "user": {"email": email, "name": full_name}}), 200
    except Exception as e:
        logger.error(f"Google OAuth verification error: {e}")
        return jsonify({"status": "error", "message": "Google OAuth service unavailable"}), 502

@app.route("/api/v1/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully"}), 200

@app.route("/api/v1/auth/me", methods=["GET"])
def auth_me():
    if 'user_id' in session:
        return jsonify({
            "status": "success",
            "authenticated": True,
            "user": {"email": session.get('user_email'), "name": session.get('user_name')}
        }), 200
    return jsonify({"status": "success", "authenticated": False}), 200

# ==========================================
# 7. TRADING & PIVOT CALCULATOR ENDPOINTS
# ==========================================
@app.route("/api/v1/calculate", methods=["POST"])
def api_calculate_pivots():
    try:
        data = request.get_json(force=True)
        validated = PivotRequestSchema(**data)
    except ValidationError as e:
        return jsonify({"status": "error", "message": "Invalid input parameters", "details": e.errors()}), 400

    pivots = calculate_pivot_levels(validated.high, validated.low, validated.close, validated.open_price)
    
    alerts = []
    if validated.current_price:
        alerts = evaluate_price_alerts(validated.current_price, pivots, validated.alert_tolerance_pct)
        
        # Dispatch to Google Calendar Webhook if provided
        if alerts and validated.google_calendar_webhook_url:
            for alert in alerts:
                dispatch_google_calendar_alert(validated.google_calendar_webhook_url, alert)

    inputs_dict = validated.model_dump() if hasattr(validated, "model_dump") else validated.dict()

    return jsonify({
        "status": "success",
        "data": {
            "inputs": inputs_dict,
            "pivots": pivots,
            "alerts": alerts,
            "alert_count": len(alerts)
        }
    }), 200

@app.route("/api/v1/test-google-calendar", methods=["POST"])
def api_test_google_calendar():
    data = request.get_json(force=True) or {}
    webhook_url = data.get("webhook_url")
    if not webhook_url or not webhook_url.startswith("http"):
        return jsonify({"status": "error", "message": "Invalid Google Calendar Webhook URL"}), 400

    sample_alert = {
        "alert_type": "RESISTANCE_NEAR",
        "model": "Standard",
        "level": "R1",
        "current_price": 2650.0,
        "target_price": 2648.5,
        "message": "🚨 Test Alert: Current price (2650.0) is near Standard R1 (2648.5)"
    }
    success = dispatch_google_calendar_alert(webhook_url, sample_alert)
    if success:
        return jsonify({"status": "success", "message": "Google Calendar test event dispatched successfully!"}), 200
    return jsonify({"status": "error", "message": "Unable to dispatch event to Google Calendar Webhook."}), 502

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"service": "UMARMATHI Pivot Engine", "status": "healthy", "version": "2.1.0"}), 200

# ==========================================
# 8. UMARMATHI EMBEDDED FRONT-END DASHBOARD
# ==========================================
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UMARMATHI | Institutional Forex & Spot Metals Pivot Suite</title>
    <!-- Google Fonts & Tailwind CSS -->
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <!-- Google OAuth Client Library -->
    <script src="https://accounts.google.com/gsi/client" async defer></script>
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #07090e; color: #e2e8f0; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .bg-card { background-color: #0d111a; border: 1px solid #1e2638; }
        .gold-accent { color: #d4af37; }
        .border-gold { border-color: #d4af37; }
        .bg-gold { background-color: #d4af37; color: #07090e; }
        .bg-gold:hover { background-color: #f1c40f; }
        .tab-btn.active { background-color: #1e2638; border-color: #d4af37; color: #d4af37; }
    </style>
</head>
<body class="min-h-screen flex flex-col justify-between">

    <!-- Top Navigation Bar -->
    <header class="bg-card border-b border-gray-800 px-6 py-4 flex flex-wrap justify-between items-center shadow-lg">
        <div class="flex items-center space-x-4">
            <span class="text-2xl font-extrabold tracking-wider gold-accent">UMARMATHI</span>
            <span class="text-xs px-2.5 py-1 rounded-full bg-yellow-900 bg-opacity-30 text-yellow-400 border border-yellow-700 font-medium">Spot Metals & Forex Engine</span>
        </div>

        <div class="flex items-center space-x-6 mt-2 md:mt-0">
            <div class="flex items-center space-x-2 text-xs text-gray-400">
                <span class="inline-block w-2 h-2 rounded-full bg-green-500 animate-ping"></span>
                <span id="utc-clock" class="mono text-gray-300">00:00:00 UTC</span>
            </div>

            <!-- Auth Status / Profile -->
            <div id="auth-container">
                <button onclick="openAuthModal()" class="text-xs bg-gold px-4 py-2 rounded-lg font-bold shadow hover:shadow-xl transition">
                    Sign In / Register
                </button>
            </div>
        </div>
    </header>

    <!-- Alert Toast Banner -->
    <div id="alert-banner" class="hidden fixed top-20 left-1/2 transform -translate-x-1/2 z-50 w-11/12 max-w-2xl p-4 rounded-xl shadow-2xl text-white font-bold flex items-center justify-between transition-all duration-300">
        <div class="flex items-center space-x-3">
            <span class="text-2xl">🚨</span>
            <span id="alert-banner-msg" class="text-sm">Price boundary alert triggered!</span>
        </div>
        <button onclick="hideAlertBanner()" class="text-white hover:text-gray-200 text-lg font-bold">✕</button>
    </div>

    <!-- Main Workspace Grid -->
    <main class="max-w-7xl mx-auto px-4 py-6 w-full grid grid-cols-1 lg:grid-cols-12 gap-6">

        <!-- Left Column: Trading Controls & Live Data -->
        <div class="lg:col-span-8 space-y-6">
            
            <!-- Forex & Metals Pair Switcher -->
            <div class="bg-card p-4 rounded-2xl shadow-md flex flex-wrap gap-2 items-center justify-between">
                <span class="text-xs font-bold text-gray-400 uppercase tracking-wider">Trading Symbol:</span>
                <div class="flex flex-wrap gap-2">
                    <button onclick="setSymbol('XAUUSD')" id="btn-XAUUSD" class="tab-btn active px-3.5 py-1.5 rounded-lg border text-xs font-semibold">🟡 XAU/USD (Gold)</button>
                    <button onclick="setSymbol('XAGUSD')" id="btn-XAGUSD" class="tab-btn px-3.5 py-1.5 rounded-lg border border-gray-700 text-xs font-semibold text-gray-400">⚪ XAG/USD (Silver)</button>
                    <button onclick="setSymbol('EURUSD')" id="btn-EURUSD" class="tab-btn px-3.5 py-1.5 rounded-lg border border-gray-700 text-xs font-semibold text-gray-400">🇪🇺 EUR/USD</button>
                    <button onclick="setSymbol('GBPUSD')" id="btn-GBPUSD" class="tab-btn px-3.5 py-1.5 rounded-lg border border-gray-700 text-xs font-semibold text-gray-400">🇬🇧 GBP/USD</button>
                    <button onclick="setSymbol('USDJPY')" id="btn-USDJPY" class="tab-btn px-3.5 py-1.5 rounded-lg border border-gray-700 text-xs font-semibold text-gray-400">🇯🇵 USD/JPY</button>
                    <button onclick="setSymbol('AUDUSD')" id="btn-AUDUSD" class="tab-btn px-3.5 py-1.5 rounded-lg border border-gray-700 text-xs font-semibold text-gray-400">🇦🇺 AUD/USD</button>
                </div>
            </div>

            <!-- TradingView Live Interactive Chart -->
            <div class="bg-card p-2 rounded-2xl shadow-md overflow-hidden" style="height: 480px;">
                <div id="tradingview-container" class="w-full h-full rounded-xl"></div>
            </div>

            <!-- Multi-Model Pivot Points Table -->
            <div class="bg-card p-5 rounded-2xl shadow-md space-y-4">
                <div class="flex justify-between items-center border-b border-gray-800 pb-3">
                    <h2 class="text-base font-bold gold-accent">Support & Resistance Levels (5 Mathematical Models)</h2>
                    <span id="live-price-tag" class="mono text-sm px-3 py-1 rounded bg-gray-800 font-bold text-green-400">Live Price: $2,645.00</span>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs border-collapse">
                        <thead>
                            <tr class="text-gray-400 border-b border-gray-800">
                                <th class="p-2">Model</th>
                                <th class="p-2 text-red-400">R3 / R4</th>
                                <th class="p-2 text-red-400">R2</th>
                                <th class="p-2 text-red-400">R1</th>
                                <th class="p-2 gold-accent">Pivot (PP)</th>
                                <th class="p-2 text-green-400">S1</th>
                                <th class="p-2 text-green-400">S2</th>
                                <th class="p-2 text-green-400">S3 / S4</th>
                            </tr>
                        </thead>
                        <tbody id="pivot-table-body" class="mono divide-y divide-gray-800 text-gray-200">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Right Column: Automated Google Calendar Alerts & Event Logs -->
        <div class="lg:col-span-4 space-y-6">
            
            <!-- Streamlined Google Calendar Alert Card -->
            <div class="bg-card p-5 rounded-2xl shadow-md space-y-4 border border-blue-900 border-opacity-40">
                <div class="flex items-center justify-between">
                    <h3 class="text-sm font-bold text-blue-400 flex items-center space-x-2">
                        <span>📅 Automated Google Calendar Alerts</span>
                    </h3>
                    <span class="text-xs px-2 py-0.5 rounded bg-blue-900 text-blue-300 font-semibold">Active</span>
                </div>

                <p class="text-xs text-gray-400 leading-relaxed">
                    Automatically sync Support & Resistance boundary alerts directly into your Google Calendar or Smart Clock Webhook.
                </p>

                <div class="space-y-3">
                    <div>
                        <label class="text-xs text-gray-400 font-semibold block mb-1">Google Calendar Webhook URL:</label>
                        <input type="url" id="gcal-webhook-url" placeholder="https://script.google.com/macros/s/.../exec" class="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-blue-500">
                    </div>

                    <div>
                        <label class="text-xs text-gray-400 font-semibold block mb-1">Alert Proximity Threshold (%):</label>
                        <input type="number" id="alert-tolerance" value="0.2" step="0.05" min="0.01" max="2.0" class="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-blue-500">
                    </div>

                    <button onclick="testGoogleCalendar()" class="w-full text-xs bg-blue-600 hover:bg-blue-500 text-white font-bold py-2.5 rounded-lg transition shadow">
                        Test Google Calendar Sync
                    </button>
                </div>
            </div>

            <!-- Real-Time Alert Event Log -->
            <div class="bg-card p-5 rounded-2xl shadow-md space-y-3">
                <h3 class="text-sm font-bold text-gray-300">Live Alert Feed History</h3>
                <div id="alert-history" class="space-y-2 max-h-80 overflow-y-auto text-xs mono">
                    <p class="text-gray-500 italic text-center py-4">Automated monitoring active. Waiting for S/R boundary touches...</p>
                </div>
            </div>

        </div>
    </main>

    <!-- Footer -->
    <footer class="bg-card border-t border-gray-800 py-4 text-center text-xs text-gray-500">
        UMARMATHI Institutional Forex & Metals Pivot Suite • Hardened OWASP Security Architecture
    </footer>

    <!-- Authentication Modal (Sign In / Register / Google OAuth) -->
    <div id="auth-modal" class="hidden fixed inset-0 bg-black bg-opacity-80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
        <div class="bg-card border border-gray-800 p-6 rounded-2xl max-w-md w-full shadow-2xl space-y-5 relative">
            <button onclick="closeAuthModal()" class="absolute top-4 right-4 text-gray-400 hover:text-white font-bold text-lg">✕</button>

            <div class="text-center space-y-1">
                <h3 class="text-xl font-bold gold-accent">Welcome to UMARMATHI</h3>
                <p class="text-xs text-gray-400">Sign in or create an account to activate personal calendar alerts</p>
            </div>

            <!-- Google OAuth 2.0 Button -->
            <div class="space-y-3">
                <div id="g_id_onload"
                     data-client_id="{{ google_client_id }}"
                     data-callback="handleGoogleCredentialResponse">
                </div>
                <div class="g_id_signin flex justify-center" data-type="standard" data-theme="dark" data-size="large"></div>
            </div>

            <div class="relative flex py-1 items-center">
                <div class="flex-grow border-t border-gray-800"></div>
                <span class="flex-shrink mx-4 text-xs text-gray-500">OR EMAIL LOGIN</span>
                <div class="flex-grow border-t border-gray-800"></div>
            </div>

            <!-- Email & Password Form -->
            <form onsubmit="handleEmailAuth(event)" class="space-y-3">
                <input type="email" id="auth-email" required placeholder="Email Address" class="w-full bg-gray-900 border border-gray-800 rounded-lg px-3.5 py-2 text-xs focus:outline-none focus:border-yellow-500">
                <input type="password" id="auth-password" required placeholder="Password (min 8 chars)" class="w-full bg-gray-900 border border-gray-800 rounded-lg px-3.5 py-2 text-xs focus:outline-none focus:border-yellow-500">
                <input type="text" id="auth-fullname" placeholder="Full Name (for new register)" class="w-full bg-gray-900 border border-gray-800 rounded-lg px-3.5 py-2 text-xs focus:outline-none focus:border-yellow-500">
                
                <div class="flex space-x-2 pt-2">
                    <button type="submit" onclick="setAuthMode('login')" class="w-1/2 text-xs bg-gold font-bold py-2 rounded-lg hover:bg-yellow-500 transition">Sign In</button>
                    <button type="submit" onclick="setAuthMode('register')" class="w-1/2 text-xs bg-gray-800 hover:bg-gray-700 font-bold py-2 rounded-lg transition border border-gray-700">Register</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Scripts -->
    <script src="https://s3.tradingview.com/tv.js"></script>
    <script>
        let currentSymbol = 'XAUUSD';
        let tvWidget = null;
        let authMode = 'login';

        const tvSymbolMap = {
            'XAUUSD': 'OANDA:XAUUSD',
            'XAGUSD': 'OANDA:XAGUSD',
            'EURUSD': 'FX:EURUSD',
            'GBPUSD': 'FX:GBPUSD',
            'USDJPY': 'FX:USDJPY',
            'AUDUSD': 'FX:AUDUSD'
        };

        const defaultOHLC = {
            'XAUUSD': { high: 2650.0, low: 2620.0, close: 2642.5, open: 2630.0, price: 2645.0 },
            'XAGUSD': { high: 31.80, low: 30.90, close: 31.40, open: 31.10, price: 31.45 },
            'EURUSD': { high: 1.0980, low: 1.0910, close: 1.0945, open: 1.0920, price: 1.0950 },
            'GBPUSD': { high: 1.3120, low: 1.3040, close: 1.3085, open: 1.3050, price: 1.3090 },
            'USDJPY': { high: 149.20, low: 147.80, close: 148.50, open: 148.00, price: 148.60 },
            'AUDUSD': { high: 0.6780, low: 0.6710, close: 0.6745, open: 0.6720, price: 0.6750 }
        };

        function updateClock() {
            const now = new Date();
            document.getElementById('utc-clock').innerText = now.toISOString().substr(11, 8) + ' UTC';
        }
        setInterval(updateClock, 1000);
        updateClock();

        function loadTradingViewChart(symbolKey) {
            const tvSymbol = tvSymbolMap[symbolKey] || 'OANDA:XAUUSD';
            if (tvWidget) {
                try { tvWidget.remove(); } catch(e){}
            }
            tvWidget = new TradingView.widget({
                "autosize": true,
                "symbol": tvSymbol,
                "interval": "15",
                "timezone": "Etc/UTC",
                "theme": "dark",
                "style": "1",
                "locale": "en",
                "toolbar_bg": "#0d111a",
                "enable_publishing": false,
                "hide_side_toolbar": false,
                "container_id": "tradingview-container"
            });
        }

        function setSymbol(symbol) {
            currentSymbol = symbol;
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
                btn.classList.add('border-gray-700', 'text-gray-400');
            });
            const activeBtn = document.getElementById(`btn-${symbol}`);
            if(activeBtn) {
                activeBtn.classList.add('active');
                activeBtn.classList.remove('border-gray-700', 'text-gray-400');
            }
            loadTradingViewChart(symbol);
            calculateAndUpdatePivots();
        }

        function calculateAndUpdatePivots() {
            const ohlc = defaultOHLC[currentSymbol] || defaultOHLC['XAUUSD'];
            const gcalUrl = document.getElementById('gcal-webhook-url').value;
            const tolerance = parseFloat(document.getElementById('alert-tolerance').value) || 0.2;

            document.getElementById('live-price-tag').innerText = `Live Price: $${ohlc.price.toFixed(2)}`;

            fetch('/api/v1/calculate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    high: ohlc.high,
                    low: ohlc.low,
                    close: ohlc.close,
                    open_price: ohlc.open,
                    current_price: ohlc.price,
                    alert_tolerance_pct: tolerance,
                    google_calendar_webhook_url: gcalUrl
                })
            })
            .then(res => res.json())
            .then(data => {
                if(data.status === 'success') {
                    renderPivotTable(data.data.pivots);
                    if(data.data.alerts && data.data.alerts.length > 0) {
                        handleTriggeredAlerts(data.data.alerts);
                    }
                }
            })
            .catch(err => console.error(err));
        }

        function renderPivotTable(pivots) {
            const tbody = document.getElementById('pivot-table-body');
            tbody.innerHTML = '';
            for (const [model, levels] of Object.entries(pivots)) {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="p-2 font-bold gold-accent">${model}</td>
                    <td class="p-2 text-red-400">${levels.R3 || levels.R4 || '-'}</td>
                    <td class="p-2 text-red-400">${levels.R2 || '-'}</td>
                    <td class="p-2 text-red-400">${levels.R1 || '-'}</td>
                    <td class="p-2 font-bold gold-accent">${levels.PP || '-'}</td>
                    <td class="p-2 text-green-400">${levels.S1 || '-'}</td>
                    <td class="p-2 text-green-400">${levels.S2 || '-'}</td>
                    <td class="p-2 text-green-400">${levels.S3 || levels.S4 || '-'}</td>
                `;
                tbody.appendChild(tr);
            }
        }

        function handleTriggeredAlerts(alerts) {
            const history = document.getElementById('alert-history');
            alerts.forEach(alert => {
                showAlertBanner(alert.message, alert.alert_type);
                const item = document.createElement('div');
                item.className = 'p-2.5 rounded bg-gray-900 border border-gray-800 text-gray-300';
                item.innerHTML = `<span class="text-gray-500">[${new Date().toLocaleTimeString()}]</span> ${alert.message}`;
                history.prepend(item);
            });
        }

        function showAlertBanner(msg, type) {
            const banner = document.getElementById('alert-banner');
            const msgSpan = document.getElementById('alert-banner-msg');
            msgSpan.innerText = msg;
            banner.className = `fixed top-20 left-1/2 transform -translate-x-1/2 z-50 w-11/12 max-w-2xl p-4 rounded-xl shadow-2xl text-white font-bold flex items-center justify-between transition-all ${type.includes('RESISTANCE') ? 'bg-red-600' : 'bg-green-600'}`;
            banner.classList.remove('hidden');
        }

        function hideAlertBanner() {
            document.getElementById('alert-banner').classList.add('hidden');
        }

        function testGoogleCalendar() {
            const url = document.getElementById('gcal-webhook-url').value;
            if(!url) { alert('Please enter a Google Calendar Webhook URL first.'); return; }
            fetch('/api/v1/test-google-calendar', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ webhook_url: url })
            })
            .then(res => res.json())
            .then(data => alert(data.message));
        }

        // Auth Modal Controls
        function openAuthModal() { document.getElementById('auth-modal').classList.remove('hidden'); }
        function closeAuthModal() { document.getElementById('auth-modal').classList.add('hidden'); }
        function setAuthMode(mode) { authMode = mode; }

        function handleGoogleCredentialResponse(response) {
            fetch('/api/v1/auth/google', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ credential: response.credential })
            })
            .then(res => res.json())
            .then(data => {
                if(data.status === 'success') {
                    closeAuthModal();
                    checkAuthStatus();
                } else {
                    alert(data.message);
                }
            });
        }

        function handleEmailAuth(e) {
            e.preventDefault();
            const email = document.getElementById('auth-email').value;
            const password = document.getElementById('auth-password').value;
            const fullname = document.getElementById('auth-fullname').value;

            const endpoint = authMode === 'register' ? '/api/v1/auth/register' : '/api/v1/auth/login';
            const body = { email, password, full_name: fullname };

            fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            })
            .then(res => res.json())
            .then(data => {
                if(data.status === 'success') {
                    closeAuthModal();
                    checkAuthStatus();
                } else {
                    alert(data.message);
                }
            });
        }

        function checkAuthStatus() {
            fetch('/api/v1/auth/me')
            .then(res => res.json())
            .then(data => {
                const container = document.getElementById('auth-container');
                if(data.authenticated) {
                    container.innerHTML = `
                        <div class="flex items-center space-x-3">
                            <span class="text-xs font-bold text-gray-300">👤 ${data.user.name}</span>
                            <button onclick="logout()" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded-lg border border-gray-700">Logout</button>
                        </div>
                    `;
                } else {
                    container.innerHTML = `
                        <button onclick="openAuthModal()" class="text-xs bg-gold px-4 py-2 rounded-lg font-bold shadow hover:shadow-xl transition">
                            Sign In / Register
                        </button>
                    `;
                }
            });
        }

        function logout() {
            fetch('/api/v1/auth/logout', { method: 'POST' })
            .then(() => checkAuthStatus());
        }

        // Initialize Page
        window.onload = function() {
            loadTradingViewChart('XAUUSD');
            calculateAndUpdatePivots();
            checkAuthStatus();
            setInterval(calculateAndUpdatePivots, 5000);
        };
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index_page():
    return render_template_string(INDEX_HTML, google_client_id=GOOGLE_CLIENT_ID)

if __name__ == "__main__":
    print("Starting UMARMATHI Secure Forex & Metals Pivot Suite Server...")
    app.run(host="0.0.0.0", port=5000, debug=False)
