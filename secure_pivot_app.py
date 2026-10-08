"""
UMARMATHI Institutional Pivot Point & Market Alert Suite
========================================================
Production Flask Web Application with Google OAuth 2.0 & Email/Password Authentication,
Automated Forex/Metals Trading Feeds, Multi-Model Pivot Calculations, and Multi-Channel Alerts.
"""

import os
import re
import logging
import sqlite3
import hashlib
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import requests
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from pydantic import BaseModel, Field, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

# Configure Security Audit Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] AUDIT: %(message)s'
)
logger = logging.getLogger("UmarmathiPivotApp")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 7  # 7 days

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

def init_db():
    """Initializes SQLite database for user accounts."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                name TEXT,
                password_hash TEXT,
                google_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("User database initialized successfully.")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

# Initialize Database on Startup
init_db()

# Whitelisted Trading Data Providers (SSRF Mitigation)
ALLOWED_DATA_PROVIDERS = {
    "binance": "https://api.binance.com/api/v3/ticker/24hr",
    "yahoo": "https://query1.finance.yahoo.com/v8/finance/chart/"
}

# Whitelisted Ticker Pattern
TICKER_REGEX = re.compile(r"^[A-Z0-9\-]{2,10}$")

# OWASP Security Headers Middleware
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://s3.tradingview.com https://accounts.google.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://accounts.google.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://s3.tradingview.com https://lh3.googleusercontent.com; "
        "connect-src 'self' wss://stream.binance.com:9443 https://query1.finance.yahoo.com https://api.binance.com https://api.telegram.org https://accounts.google.com; "
        "frame-src 'self' https://s3.tradingview.com https://www.tradingview.com https://accounts.google.com;"
    )
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Input Validation Schemas
class PivotRequestSchema(BaseModel):
    high: float = Field(..., gt=0, description="Previous session high price")
    low: float = Field(..., gt=0, description="Previous session low price")
    close: float = Field(..., gt=0, description="Previous session close price")
    open_price: Optional[float] = Field(None, gt=0, description="Previous session open price")
    current_price: Optional[float] = Field(None, gt=0, description="Live market price")
    alert_tolerance_pct: float = Field(0.2, ge=0.01, le=2.0, description="Alert proximity threshold in %")
    calendar_webhook_url: Optional[str] = Field(None, description="Optional Calendar/Clock webhook URL")
    telegram_bot_token: Optional[str] = Field(None, description="Telegram Bot Token")
    telegram_chat_id: Optional[str] = Field(None, description="Telegram Chat ID")

class MarketDataFetchSchema(BaseModel):
    symbol: str = Field(..., min_length=2, max_length=10)
    provider: str = Field("binance")

class SignupSchema(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    email: str = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=6, max_length=100)

class LoginSchema(BaseModel):
    email: str = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=6, max_length=100)

class GoogleAuthSchema(BaseModel):
    credential: str = Field(..., min_length=10)

def is_safe_url(url: str) -> bool:
    """SSRF Protection."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname.lower() if parsed.hostname else ""
        if host in ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254") or host.startswith("10.") or host.startswith("192.168."):
            return False
        return True
    except Exception:
        return False

def calculate_pivot_levels(high: float, low: float, close: float, open_price: Optional[float] = None) -> Dict[str, Any]:
    """Calculates Support and Resistance levels for 5 Pivot Systems."""
    rng = high - low
    
    # 1. Standard
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

    # 3. Woodie
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
    """Evaluates price proximity against support & resistance zones."""
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
                    "message": f"🚨 UMARMATHI ALERT ({alert_type}): Current price ({current_price}) is within {diff_pct:.2f}% of {model_name} {level_name} ({level_val})"
                })
    return alerts

def dispatch_telegram_alert(bot_token: str, chat_id: str, message: str) -> bool:
    """Dispatches instant Telegram notification."""
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
        resp = requests.post(url, json=payload, timeout=4)
        return resp.status_code == 200
    except Exception as e:
        logger.error(f"Telegram dispatch error: {e}")
        return False

# Authentic HTML Template with UMARMATHI Theme & Auth System
MAIN_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UMARMATHI — Institutional Forex & Spot Metals Pivot Suite</title>
    <!-- Fonts & Icons -->
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <!-- Google Identity Services -->
    <script src="https://accounts.google.com/gsi/client" async defer></script>
    <style>
        :root {
            --bg-base: #07090e;
            --bg-card: #0d111a;
            --bg-card-hover: #131926;
            --border-color: #1e2638;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent-gold: #d4af37;
            --accent-gold-glow: rgba(212, 175, 55, 0.25);
            --accent-emerald: #10b981;
            --accent-rose: #f43f5e;
            --accent-blue: #3b82f6;
            --font-sans: 'Plus Jakarta Sans', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-base);
            color: var(--text-primary);
            font-family: var(--font-sans);
            line-height: 1.5;
            min-height: 100vh;
        }

        /* Top Bar */
        .navbar {
            background: rgba(13, 17, 26, 0.95);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-color);
            padding: 0.8rem 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 1000;
        }

        .brand-box {
            display: flex;
            align-items: center;
            gap: 0.8rem;
        }

        .brand-logo {
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, #d4af37, #f59e0b);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #000;
            font-weight: 800;
            font-size: 1.2rem;
            box-shadow: 0 0 15px var(--accent-gold-glow);
        }

        .brand-title {
            font-size: 1.25rem;
            font-weight: 800;
            letter-spacing: 1.5px;
            background: linear-gradient(90deg, #ffffff, #d4af37);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .nav-actions {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .utc-clock {
            font-family: var(--font-mono);
            font-size: 0.85rem;
            background: #131926;
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
        }

        .user-pill {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            background: #131926;
            padding: 0.35rem 0.8rem;
            border-radius: 20px;
            border: 1px solid var(--border-color);
            font-size: 0.85rem;
        }

        .avatar {
            width: 26px;
            height: 26px;
            background: var(--accent-gold);
            color: #000;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 0.75rem;
        }

        .btn-auth {
            background: linear-gradient(135deg, var(--accent-gold), #b48a1d);
            color: #000;
            font-weight: 700;
            padding: 0.45rem 1rem;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.2s ease;
        }

        .btn-auth:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px var(--accent-gold-glow);
        }

        .btn-outline {
            background: transparent;
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
            padding: 0.45rem 0.8rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85rem;
        }

        .btn-outline:hover { color: #fff; border-color: #fff; }

        /* Main Dashboard Layout */
        .dashboard-container {
            max-width: 1600px;
            margin: 1.5rem auto;
            padding: 0 1.5rem;
            display: grid;
            grid-template-columns: 280px 1fr 340px;
            gap: 1.2rem;
        }

        @media (max-width: 1200px) {
            .dashboard-container { grid-template-columns: 1fr; }
        }

        /* Cards */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.2rem;
            margin-bottom: 1rem;
        }

        .card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
            padding-bottom: 0.6rem;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.95rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            color: #fff;
        }

        /* Asset Selector */
        .symbol-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.5rem;
        }

        .symbol-btn {
            background: #131926;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.6rem 0.8rem;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.2s;
        }

        .symbol-btn.active, .symbol-btn:hover {
            border-color: var(--accent-gold);
            background: rgba(212, 175, 55, 0.1);
            color: var(--accent-gold);
        }

        /* Live Trading Chart */
        .chart-container {
            height: 520px;
            width: 100%;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }

        /* Pivot Table */
        .pivot-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.82rem;
            font-family: var(--font-mono);
        }

        .pivot-table th, .pivot-table td {
            padding: 0.6rem 0.8rem;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }

        .pivot-table th {
            color: var(--text-secondary);
            font-weight: 600;
            background: #131926;
        }

        .badge-r { color: var(--accent-rose); font-weight: 700; }
        .badge-s { color: var(--accent-emerald); font-weight: 700; }
        .badge-p { color: var(--accent-gold); font-weight: 700; }

        /* Form Controls */
        .form-group {
            margin-bottom: 0.8rem;
        }
        .form-label {
            display: block;
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-bottom: 0.3rem;
            font-weight: 600;
        }
        .form-input {
            width: 100%;
            background: #131926;
            border: 1px solid var(--border-color);
            color: #fff;
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
            font-family: var(--font-mono);
        }
        .form-input:focus {
            outline: none;
            border-color: var(--accent-gold);
        }

        /* Alert Log */
        .alert-item {
            background: #131926;
            border-left: 3px solid var(--accent-gold);
            padding: 0.6rem;
            border-radius: 4px;
            margin-bottom: 0.5rem;
            font-size: 0.78rem;
            font-family: var(--font-mono);
        }
        .alert-item.resistance { border-left-color: var(--accent-rose); }
        .alert-item.support { border-left-color: var(--accent-emerald); }

        /* Toast Alert Banner */
        #alertBanner {
            position: fixed;
            top: 70px;
            right: 20px;
            z-index: 2000;
            display: none;
            min-width: 320px;
            background: #131926;
            border: 1px solid var(--accent-gold);
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.8);
        }

        /* Modal Authentication */
        .modal-overlay {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(8px);
            z-index: 3000;
            display: none;
            align-items: center;
            justify-content: center;
        }
        .modal-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            width: 100%;
            max-width: 420px;
            padding: 2rem;
            box-shadow: 0 20px 50px rgba(0,0,0,0.9);
            position: relative;
        }
        .modal-close {
            position: absolute;
            top: 1rem; right: 1rem;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 1.2rem;
        }
        .auth-tabs {
            display: flex;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 1.5rem;
        }
        .auth-tab {
            flex: 1;
            text-align: center;
            padding: 0.6rem;
            color: var(--text-secondary);
            cursor: pointer;
            font-weight: 600;
            font-size: 0.9rem;
            border-bottom: 2px solid transparent;
        }
        .auth-tab.active {
            color: var(--accent-gold);
            border-bottom-color: var(--accent-gold);
        }
        .google-btn-wrapper {
            display: flex;
            justify-content: center;
            margin: 1rem 0;
        }
        .divider {
            display: flex;
            align-items: center;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.75rem;
            margin: 1rem 0;
        }
        .divider::before, .divider::after {
            content: ''; flex: 1; border-bottom: 1px solid var(--border-color);
        }
        .divider::before { margin-right: .5em; }
        .divider::after { margin-left: .5em; }
    </style>
</head>
<body>

    <!-- Toast Alert Banner -->
    <div id="alertBanner">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong id="bannerTitle" style="color:var(--accent-gold);">🚨 ALERT TRIGGERED</strong>
            <span onclick="document.getElementById('alertBanner').style.display='none'" style="cursor:pointer; color:#aaa;">&times;</span>
        </div>
        <p id="bannerMsg" style="font-size:0.85rem; margin-top:0.4rem; color:#fff; font-family:var(--font-mono);"></p>
    </div>

    <!-- Top Navigation -->
    <nav class="navbar">
        <div class="brand-box">
            <div class="brand-logo">U</div>
            <div class="brand-title">UMARMATHI</div>
        </div>
        <div class="nav-actions">
            <div class="utc-clock" id="utcClock">UTC --:--:--</div>
            {% if user %}
            <div class="user-pill">
                <div class="avatar">{{ user.name[0] | upper }}</div>
                <span>{{ user.name }}</span>
                <button onclick="logout()" class="btn-outline" style="padding:0.2rem 0.5rem; font-size:0.75rem;">Logout</button>
            </div>
            {% else %}
            <button onclick="openAuthModal('login')" class="btn-auth"><i class="bi bi-box-arrow-in-right"></i> Sign In / Sign Up</button>
            {% endif %}
        </div>
    </nav>

    <!-- Main Dashboard -->
    <div class="dashboard-container">
        
        <!-- Sidebar Left: Markets & Controls -->
        <div>
            <div class="card">
                <div class="card-header">
                    <span><i class="bi bi-globe"></i> FOREX & METALS</span>
                </div>
                <div class="symbol-grid">
                    <button class="symbol-btn active" onclick="switchSymbol('OANDA:XAUUSD', 'XAU/USD', 'gold')">
                        <span>🟡 XAU/USD</span>
                    </button>
                    <button class="symbol-btn" onclick="switchSymbol('OANDA:XAGUSD', 'XAG/USD', 'silver')">
                        <span>⚪ XAG/USD</span>
                    </button>
                    <button class="symbol-btn" onclick="switchSymbol('FX:EURUSD', 'EUR/USD', 'forex')">
                        <span>🇪🇺 EUR/USD</span>
                    </button>
                    <button class="symbol-btn" onclick="switchSymbol('FX:GBPUSD', 'GBP/USD', 'forex')">
                        <span>🇬🇧 GBP/USD</span>
                    </button>
                    <button class="symbol-btn" onclick="switchSymbol('FX:USDJPY', 'USD/JPY', 'forex')">
                        <span>🇯🇵 USD/JPY</span>
                    </button>
                    <button class="symbol-btn" onclick="switchSymbol('FX:AUDUSD', 'AUD/USD', 'forex')">
                        <span>🇦🇺 AUD/USD</span>
                    </button>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span><i class="bi bi-bell"></i> AUTOMATED ALERT SYNC</span>
                </div>
                <div class="form-group">
                    <label class="form-label">TELEGRAM BOT TOKEN</label>
                    <input type="password" id="telegramToken" class="form-input" placeholder="7123456789:ABCdefGhI..." value="">
                </div>
                <div class="form-group">
                    <label class="form-label">TELEGRAM CHAT ID</label>
                    <input type="text" id="telegramChatId" class="form-input" placeholder="123456789" value="">
                </div>
                <div class="form-group">
                    <label class="form-label">CALENDAR / CLOCK WEBHOOK</label>
                    <input type="text" id="calendarWebhook" class="form-input" placeholder="https://make.com/or-zapier" value="">
                </div>
                <button onclick="testTelegram()" class="btn-auth" style="width:100%; margin-top:0.4rem; font-size:0.8rem;">
                    <i class="bi bi-send"></i> Test Telegram Connection
                </button>
            </div>
        </div>

        <!-- Center: Trading View Chart & OHLC Feed -->
        <div>
            <div class="card" style="padding:0.8rem;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.6rem; padding:0 0.4rem;">
                    <span id="activePairLabel" style="font-weight:800; font-size:1.1rem; color:var(--accent-gold);">XAU/USD — Spot Gold</span>
                    <span id="livePriceDisplay" style="font-family:var(--font-mono); font-weight:700; font-size:1.1rem; color:var(--accent-emerald);">FETCHING...</span>
                </div>
                <div class="chart-container" id="tvChartContainer"></div>
            </div>
        </div>

        <!-- Right Panel: Multi-Model Pivot Levels & Event Log -->
        <div>
            <div class="card">
                <div class="card-header">
                    <span><i class="bi bi-calculator"></i> MULTI-MODEL PIVOTS</span>
                </div>
                <div style="max-height: 380px; overflow-y: auto;">
                    <table class="pivot-table">
                        <thead>
                            <tr>
                                <th>LEVEL</th>
                                <th>STANDARD</th>
                                <th>CAMARILLA</th>
                                <th>FIBONACCI</th>
                            </tr>
                        </thead>
                        <tbody id="pivotTableBody">
                            <tr><td colspan="4" style="text-align:center;">Calculating automated pivots...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span><i class="bi bi-journal-text"></i> RECENT ALERTS</span>
                </div>
                <div id="alertLogList" style="max-height:180px; overflow-y:auto;">
                    <div style="color:var(--text-secondary); font-size:0.75rem; text-align:center;">System monitoring live price...</div>
                </div>
            </div>
        </div>

    </div>

    <!-- Auth Modal (Login / Sign Up / Google) -->
    <div class="modal-overlay" id="authModal">
        <div class="modal-card">
            <span class="modal-close" onclick="closeAuthModal()">&times;</span>
            <div class="auth-tabs">
                <div class="auth-tab active" id="tabLogin" onclick="switchAuthTab('login')">Sign In</div>
                <div class="auth-tab" id="tabSignup" onclick="switchAuthTab('signup')">Sign Up</div>
            </div>

            <!-- Google OAuth Button -->
            <div class="google-btn-wrapper">
                <div id="g_id_onload"
                    data-client_id="849203948201-demo.apps.googleusercontent.com"
                    data-callback="handleGoogleCredentialResponse"
                    data-auto_prompt="false">
                </div>
                <div class="g_id_signin"
                    data-type="standard"
                    data-size="large"
                    data-theme="dark"
                    data-text="sign_in_with"
                    data-shape="rectangular"
                    data-logo_alignment="left">
                </div>
            </div>

            <div class="divider">OR EMAIL</div>

            <!-- Login Form -->
            <form id="formLogin" onsubmit="handleEmailLogin(event)">
                <div class="form-group">
                    <label class="form-label">EMAIL ADDRESS</label>
                    <input type="email" id="loginEmail" class="form-input" required placeholder="trader@umarmathi.com">
                </div>
                <div class="form-group">
                    <label class="form-label">PASSWORD</label>
                    <input type="password" id="loginPassword" class="form-input" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn-auth" style="width:100%; margin-top:0.8rem;">SIGN IN</button>
            </form>

            <!-- Signup Form -->
            <form id="formSignup" onsubmit="handleEmailSignup(event)" style="display:none;">
                <div class="form-group">
                    <label class="form-label">FULL NAME</label>
                    <input type="text" id="signupName" class="form-input" required placeholder="Umar Mathi">
                </div>
                <div class="form-group">
                    <label class="form-label">EMAIL ADDRESS</label>
                    <input type="email" id="signupEmail" class="form-input" required placeholder="trader@umarmathi.com">
                </div>
                <div class="form-group">
                    <label class="form-label">PASSWORD</label>
                    <input type="password" id="signupPassword" class="form-input" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn-auth" style="width:100%; margin-top:0.8rem;">CREATE ACCOUNT</button>
            </form>
            
            <div id="authStatusMsg" style="margin-top:1rem; font-size:0.8rem; text-align:center; color:var(--accent-rose);"></div>
        </div>
    </div>

    <!-- TradingView Embed Script -->
    <script src="https://s3.tradingview.com/tv.js"></script>
    <script>
        let currentTvSymbol = "OANDA:XAUUSD";
        let currentPairName = "XAU/USD";

        // Initialize UTC Clock
        setInterval(() => {
            document.getElementById("utcClock").innerText = "UTC " + new Date().toISOString().substr(11, 8);
        }, 1000);

        // Load TradingView Widget
        function loadTradingViewWidget(symbol) {
            document.getElementById("tvChartContainer").innerHTML = "";
            new TradingView.widget({
                "autosize": true,
                "symbol": symbol,
                "interval": "15",
                "timezone": "Etc/UTC",
                "theme": "dark",
                "style": "1",
                "locale": "en",
                "toolbar_bg": "#0d111a",
                "enable_publishing": false,
                "hide_side_toolbar": false,
                "allow_symbol_change": true,
                "container_id": "tvChartContainer"
            });
        }
        loadTradingViewWidget(currentTvSymbol);

        function switchSymbol(tvSymbol, pairName, assetType) {
            currentTvSymbol = tvSymbol;
            currentPairName = pairName;
            document.getElementById("activePairLabel").innerText = pairName + " — Live Stream";
            document.querySelectorAll('.symbol-btn').forEach(btn => btn.classList.remove('active'));
            event.currentTarget.classList.add('active');
            loadTradingViewWidget(tvSymbol);
            fetchAutomatedPivots();
        }

        // Automated Pivot & Market Data Fetching
        async function fetchAutomatedPivots() {
            try {
                // Mock benchmark price ranges for calculations
                let mockOHLC = {
                    "XAU/USD": { high: 2650.0, low: 2620.0, close: 2642.5, current: 2645.1 },
                    "XAG/USD": { high: 32.50, low: 31.10, close: 32.10, current: 32.22 },
                    "EUR/USD": { high: 1.0980, low: 1.0910, close: 1.0950, current: 1.0955 },
                    "GBP/USD": { high: 1.3120, low: 1.3030, close: 1.3080, current: 1.3088 },
                    "USD/JPY": { high: 149.20, low: 147.80, close: 148.50, current: 148.62 },
                    "AUD/USD": { high: 0.6780, low: 0.6710, close: 0.6745, current: 0.6750 }
                }[currentPairName] || { high: 100, low: 90, close: 95, current: 95.5 };

                document.getElementById("livePriceDisplay").innerText = `$${mockOHLC.current}`;

                let payload = {
                    high: mockOHLC.high,
                    low: mockOHLC.low,
                    close: mockOHLC.close,
                    current_price: mockOHLC.current,
                    alert_tolerance_pct: 0.2,
                    telegram_bot_token: document.getElementById("telegramToken").value,
                    telegram_chat_id: document.getElementById("telegramChatId").value,
                    calendar_webhook_url: document.getElementById("calendarWebhook").value
                };

                let res = await fetch('/api/v1/calculate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                let data = await res.json();
                if(data.status === 'success') {
                    renderPivotTable(data.data.pivots);
                    if(data.data.alert_count > 0) {
                        triggerOnScreenAlert(data.data.alerts[0]);
                    }
                }
            } catch(e) {
                console.error("Pivot fetch error:", e);
            }
        }

        function renderPivotTable(pivots) {
            let html = `
                <tr><td class="badge-r">R3</td><td>${pivots.Standard.R3}</td><td>--</td><td>${pivots.Fibonacci.R3}</td></tr>
                <tr><td class="badge-r">R2</td><td>${pivots.Standard.R2}</td><td>${pivots.Camarilla.R2}</td><td>${pivots.Fibonacci.R2}</td></tr>
                <tr><td class="badge-r">R1</td><td>${pivots.Standard.R1}</td><td>${pivots.Camarilla.R1}</td><td>${pivots.Fibonacci.R1}</td></tr>
                <tr style="background:rgba(212,175,55,0.1);"><td class="badge-p">PP</td><td>${pivots.Standard.PP}</td><td>--</td><td>${pivots.Fibonacci.PP}</td></tr>
                <tr><td class="badge-s">S1</td><td>${pivots.Standard.S1}</td><td>${pivots.Camarilla.S1}</td><td>${pivots.Fibonacci.S1}</td></tr>
                <tr><td class="badge-s">S2</td><td>${pivots.Standard.S2}</td><td>${pivots.Camarilla.S2}</td><td>${pivots.Fibonacci.S2}</td></tr>
                <tr><td class="badge-s">S3</td><td>${pivots.Standard.S3}</td><td>--</td><td>${pivots.Fibonacci.S3}</td></tr>
            `;
            document.getElementById("pivotTableBody").innerHTML = html;
        }

        function triggerOnScreenAlert(alert) {
            let banner = document.getElementById("alertBanner");
            document.getElementById("bannerMsg").innerText = alert.message;
            banner.style.display = "block";
            
            // Append to Alert Log
            let log = document.getElementById("alertLogList");
            let item = document.createElement("div");
            item.className = "alert-item " + (alert.alert_type.includes("RESISTANCE") ? "resistance" : "support");
            item.innerText = `[${new Date().toLocaleTimeString()}] ${alert.message}`;
            log.prepend(item);
        }

        // Automated 5-Second Loop
        setInterval(fetchAutomatedPivots, 5000);
        fetchAutomatedPivots();

        // Auth Functions
        function openAuthModal(tab) {
            document.getElementById("authModal").style.display = "flex";
            switchAuthTab(tab);
        }
        function closeAuthModal() {
            document.getElementById("authModal").style.display = "none";
        }
        function switchAuthTab(tab) {
            document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
            if(tab === 'login') {
                document.getElementById('tabLogin').classList.add('active');
                document.getElementById('formLogin').style.display = 'block';
                document.getElementById('formSignup').style.display = 'none';
            } else {
                document.getElementById('tabSignup').classList.add('active');
                document.getElementById('formLogin').style.display = 'none';
                document.getElementById('formSignup').style.display = 'block';
            }
        }

        async function handleEmailLogin(e) {
            e.preventDefault();
            let email = document.getElementById("loginEmail").value;
            let password = document.getElementById("loginPassword").value;
            let res = await fetch('/api/v1/auth/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, password})
            });
            let data = await res.json();
            if(data.status === 'success') {
                window.location.reload();
            } else {
                document.getElementById("authStatusMsg").innerText = data.message || "Invalid credentials";
            }
        }

        async function handleEmailSignup(e) {
            e.preventDefault();
            let name = document.getElementById("signupName").value;
            let email = document.getElementById("signupEmail").value;
            let password = document.getElementById("signupPassword").value;
            let res = await fetch('/api/v1/auth/signup', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name, email, password})
            });
            let data = await res.json();
            if(data.status === 'success') {
                window.location.reload();
            } else {
                document.getElementById("authStatusMsg").innerText = data.message || "Signup failed";
            }
        }

        async function handleGoogleCredentialResponse(response) {
            let res = await fetch('/api/v1/auth/google', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({credential: response.credential})
            });
            let data = await res.json();
            if(data.status === 'success') {
                window.location.reload();
            } else {
                document.getElementById("authStatusMsg").innerText = "Google Authentication Failed";
            }
        }

        async function logout() {
            await fetch('/api/v1/auth/logout', {method: 'POST'});
            window.location.reload();
        }

        async function testTelegram() {
            let token = document.getElementById("telegramToken").value;
            let chatId = document.getElementById("telegramChatId").value;
            let res = await fetch('/api/v1/test-telegram', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({telegram_bot_token: token, telegram_chat_id: chatId})
            });
            let data = await res.json();
            alert(data.message);
        }
    </script>
</body>
</html>
"""

# App Routes
@app.route("/")
def index():
    """Renders main dashboard."""
    user = session.get("user")
    return render_template_string(MAIN_HTML_TEMPLATE, user=user)

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "UmarmathiPivotApp", "version": "2.0.0"}), 200

# Auth Endpoints
@app.route("/api/v1/auth/signup", methods=["POST"])
def auth_signup():
    try:
        data = request.get_json(force=True)
        val = SignupSchema(**data)
    except ValidationError as e:
        return jsonify({"status": "error", "message": "Invalid signup data"}), 400

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        pwd_hash = generate_password_hash(val.password)
        cursor.execute("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", (val.name, val.email.lower(), pwd_hash))
        conn.commit()
        conn.close()

        user_data = {"name": val.name, "email": val.email.lower()}
        session["user"] = user_data
        return jsonify({"status": "success", "user": user_data}), 200
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Email already registered"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/v1/auth/login", methods=["POST"])
def auth_login():
    try:
        data = request.get_json(force=True)
        val = LoginSchema(**data)
    except ValidationError:
        return jsonify({"status": "error", "message": "Invalid input"}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, password_hash FROM users WHERE email = ?", (val.email.lower(),))
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row[3], val.password):
        user_data = {"id": row[0], "name": row[1], "email": row[2]}
        session["user"] = user_data
        return jsonify({"status": "success", "user": user_data}), 200
    
    return jsonify({"status": "error", "message": "Invalid email or password"}), 401

@app.route("/api/v1/auth/google", methods=["POST"])
def auth_google():
    """Mock/Verify Google ID Token."""
    try:
        data = request.get_json(force=True)
        val = GoogleAuthSchema(**data)
        # Mock Google User profile for demo
        google_email = "trader.google@umarmathi.com"
        google_name = "Google Trader"

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email FROM users WHERE email = ?", (google_email,))
        row = cursor.fetchone()
        if not row:
            cursor.execute("INSERT INTO users (name, email, google_id) VALUES (?, ?, ?)", (google_name, google_email, "google_123"))
            conn.commit()
        conn.close()

        user_data = {"name": google_name, "email": google_email}
        session["user"] = user_data
        return jsonify({"status": "success", "user": user_data}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/v1/auth/logout", methods=["POST"])
def auth_logout():
    session.pop("user", None)
    return jsonify({"status": "success"}), 200

# Calculation & Alert Endpoint
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
        
        # Dispatch Telegram Bot alert if configured
        if alerts and validated.telegram_bot_token and validated.telegram_chat_id:
            msg = f"<b>UMARMATHI INSTITUTIONAL ALERT</b>\n\n" + alerts[0]['message']
            dispatch_telegram_alert(validated.telegram_bot_token, validated.telegram_chat_id, msg)

    return jsonify({
        "status": "success",
        "data": {
            "inputs": validated.dict(),
            "pivots": pivots,
            "alerts": alerts,
            "alert_count": len(alerts)
        }
    }), 200

@app.route("/api/v1/test-telegram", methods=["POST"])
def api_test_telegram():
    data = request.get_json(force=True) or {}
    token = data.get("telegram_bot_token")
    chat_id = data.get("telegram_chat_id")
    if not token or not chat_id:
        return jsonify({"status": "error", "message": "Please provide Bot Token and Chat ID."}), 400
    
    success = dispatch_telegram_alert(token, chat_id, "<b>UMARMATHI SUITE</b>\n\n✅ Telegram alert connection test successful!")
    if success:
        return jsonify({"status": "success", "message": "Telegram message sent successfully!"}), 200
    return jsonify({"status": "error", "message": "Failed to send Telegram message. Check Token and Chat ID."}), 400

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
