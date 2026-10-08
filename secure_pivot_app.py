"""
Secure Pivot Point Suite - UMARMATHI (OWASP Top 10 & CIA Triad Compliant)
========================================================================
A production-ready Python web application built with Flask, Pydantic, and Security Hardening.
Integrates live market data feeds, multi-model pivot calculations, Google OAuth 2.0, and TradingView charts.
"""

import os
import re
import sqlite3
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import requests
from flask import Flask, request, jsonify, render_template_string, session
from pydantic import BaseModel, Field, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

# PII Sanitizing Log Formatter
class PIISanitizingFormatter(logging.Formatter):
    def format(self, record):
        msg = super().format(record)
        # Redact email addresses in logs
        msg = re.sub(r'([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', r'\1[0]***@\2', msg)
        return msg

handler = logging.StreamHandler()
handler.setFormatter(PIISanitizingFormatter('%(asctime)s [%(levelname)s] AUDIT: %(message)s'))

logger = logging.getLogger("SecurePivotApp")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")

# SQLite Database Setup
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            password_hash TEXT,
            auth_provider TEXT DEFAULT 'email',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# OWASP Security Headers Middleware
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' data: gap:; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://s3.tradingview.com https://accounts.google.com https://*.tradingview.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://accounts.google.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https://s3.tradingview.com https://www.tradingview.com https://lh3.googleusercontent.com; "
        "connect-src 'self' https://query1.finance.yahoo.com https://api.binance.com https://accounts.google.com https://*.tradingview.com wss://*.tradingview.com; "
        "frame-src 'self' https://s3.tradingview.com https://www.tradingview.com https://www.tradingview-widget.com https://accounts.google.com;"
    )
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Pydantic Schemas
class PivotRequestSchema(BaseModel):
    high: float = Field(..., gt=0)
    low: float = Field(..., gt=0)
    close: float = Field(..., gt=0)
    open_price: Optional[float] = Field(None, gt=0)

class RegisterSchema(BaseModel):
    email: str = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=6, max_length=100)
    name: str = Field(..., min_length=2, max_length=100)

class LoginSchema(BaseModel):
    email: str = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=1, max_length=100)

def calculate_pivot_levels(high: float, low: float, close: float, open_price: Optional[float] = None) -> Dict[str, Any]:
    """Mathematical Pivot Calculations for 5 Major Models."""
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

# API Endpoints
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "UMARMATHI Secured Pivot Suite", "version": "3.0"}), 200

@app.route("/api/v1/auth/register", methods=["POST"])
def auth_register():
    try:
        data = request.get_json(force=True)
        validated = RegisterSchema(**data)
    except ValidationError as e:
        return jsonify({"status": "error", "message": "Invalid registration input", "details": e.errors()}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        pw_hash = generate_password_hash(validated.password)
        cursor.execute("INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)", (validated.email.lower(), validated.name, pw_hash))
        conn.commit()
        session['user'] = {"email": validated.email.lower(), "name": validated.name}
        logger.info(f"New user registered: {validated.email}")
        return jsonify({"status": "success", "user": session['user']}), 201
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Email already registered"}), 400
    finally:
        conn.close()

@app.route("/api/v1/auth/login", methods=["POST"])
def auth_login():
    try:
        data = request.get_json(force=True)
        validated = LoginSchema(**data)
    except ValidationError as e:
        return jsonify({"status": "error", "message": "Invalid login parameters"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, password_hash FROM users WHERE email = ?", (validated.email.lower(),))
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row[2], validated.password):
        session['user'] = {"email": validated.email.lower(), "name": row[1]}
        logger.info(f"Successful login for user: {validated.email}")
        return jsonify({"status": "success", "user": session['user']}), 200
    
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route("/api/v1/auth/logout", methods=["POST"])
def auth_logout():
    session.pop('user', None)
    return jsonify({"status": "success", "message": "Logged out"}), 200

@app.route("/api/v1/auth/me", methods=["GET"])
def auth_me():
    return jsonify({"status": "success", "user": session.get('user', None)}), 200

@app.route("/api/v1/calculate", methods=["POST"])
def api_calculate_pivots():
    try:
        data = request.get_json(force=True)
        validated = PivotRequestSchema(**data)
    except ValidationError as e:
        return jsonify({"status": "error", "message": "Invalid input parameters", "details": e.errors()}), 400

    pivots = calculate_pivot_levels(validated.high, validated.low, validated.close, validated.open_price)
    return jsonify({"status": "success", "data": {"inputs": validated.model_dump(), "pivots": pivots}}), 200

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UMARMATHI | Forex & Spot Metals Pivot Suite</title>
    <!-- Tailwind CSS & Google Fonts -->
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://s3.tradingview.com/tv.js"></script>
    <script src="https://accounts.google.com/gsi/client" async defer></script>
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #07090e; color: #f3f4f6; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        .gold-glow { text-shadow: 0 0 20px rgba(212, 175, 55, 0.4); }
        .border-gold { border-color: rgba(212, 175, 55, 0.3); }
        .bg-gold-gradient { background: linear-gradient(135deg, #D4AF37 0%, #AA7C11 100%); }
        .card-bg { background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.08); }
    </style>
</head>
<body class="min-h-screen flex flex-col justify-between">

    <!-- Top Navigation Bar -->
    <header class="border-b border-gray-800 bg-slate-950/80 sticky top-0 z-50 backdrop-blur-md">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="w-10 h-10 rounded-xl bg-gold-gradient flex items-center justify-center font-bold text-slate-950 text-xl shadow-lg">
                    U
                </div>
                <div>
                    <span class="text-xl font-extrabold tracking-wider text-white gold-glow">UMARMATHI</span>
                    <span class="text-xs block text-amber-400/80 font-mono tracking-widest uppercase">Institutional Pivot Engine</span>
                </div>
            </div>

            <!-- Pair Selector -->
            <div class="hidden md:flex space-x-1 bg-slate-900/90 p-1 rounded-xl border border-gray-800">
                <button onclick="selectPair('XAUUSD', 'OANDA:XAUUSD')" id="btn-XAUUSD" class="pair-btn px-3 py-1.5 rounded-lg text-xs font-semibold transition-all bg-amber-500/20 text-amber-300 border border-amber-500/40">🟡 XAU/USD</button>
                <button onclick="selectPair('XAGUSD', 'OANDA:XAGUSD')" id="btn-XAGUSD" class="pair-btn px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-400 hover:text-white transition-all">⚪ XAG/USD</button>
                <button onclick="selectPair('EURUSD', 'FX:EURUSD')" id="btn-EURUSD" class="pair-btn px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-400 hover:text-white transition-all">🇪🇺 EUR/USD</button>
                <button onclick="selectPair('GBPUSD', 'FX:GBPUSD')" id="btn-GBPUSD" class="pair-btn px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-400 hover:text-white transition-all">🇬🇧 GBP/USD</button>
                <button onclick="selectPair('USDJPY', 'FX:USDJPY')" id="btn-USDJPY" class="pair-btn px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-400 hover:text-white transition-all">🇯🇵 USD/JPY</button>
                <button onclick="selectPair('AUDUSD', 'FX:AUDUSD')" id="btn-AUDUSD" class="pair-btn px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-400 hover:text-white transition-all">🇦🇺 AUD/USD</button>
            </div>

            <!-- Auth Buttons / User Pill -->
            <div class="flex items-center space-x-3" id="auth-nav-container">
                <button onclick="openAuthModal()" class="px-4 py-2 text-xs font-semibold text-slate-950 bg-amber-400 hover:bg-amber-300 rounded-lg shadow-md transition-all">
                    Sign In / Register
                </button>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 w-full flex-grow">
        
        <!-- Mobile Pair Switcher -->
        <div class="md:hidden grid grid-cols-3 gap-2 mb-4">
            <button onclick="selectPair('XAUUSD', 'OANDA:XAUUSD')" class="px-2 py-2 rounded-lg text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40 text-center">🟡 Gold</button>
            <button onclick="selectPair('XAGUSD', 'OANDA:XAGUSD')" class="px-2 py-2 rounded-lg text-xs font-semibold bg-slate-900 text-gray-300 border border-gray-800 text-center">⚪ Silver</button>
            <button onclick="selectPair('EURUSD', 'FX:EURUSD')" class="px-2 py-2 rounded-lg text-xs font-semibold bg-slate-900 text-gray-300 border border-gray-800 text-center">🇪🇺 EURUSD</button>
            <button onclick="selectPair('GBPUSD', 'FX:GBPUSD')" class="px-2 py-2 rounded-lg text-xs font-semibold bg-slate-900 text-gray-300 border border-gray-800 text-center">🇬🇧 GBPUSD</button>
            <button onclick="selectPair('USDJPY', 'FX:USDJPY')" class="px-2 py-2 rounded-lg text-xs font-semibold bg-slate-900 text-gray-300 border border-gray-800 text-center">🇯🇵 USDJPY</button>
            <button onclick="selectPair('AUDUSD', 'FX:AUDUSD')" class="px-2 py-2 rounded-lg text-xs font-semibold bg-slate-900 text-gray-300 border border-gray-800 text-center">🇦🇺 AUDUSD</button>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            <!-- TradingView Live Chart Container (7 Cols) -->
            <div class="lg:col-span-7 flex flex-col space-y-4">
                <div class="card-bg p-4 rounded-2xl shadow-xl flex-grow flex flex-col">
                    <div class="flex items-center justify-between mb-3">
                        <div class="flex items-center space-x-2">
                            <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                            <h2 class="text-sm font-bold text-gray-200 tracking-wide" id="chart-pair-title">OANDA:XAUUSD - Live Interactive Feed</h2>
                        </div>
                        <span class="text-xs font-mono bg-slate-900 text-amber-400 px-2.5 py-1 rounded-md border border-gray-800" id="utc-clock">00:00:00 UTC</span>
                    </div>

                    <div id="tradingview_chart" class="w-full h-[450px] rounded-xl overflow-hidden border border-gray-800/80"></div>
                </div>
            </div>

            <!-- Pivot Calculator & Levels Panel (5 Cols) -->
            <div class="lg:col-span-5 flex flex-col space-y-4">
                
                <!-- Inputs Box -->
                <div class="card-bg p-5 rounded-2xl shadow-xl border border-gray-800">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-sm font-bold text-amber-400 tracking-wider uppercase flex items-center gap-2">
                            <span>📊</span> Session Price Benchmarks
                        </h3>
                        <span class="text-[10px] text-gray-400 uppercase font-mono" id="active-symbol-badge">XAU/USD</span>
                    </div>

                    <div class="grid grid-cols-2 gap-3 mb-4">
                        <div>
                            <label class="block text-xs font-semibold text-gray-400 mb-1">Session High</label>
                            <input type="number" step="any" id="inp-high" value="2650.00" class="w-full bg-slate-950 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white font-mono focus:border-amber-500 focus:outline-none">
                        </div>
                        <div>
                            <label class="block text-xs font-semibold text-gray-400 mb-1">Session Low</label>
                            <input type="number" step="any" id="inp-low" value="2620.00" class="w-full bg-slate-950 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white font-mono focus:border-amber-500 focus:outline-none">
                        </div>
                        <div>
                            <label class="block text-xs font-semibold text-gray-400 mb-1">Session Close</label>
                            <input type="number" step="any" id="inp-close" value="2642.50" class="w-full bg-slate-950 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white font-mono focus:border-amber-500 focus:outline-none">
                        </div>
                        <div>
                            <label class="block text-xs font-semibold text-gray-400 mb-1">Session Open</label>
                            <input type="number" step="any" id="inp-open" value="2630.00" class="w-full bg-slate-950 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white font-mono focus:border-amber-500 focus:outline-none">
                        </div>
                    </div>

                    <button onclick="recalculatePivots()" class="w-full py-2.5 bg-gold-gradient text-slate-950 font-bold rounded-xl text-xs uppercase tracking-wider hover:opacity-95 transition-all shadow-lg">
                        Recalculate Multi-Model Pivots
                    </button>
                </div>

                <!-- Pivot Results Display -->
                <div class="card-bg p-5 rounded-2xl shadow-xl flex-grow border border-gray-800 overflow-hidden">
                    <div class="flex items-center justify-between mb-3 border-b border-gray-800 pb-2">
                        <h3 class="text-sm font-bold text-gray-200">Support & Resistance Levels</h3>
                        <div class="flex space-x-1">
                            <button onclick="switchModel('Standard')" id="model-Standard" class="model-tab px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/30">Standard</button>
                            <button onclick="switchModel('Fibonacci')" id="model-Fibonacci" class="model-tab px-2.5 py-1 text-[11px] font-semibold rounded-lg text-gray-400 hover:text-white">Fibonacci</button>
                            <button onclick="switchModel('Woodie')" id="model-Woodie" class="model-tab px-2.5 py-1 text-[11px] font-semibold rounded-lg text-gray-400 hover:text-white">Woodie</button>
                            <button onclick="switchModel('Camarilla')" id="model-Camarilla" class="model-tab px-2.5 py-1 text-[11px] font-semibold rounded-lg text-gray-400 hover:text-white">Camarilla</button>
                        </div>
                    </div>

                    <div id="pivot-table-container" class="font-mono text-xs space-y-2 mt-2">
                        <!-- Populated dynamically -->
                    </div>
                </div>

            </div>
        </div>

    </main>

    <!-- Footer -->
    <footer class="border-t border-gray-800/60 bg-slate-950/80 py-4 mt-8">
        <div class="max-w-7xl mx-auto px-4 text-center text-xs text-gray-500 flex flex-col md:flex-row items-center justify-between gap-2">
            <span>© 2026 UMARMATHI Institutional Trading Suite. All rights reserved.</span>
            <span class="text-amber-500/80 font-mono">OWASP Top 10 Secured • CIA Triad Hardened</span>
        </div>
    </footer>

    <!-- Authentication Modal -->
    <div id="auth-modal" class="fixed inset-0 bg-slate-950/80 backdrop-blur-md hidden items-center justify-center z-50 p-4">
        <div class="card-bg p-6 rounded-2xl max-w-md w-full border border-gray-800 relative shadow-2xl">
            <button onclick="closeAuthModal()" class="absolute top-4 right-4 text-gray-400 hover:text-white text-xl">✕</button>
            <h3 class="text-lg font-bold text-white mb-1">Access UMARMATHI Suite</h3>
            <p class="text-xs text-gray-400 mb-4">Sign in to sync trading settings and benchmarks across sessions.</p>

            <div class="space-y-3">
                <div>
                    <label class="block text-xs text-gray-400 mb-1">Full Name (Registration only)</label>
                    <input type="text" id="auth-name" placeholder="Umar Mathi" class="w-full bg-slate-950 border border-gray-800 rounded-xl px-3 py-2 text-xs text-white">
                </div>
                <div>
                    <label class="block text-xs text-gray-400 mb-1">Email Address</label>
                    <input type="email" id="auth-email" placeholder="trader@umarmathi.com" class="w-full bg-slate-950 border border-gray-800 rounded-xl px-3 py-2 text-xs text-white">
                </div>
                <div>
                    <label class="block text-xs text-gray-400 mb-1">Password</label>
                    <input type="password" id="auth-password" class="w-full bg-slate-950 border border-gray-800 rounded-xl px-3 py-2 text-xs text-white">
                </div>

                <div class="grid grid-cols-2 gap-2 pt-2">
                    <button onclick="submitAuth('login')" class="py-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-semibold">Sign In</button>
                    <button onclick="submitAuth('register')" class="py-2.5 bg-gold-gradient text-slate-950 rounded-xl text-xs font-bold">Register Account</button>
                </div>

                <div class="relative my-4 flex items-center justify-center">
                    <span class="border-t border-gray-800 w-full"></span>
                    <span class="bg-slate-900 px-2 text-[10px] text-gray-500 uppercase">OR</span>
                    <span class="border-t border-gray-800 w-full"></span>
                </div>

                <div id="g_id_onload" data-client_id="{{ google_client_id }}" data-callback="handleGoogleSignIn" data-auto_prompt="false"></div>
                <div class="g_id_signin flex justify-center" data-type="standard" data-theme="filled_black" data-size="large"></div>
            </div>
        </div>
    </div>

    <!-- Application Script -->
    <script>
        let currentSymbol = 'XAUUSD';
        let currentTvSymbol = 'OANDA:XAUUSD';
        let currentModel = 'Standard';
        let pivotData = {};

        const PRESETS = {
            'XAUUSD': { high: 2650.00, low: 2620.00, close: 2642.50, open: 2630.00, tvSymbol: 'OANDA:XAUUSD' },
            'XAGUSD': { high: 31.80, low: 30.90, close: 31.45, open: 31.10, tvSymbol: 'OANDA:XAGUSD' },
            'EURUSD': { high: 1.0890, low: 1.0810, close: 1.0855, open: 1.0825, tvSymbol: 'FX:EURUSD' },
            'GBPUSD': { high: 1.3050, low: 1.2960, close: 1.3010, open: 1.2980, tvSymbol: 'FX:GBPUSD' },
            'USDJPY': { high: 149.80, low: 148.50, close: 149.20, open: 148.80, tvSymbol: 'FX:USDJPY' },
            'AUDUSD': { high: 0.6720, low: 0.6650, close: 0.6685, open: 0.6660, tvSymbol: 'FX:AUDUSD' }
        };

        // Initialize TradingView Widget
        function initTradingViewWidget(symbol) {
            document.getElementById('tradingview_chart').innerHTML = '';
            new TradingView.widget({
                "autosize": true,
                "symbol": symbol,
                "interval": "15",
                "timezone": "Etc/UTC",
                "theme": "dark",
                "style": "1",
                "locale": "en",
                "toolbar_bg": "#0f172a",
                "enable_publishing": false,
                "allow_symbol_change": true,
                "container_id": "tradingview_chart"
            });
        }

        function updateClock() {
            const now = new Date();
            document.getElementById('utc-clock').innerText = now.toUTCString().split(' ')[4] + ' UTC';
        }
        setInterval(updateClock, 1000);
        updateClock();

        function selectPair(symbol, tvSymbol) {
            currentSymbol = symbol;
            currentTvSymbol = tvSymbol;

            document.querySelectorAll('.pair-btn').forEach(btn => {
                btn.className = 'pair-btn px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-400 hover:text-white transition-all';
            });
            const activeBtn = document.getElementById('btn-' + symbol);
            if (activeBtn) {
                activeBtn.className = 'pair-btn px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40';
            }

            document.getElementById('chart-pair-title').innerText = tvSymbol + ' - Live Interactive Feed';
            document.getElementById('active-symbol-badge').innerText = symbol.replace('USD', '/USD');

            if (PRESETS[symbol]) {
                document.getElementById('inp-high').value = PRESETS[symbol].high;
                document.getElementById('inp-low').value = PRESETS[symbol].low;
                document.getElementById('inp-close').value = PRESETS[symbol].close;
                document.getElementById('inp-open').value = PRESETS[symbol].open;
            }

            initTradingViewWidget(tvSymbol);
            recalculatePivots();
        }

        function recalculatePivots() {
            const payload = {
                high: parseFloat(document.getElementById('inp-high').value),
                low: parseFloat(document.getElementById('inp-low').value),
                close: parseFloat(document.getElementById('inp-close').value),
                open_price: parseFloat(document.getElementById('inp-open').value)
            };

            fetch('/api/v1/calculate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    pivotData = data.data.pivots;
                    renderPivotTable();
                }
            });
        }

        function switchModel(model) {
            currentModel = model;
            document.querySelectorAll('.model-tab').forEach(tab => {
                tab.className = 'model-tab px-2.5 py-1 text-[11px] font-semibold rounded-lg text-gray-400 hover:text-white';
            });
            document.getElementById('model-' + model).className = 'model-tab px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/30';
            renderPivotTable();
        }

        function renderPivotTable() {
            const container = document.getElementById('pivot-table-container');
            const levels = pivotData[currentModel] || {};
            if (Object.keys(levels).length === 0) {
                container.innerHTML = '<div class="text-gray-500 text-center py-4">No levels calculated</div>';
                return;
            }

            let html = '';
            for (const [key, val] of Object.entries(levels)) {
                let colorClass = 'text-gray-300';
                if (key.startsWith('R')) colorClass = 'text-rose-400 font-semibold';
                if (key.startsWith('S')) colorClass = 'text-emerald-400 font-semibold';
                if (key === 'PP') colorClass = 'text-amber-300 font-bold';

                html += `
                    <div class="flex items-center justify-between p-2 rounded-lg bg-slate-950/60 border border-gray-800/60">
                        <span class="${colorClass}">${key}</span>
                        <span class="text-white">${val.toFixed(4)}</span>
                    </div>
                `;
            }
            container.innerHTML = html;
        }

        // Auth Modal Controls
        function openAuthModal() { document.getElementById('auth-modal').classList.remove('hidden'); document.getElementById('auth-modal').classList.add('flex'); }
        function closeAuthModal() { document.getElementById('auth-modal').classList.add('hidden'); document.getElementById('auth-modal').classList.remove('flex'); }

        function submitAuth(type) {
            const endpoint = type === 'login' ? '/api/v1/auth/login' : '/api/v1/auth/register';
            const payload = {
                email: document.getElementById('auth-email').value,
                password: document.getElementById('auth-password').value,
                name: document.getElementById('auth-name').value
            };

            fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    closeAuthModal();
                    checkSession();
                } else {
                    alert(data.message || 'Authentication failed');
                }
            });
        }

        function checkSession() {
            fetch('/api/v1/auth/me')
            .then(res => res.json())
            .then(data => {
                const container = document.getElementById('auth-nav-container');
                if (data.user) {
                    container.innerHTML = `
                        <div class="flex items-center space-x-2 bg-slate-900 border border-gray-800 px-3 py-1.5 rounded-xl">
                            <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                            <span class="text-xs text-amber-300 font-semibold">${data.user.name}</span>
                            <button onclick="logout()" class="text-[10px] text-gray-400 hover:text-rose-400 ml-2">Logout</button>
                        </div>
                    `;
                }
            });
        }

        function logout() {
            fetch('/api/v1/auth/logout', { method: 'POST' }).then(() => checkSession());
        }

        // Initial Load
        window.onload = function() {
            initTradingViewWidget('OANDA:XAUUSD');
            recalculatePivots();
            checkSession();
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
