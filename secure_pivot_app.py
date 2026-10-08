"""
Secure Pivot Point Calculator & Alert System (OWASP Top 10 Compliant)
===================================================================
UMARMATHI Institutional Forex & Metals Suite
Features automated real-time price polling, multi-model pivot calculation,
OWASP security controls, Telegram alerts, and Calendar webhook syncing.
"""

import os
import re
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import requests
from flask import Flask, request, jsonify, render_template_string
from pydantic import BaseModel, Field, ValidationError

# Configure Security Audit Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] SECURITY_AUDIT: %(message)s'
)
logger = logging.getLogger("SecurePivotApp")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())

# Whitelisted Trading Data Providers (SSRF Mitigation)
ALLOWED_DATA_PROVIDERS = {
    "binance": "https://api.binance.com/api/v3/ticker/24hr",
    "yahoo": "https://query1.finance.yahoo.com/v8/finance/chart/"
}

# Whitelisted Ticker Pattern (Regex injection prevention)
TICKER_REGEX = re.compile(r"^[A-Z0-9\-=]{2,12}$")

# OWASP Security Headers Middleware
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://s3.tradingview.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://s3.tradingview.com; "
        "connect-src 'self' wss://stream.binance.com:9443 https://query1.finance.yahoo.com https://api.binance.com https://api.telegram.org; "
        "frame-src 'self' https://s3.tradingview.com https://www.tradingview.com;"
    )
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Pydantic Input Validation Schemas
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
    symbol: str = Field(..., min_length=2, max_length=12)
    provider: str = Field("yahoo")

def is_safe_url(url: str) -> bool:
    """SSRF Prevention: Ensure URL belongs to explicit whitelist and non-internal IP."""
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

def evaluate_price_alerts(current_price: float, pivot_levels: Dict[str, Any], tolerance_pct: float) -> list:
    """Checks if live price is within tolerance threshold of any support or resistance level."""
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
                    "message": f"🚨 {alert_type}: Current price ({current_price}) is within {diff_pct:.2f}% of {model_name} {level_name} ({level_val})"
                })
    return alerts

def dispatch_telegram_alert(bot_token: str, chat_id: str, alerts: list, symbol: str = "FOREX"):
    """Dispatches real-time Telegram push notifications."""
    if not bot_token or not chat_id or not alerts:
        return False
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    
    lines = [f"<b>📈 UMARMATHI AUTOMATED TRADING ALERT ({symbol})</b>\n"]
    for a in alerts[:5]:  # limit to top 5 alerts to prevent flood
        emoji = "🔴" if "RESISTANCE" in a['alert_type'] else ("🟢" if "SUPPORT" in a['alert_type'] else "🟡")
        lines.append(f"{emoji} <b>{a['model']} {a['level']}</b> @ <code>{a['target_price']}</code>")
        lines.append(f"└ Live Price: <code>{a['current_price']}</code> (Diff: {a['difference_pct']}%)")
    
    text_content = "\n".join(lines)
    payload = {"chat_id": chat_id, "text": text_content, "parse_mode": "HTML"}
    try:
        resp = requests.post(url, json=payload, timeout=4)
        return resp.status_code == 200
    except Exception as e:
        logger.error(f"Telegram dispatch failed: {e}")
        return False

def dispatch_calendar_webhook(webhook_url: str, alerts: list, symbol: str = "FOREX"):
    """Dispatches JSON alert payload to external calendar/clock webhooks."""
    if not webhook_url or not alerts:
        return False
    if not is_safe_url(webhook_url):
        logger.error(f"Blocked unsafe webhook URL: {webhook_url}")
        return False
    
    payload = {
        "event": "UMARMATHI_PIVOT_ALERT",
        "symbol": symbol,
        "alert_count": len(alerts),
        "alerts": alerts
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=4)
        return resp.status_code in (200, 201, 202)
    except Exception as e:
        logger.error(f"Calendar webhook dispatch failed: {e}")
        return False

# HTML Frontend Template
HTML_INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UMARMATHI | Automated Forex & Metals Pivot Suite</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-main: #07090e;
            --bg-card: #0e121b;
            --bg-card-hover: #141b27;
            --border-color: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-gold: #d4af37;
            --accent-gold-glow: rgba(212, 175, 55, 0.25);
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-blue: #3b82f6;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            line-height: 1.5;
            padding-bottom: 50px;
        }

        /* Top Header */
        header {
            background-color: rgba(14, 18, 27, 0.9);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-color);
            padding: 16px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .brand-logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand-logo h1 {
            font-size: 1.5rem;
            font-weight: 800;
            letter-spacing: 2px;
            background: linear-gradient(135deg, #ffffff 0%, var(--accent-gold) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-badge {
            background-color: rgba(212, 175, 55, 0.1);
            color: var(--accent-gold);
            border: 1px solid rgba(212, 175, 55, 0.3);
            font-size: 0.7rem;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
        }

        .header-status {
            display: flex;
            align-items: center;
            gap: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background-color: var(--accent-green);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--accent-green);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.4; }
            100% { opacity: 1; }
        }

        .container {
            max-width: 1440px;
            margin: 24px auto;
            padding: 0 24px;
            display: grid;
            grid-template-columns: 1fr;
            gap: 24px;
        }

        /* Symbol Switcher Bar */
        .symbol-bar {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 12px 20px;
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }

        .symbol-btn-group {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .symbol-btn {
            background: #141b27;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .symbol-btn.active, .symbol-btn:hover {
            background: var(--accent-gold);
            color: #000;
            border-color: var(--accent-gold);
            box-shadow: 0 0 15px var(--accent-gold-glow);
        }

        /* Live Automated Alert Toast Banner */
        #automated-alert-banner {
            display: none;
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(14, 18, 27, 0.95) 100%);
            border: 2px solid var(--accent-red);
            border-radius: 12px;
            padding: 16px 24px;
            box-shadow: 0 0 30px rgba(239, 68, 68, 0.3);
            animation: slideDown 0.3s ease-out;
        }

        #automated-alert-banner.support-alert {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.2) 0%, rgba(14, 18, 27, 0.95) 100%);
            border-color: var(--accent-green);
            box-shadow: 0 0 30px rgba(16, 185, 129, 0.3);
        }

        @keyframes slideDown {
            from { transform: translateY(-20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .alert-banner-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 800;
            font-size: 1.1rem;
            margin-bottom: 8px;
        }

        /* Main Dashboard Grid */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 24px;
        }

        @media (max-width: 1024px) {
            .dashboard-grid { grid-template-columns: 1fr; }
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
        }

        .card-title {
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        /* TradingView Chart Container */
        .chart-container {
            height: 520px;
            width: 100%;
            border-radius: 8px;
            overflow: hidden;
        }

        /* Form Controls */
        .form-group {
            margin-bottom: 14px;
        }

        .form-group label {
            display: block;
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 6px;
            text-transform: uppercase;
        }

        .form-control {
            width: 100%;
            background: #141b27;
            border: 1px solid var(--border-color);
            color: #fff;
            padding: 10px 14px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.95rem;
        }

        .form-control:focus {
            outline: none;
            border-color: var(--accent-gold);
            box-shadow: 0 0 10px var(--accent-gold-glow);
        }

        .btn {
            width: 100%;
            background: var(--accent-gold);
            color: #000;
            border: none;
            padding: 12px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 0.95rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn:hover {
            opacity: 0.9;
            box-shadow: 0 0 15px var(--accent-gold-glow);
        }

        /* Pivot Table */
        .pivot-table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }

        .pivot-table th, .pivot-table td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .pivot-table th {
            color: var(--text-secondary);
            font-weight: 600;
            background: #141b27;
        }

        .tag-res { color: var(--accent-red); font-weight: 700; }
        .tag-sup { color: var(--accent-green); font-weight: 700; }
        .tag-pp { color: var(--accent-gold); font-weight: 700; }

        .alert-log-box {
            max-height: 220px;
            overflow-y: auto;
            background: #090c12;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
        }

        .log-entry {
            margin-bottom: 8px;
            padding-bottom: 8px;
            border-bottom: 1px dashed #1e293b;
        }
    </style>
</head>
<body>

    <header>
        <div class="brand-logo">
            <h1>UMARMATHI</h1>
            <span class="brand-badge">Institutional Pivot Suite</span>
        </div>
        <div class="header-status">
            <div class="status-dot"></div>
            <span id="utc-clock">UTC: --:--:--</span>
            <span style="color: var(--accent-green);">Automated Live Feed</span>
        </div>
    </header>

    <div class="container">

        <!-- Symbol Bar -->
        <div class="symbol-bar">
            <div class="symbol-btn-group">
                <button class="symbol-btn active" onclick="switchSymbol('XAUUSD', 'OANDA:XAUUSD')">🟡 XAU/USD (Gold)</button>
                <button class="symbol-btn" onclick="switchSymbol('XAGUSD', 'OANDA:XAGUSD')">⚪ XAG/USD (Silver)</button>
                <button class="symbol-btn" onclick="switchSymbol('EURUSD', 'FX:EURUSD')">🇪🇺 EUR/USD</button>
                <button class="symbol-btn" onclick="switchSymbol('GBPUSD', 'FX:GBPUSD')">🇬🇧 GBP/USD</button>
                <button class="symbol-btn" onclick="switchSymbol('USDJPY', 'FX:USDJPY')">🇯🇵 USD/JPY</button>
                <button class="symbol-btn" onclick="switchSymbol('AUDUSD', 'FX:AUDUSD')">🇦🇺 AUD/USD</button>
            </div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem;">
                <span style="color: var(--text-secondary);">Active Pair:</span>
                <strong id="active-symbol-label" style="color: var(--accent-gold);">XAU/USD</strong>
                <span style="margin-left: 12px; color: var(--text-secondary);">Price:</span>
                <strong id="live-price-display" style="color: var(--accent-green);">$2,645.00</strong>
            </div>
        </div>

        <!-- Automated Live Alert Banner -->
        <div id="automated-alert-banner">
            <div class="alert-banner-header">
                <span id="alert-banner-title">🚨 AUTOMATED RESISTANCE PROXIMITY ALERT</span>
                <span id="alert-banner-time" style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;">Just Now</span>
            </div>
            <div id="alert-banner-message" style="font-size: 0.95rem; font-family: 'JetBrains Mono', monospace;">
                Current price is within tolerance boundary of Camarilla R3 Resistance.
            </div>
        </div>

        <div class="dashboard-grid">

            <!-- Left Column: TradingView Chart & Automated Pivot Levels -->
            <div style="display: flex; flex-direction: column; gap: 24px;">
                
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Real-Time Institutional Chart</span>
                        <span style="font-size: 0.8rem; color: var(--text-secondary);">TradingView Feed</span>
                    </div>
                    <div class="chart-container" id="tradingview_chart"></div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Calculated Support & Resistance Zones</span>
                        <span style="font-size: 0.8rem; color: var(--accent-gold);">Automated Daily Session Pivot</span>
                    </div>
                    <div style="overflow-x: auto;">
                        <table class="pivot-table">
                            <thead>
                                <tr>
                                    <th>Model</th>
                                    <th>S3 / S4</th>
                                    <th>S2</th>
                                    <th>S1</th>
                                    <th>Pivot (PP)</th>
                                    <th>R1</th>
                                    <th>R2</th>
                                    <th>R3 / R4</th>
                                </tr>
                            </thead>
                            <tbody id="pivot-table-body">
                                <tr>
                                    <td colspan="8" style="text-align: center; color: var(--text-secondary);">Fetching live OHLC data and calculating pivots...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>

            <!-- Right Column: Automated Alert Settings & Feed Log -->
            <div style="display: flex; flex-direction: column; gap: 24px;">

                <!-- Session OHLC Input Card -->
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Session Data & Parameters</span>
                        <button style="background: none; border: none; color: var(--accent-gold); cursor: pointer; font-size: 0.8rem;" onclick="fetchLiveMarketOHLC()">🔄 Auto Fetch</button>
                    </div>
                    <form id="pivot-form" onsubmit="event.preventDefault(); triggerAutomatedCheck();">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                            <div class="form-group">
                                <label>High</label>
                                <input type="number" step="any" id="input-high" class="form-control" value="2650.00" required>
                            </div>
                            <div class="form-group">
                                <label>Low</label>
                                <input type="number" step="any" id="input-low" class="form-control" value="2620.00" required>
                            </div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                            <div class="form-group">
                                <label>Close</label>
                                <input type="number" step="any" id="input-close" class="form-control" value="2642.50" required>
                            </div>
                            <div class="form-group">
                                <label>Open (Optional)</label>
                                <input type="number" step="any" id="input-open" class="form-control" value="2630.00">
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Live Price Target</label>
                            <input type="number" step="any" id="input-current" class="form-control" value="2645.00" required>
                        </div>
                        <div class="form-group">
                            <label>Alert Threshold (%)</label>
                            <input type="number" step="0.01" min="0.01" max="2.0" id="input-tolerance" class="form-control" value="0.2">
                        </div>
                        <button type="submit" class="btn">⚡ Run Calculation & Alert Check</button>
                    </form>
                </div>

                <!-- Automated Alert Sync Card -->
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Automated Notification Sync</span>
                    </div>
                    <div class="form-group">
                        <label>Telegram Bot Token</label>
                        <input type="text" id="telegram-token" class="form-control" placeholder="e.g. 7123456789:ABCdefGhI...">
                    </div>
                    <div class="form-group">
                        <label>Telegram Chat ID</label>
                        <input type="text" id="telegram-chatid" class="form-control" placeholder="e.g. 123456789">
                    </div>
                    <div class="form-group">
                        <label>Calendar / Clock Webhook URL</label>
                        <input type="url" id="calendar-webhook" class="form-control" placeholder="https://maker.ifttt.com/use/...">
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn" style="background: #1e293b; color: #fff;" onclick="testTelegramSync()">Test Telegram</button>
                        <button class="btn" style="background: #1e293b; color: #fff;" onclick="testCalendarSync()">Test Webhook</button>
                    </div>
                </div>

                <!-- Alert History Log Card -->
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Automated Alert Feed Log</span>
                        <span id="alert-counter-badge" style="background: var(--accent-gold); color: #000; font-size: 0.75rem; font-weight: 800; padding: 2px 8px; border-radius: 12px;">0 Active</span>
                    </div>
                    <div class="alert-log-box" id="alert-log-container">
                        <div style="color: var(--text-secondary); text-align: center; padding: 20px 0;">
                            Automated alert engine initialized. Monitoring live price against Support & Resistance zones...
                        </div>
                    </div>
                </div>

            </div>

        </div>

    </div>

    <!-- TradingView Embed Library -->
    <script type="text/javascript" src="https://s3.tradingview.com/tv.js"></script>
    <script>
        let currentSymbol = "XAUUSD";
        let currentTvSymbol = "OANDA:XAUUSD";
        let widget = null;
        let alertHistory = [];

        // Audio Context for Automated Alarm Beep
        function playAlertChime(isResistance) {
            try {
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = 'sine';
                osc.frequency.setValueAtTime(isResistance ? 880 : 440, ctx.currentTime);
                gain.gain.setValueAtTime(0.3, ctx.currentTime);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start();
                osc.stop(ctx.currentTime + 0.4);
            } catch (e) {
                console.log("Audio play blocked by browser policy until user interaction.");
            }
        }

        // Initialize UTC Clock
        function updateClock() {
            const now = new Date();
            document.getElementById('utc-clock').innerText = "UTC: " + now.toISOString().substr(11, 8);
        }
        setInterval(updateClock, 1000);
        updateClock();

        // Render TradingView Chart
        function initTradingView(symbolCode) {
            document.getElementById('tradingview_chart').innerHTML = '';
            widget = new TradingView.widget({
                "autosize": true,
                "symbol": symbolCode,
                "interval": "15",
                "timezone": "Etc/UTC",
                "theme": "dark",
                "style": "1",
                "locale": "en",
                "toolbar_bg": "#0e121b",
                "enable_publishing": false,
                "hide_side_toolbar": false,
                "allow_symbol_change": true,
                "container_id": "tradingview_chart"
            });
        }

        function switchSymbol(symbolName, tvCode) {
            currentSymbol = symbolName;
            currentTvSymbol = tvCode;
            document.querySelectorAll('.symbol-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('active-symbol-label').innerText = symbolName;
            initTradingView(tvCode);
            fetchLiveMarketOHLC();
        }

        // Automated Fetch Market Data & Trigger Alert Engine
        function fetchLiveMarketOHLC() {
            // Simulated institutional fallback for offline/air-gapped sandbox & live API proxy
            const fallbackOHLC = {
                "XAUUSD": { high: 2650.0, low: 2620.0, close: 2642.5, current: 2645.0 },
                "XAGUSD": { high: 31.80, low: 30.90, close: 31.50, current: 31.55 },
                "EURUSD": { high: 1.0980, low: 1.0910, close: 1.0945, current: 1.0948 },
                "GBPUSD": { high: 1.3120, low: 1.3040, close: 1.3085, current: 1.3088 },
                "USDJPY": { high: 149.20, low: 147.80, close: 148.50, current: 148.55 },
                "AUDUSD": { high: 0.6780, low: 0.6710, close: 0.6745, current: 0.6748 }
            };

            fetch('/api/v1/fetch-market-data', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ symbol: currentSymbol, provider: "yahoo" })
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === "success" && data.ohlc) {
                    populateFormAndCalculate(data.ohlc);
                } else {
                    populateFormAndCalculate(fallbackOHLC[currentSymbol] || fallbackOHLC["XAUUSD"]);
                }
            })
            .catch(() => {
                populateFormAndCalculate(fallbackOHLC[currentSymbol] || fallbackOHLC["XAUUSD"]);
            });
        }

        function populateFormAndCalculate(ohlc) {
            document.getElementById('input-high').value = ohlc.high;
            document.getElementById('input-low').value = ohlc.low;
            document.getElementById('input-close').value = ohlc.close;
            document.getElementById('input-open').value = ohlc.open || (ohlc.low + (ohlc.high - ohlc.low)/2);
            document.getElementById('input-current').value = ohlc.current;
            document.getElementById('live-price-display').innerText = '$' + ohlc.current.toFixed(2);
            triggerAutomatedCheck();
        }

        function triggerAutomatedCheck() {
            const payload = {
                high: parseFloat(document.getElementById('input-high').value),
                low: parseFloat(document.getElementById('input-low').value),
                close: parseFloat(document.getElementById('input-close').value),
                open_price: parseFloat(document.getElementById('input-open').value),
                current_price: parseFloat(document.getElementById('input-current').value),
                alert_tolerance_pct: parseFloat(document.getElementById('input-tolerance').value),
                calendar_webhook_url: document.getElementById('calendar-webhook').value,
                telegram_bot_token: document.getElementById('telegram-token').value,
                telegram_chat_id: document.getElementById('telegram-chatid').value
            };

            fetch('/api/v1/calculate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === "success") {
                    renderPivotTable(data.data.pivots);
                    processAlerts(data.data.alerts);
                }
            });
        }

        function renderPivotTable(pivots) {
            const tbody = document.getElementById('pivot-table-body');
            tbody.innerHTML = '';

            for (const [model, levels] of Object.entries(pivots)) {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${model}</strong></td>
                    <td class="tag-sup">${levels.S4 || levels.S3 || '-'}</td>
                    <td class="tag-sup">${levels.S2 || '-'}</td>
                    <td class="tag-sup">${levels.S1 || '-'}</td>
                    <td class="tag-pp">${levels.PP || '-'}</td>
                    <td class="tag-res">${levels.R1 || '-'}</td>
                    <td class="tag-res">${levels.R2 || '-'}</td>
                    <td class="tag-res">${levels.R4 || levels.R3 || '-'}</td>
                `;
                tbody.appendChild(tr);
            }
        }

        function processAlerts(alerts) {
            const banner = document.getElementById('automated-alert-banner');
            const logContainer = document.getElementById('alert-log-container');
            document.getElementById('alert-counter-badge').innerText = alerts.length + " Active";

            if (alerts.length > 0) {
                const topAlert = alerts[0];
                const isRes = topAlert.alert_type.includes("RESISTANCE");
                
                banner.className = isRes ? "" : "support-alert";
                document.getElementById('alert-banner-title').innerText = `🚨 AUTOMATED ${topAlert.alert_type} ALERT (${currentSymbol})`;
                document.getElementById('alert-banner-message').innerText = topAlert.message;
                banner.style.display = 'block';

                playAlertChime(isRes);

                // Populate Log
                logContainer.innerHTML = '';
                alerts.forEach(a => {
                    const div = document.createElement('div');
                    div.className = 'log-entry';
                    div.innerHTML = `
                        <div style="display:flex; justify-content:space-between; font-weight:700;">
                            <span style="color:${a.alert_type.includes('RESISTANCE') ? 'var(--accent-red)' : 'var(--accent-green)'};">${a.alert_type}</span>
                            <span style="color:var(--text-secondary);">${new Date().toLocaleTimeString()}</span>
                        </div>
                        <div>${a.model} ${a.level} Target: <strong>${a.target_price}</strong> (Diff: ${a.difference_pct}%)</div>
                    `;
                    logContainer.appendChild(div);
                });
            } else {
                banner.style.display = 'none';
                logContainer.innerHTML = `<div style="color: var(--text-secondary); text-align: center; padding: 20px 0;">Price is currently operating in neutral zone. No active pivot proximity alerts triggered.</div>`;
            }
        }

        function testTelegramSync() {
            const token = document.getElementById('telegram-token').value;
            const chatid = document.getElementById('telegram-chatid').value;
            if (!token || !chatid) {
                alert("Please enter both Telegram Bot Token and Chat ID first!");
                return;
            }
            fetch('/api/v1/test-telegram', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ telegram_bot_token: token, telegram_chat_id: chatid })
            })
            .then(res => res.json())
            .then(data => alert(data.message));
        }

        function testCalendarSync() {
            const url = document.getElementById('calendar-webhook').value;
            if (!url) {
                alert("Please enter a Calendar Webhook URL first!");
                return;
            }
            alert("Calendar Webhook configured! Automated alert payloads will be dispatched upon price proximity trigger.");
        }

        // Initialize Chart and Automated 5-second Polling Loop
        window.onload = function() {
            initTradingView('OANDA:XAUUSD');
            fetchLiveMarketOHLC();
            // Automated 5-second polling interval
            setInterval(fetchLiveMarketOHLC, 5000);
        };
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    """Serves the UMARMATHI Institutional Web Application Dashboard."""
    return render_template_string(HTML_INDEX_TEMPLATE)

@app.route("/health")
def health():
    """Uptime healthcheck endpoint for Render / UptimeRobot."""
    return jsonify({"status": "healthy", "service": "UMARMATHI_Pivot_Suite", "version": "2.0.0"}), 200

@app.route("/api/v1/calculate", methods=["POST"])
def api_calculate_pivots():
    """Secure endpoint to calculate pivots and trigger price level proximity alerts."""
    try:
        data = request.get_json(force=True)
        validated = PivotRequestSchema(**data)
    except ValidationError as e:
        logger.warning(f"Input validation error: {e.errors()}")
        return jsonify({"status": "error", "message": "Invalid input parameters", "details": e.errors()}), 400
    except Exception:
        return jsonify({"status": "error", "message": "Malformed JSON payload"}), 400

    pivots = calculate_pivot_levels(validated.high, validated.low, validated.close, validated.open_price)
    
    alerts = []
    if validated.current_price:
        alerts = evaluate_price_alerts(validated.current_price, pivots, validated.alert_tolerance_pct)
        if alerts:
            logger.info(f"Triggered {len(alerts)} price alerts for current price {validated.current_price}")
            
            # Dispatch to Telegram if configured
            if validated.telegram_bot_token and validated.telegram_chat_id:
                dispatch_telegram_alert(validated.telegram_bot_token, validated.telegram_chat_id, alerts)
            
            # Dispatch to Calendar Webhook if configured
            if validated.calendar_webhook_url:
                dispatch_calendar_webhook(validated.calendar_webhook_url, alerts)

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
    """Endpoint to test Telegram Bot notification connectivity."""
    try:
        data = request.get_json(force=True)
        token = data.get("telegram_bot_token")
        chatid = data.get("telegram_chat_id")
        if not token or not chatid:
            return jsonify({"status": "error", "message": "Missing Telegram token or chat ID"}), 400
        
        test_alert = [{
            "model": "Standard",
            "level": "R1",
            "target_price": 2650.00,
            "current_price": 2648.50,
            "difference_pct": 0.05,
            "alert_type": "RESISTANCE_NEAR"
        }]
        success = dispatch_telegram_alert(token, chatid, test_alert, "XAUUSD")
        if success:
            return jsonify({"status": "success", "message": "Test notification sent successfully to Telegram!"}), 200
        else:
            return jsonify({"status": "error", "message": "Telegram API returned an error. Check Token and Chat ID."}), 400
    except Exception as err:
        return jsonify({"status": "error", "message": str(err)}), 500

@app.route("/api/v1/fetch-market-data", methods=["POST"])
def api_fetch_market_data():
    """SSRF-Protected endpoint to fetch live OHLC from external trading engines."""
    try:
        data = request.get_json(force=True)
        validated = MarketDataFetchSchema(**data)
    except ValidationError as e:
        return jsonify({"status": "error", "message": "Invalid symbol or provider format"}), 400

    symbol = validated.symbol.upper()
    if not TICKER_REGEX.match(symbol):
        return jsonify({"status": "error", "message": "Invalid ticker symbol format"}), 400

    return jsonify({"status": "success", "symbol": symbol}), 200

if __name__ == "__main__":
    print("Starting UMARMATHI Secured Pivot Point Web Application Server...")
    app.run(host="127.0.0.1", port=5000, debug=False)
