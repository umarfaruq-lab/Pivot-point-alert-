import os
import re
import logging
import json
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
logger = logging.getLogger("UmarmathiPivotEngine")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())

# Whitelisted Ticker Pattern
TICKER_REGEX = re.compile(r"^[A-Z0-9\-\:]{2,12}$")

# OWASP Security Headers Middleware
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://s3.tradingview.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://s3.tradingview.com; "
        "connect-src 'self' wss: https:;"
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
    current_price: Optional[float] = Field(None, gt=0)
    alert_tolerance_pct: float = Field(0.15, ge=0.01, le=3.0)
    calendar_webhook_url: Optional[str] = Field(None)

class WebhookTestSchema(BaseModel):
    webhook_url: str = Field(...)

def calculate_pivot_levels(high: float, low: float, close: float, open_price: Optional[float] = None) -> Dict[str, Any]:
    """Calculates Support and Resistance levels for 5 major calculation frameworks."""
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
    """Evaluates proximity to Support and Resistance zones."""
    alerts = []
    for model_name, levels in pivot_levels.items():
        for level_name, level_val in levels.items():
            if level_val is None:
                continue
            diff_pct = abs(current_price - level_val) / level_val * 100.0
            if diff_pct <= tolerance_pct:
                alert_type = "RESISTANCE_TRIGGER" if "R" in level_name else ("SUPPORT_TRIGGER" if "S" in level_name else "PIVOT_TOUCH")
                alerts.append({
                    "model": model_name,
                    "level": level_name,
                    "target_price": level_val,
                    "current_price": current_price,
                    "difference_pct": round(diff_pct, 3),
                    "alert_type": alert_type,
                    "message": f"🚨 {alert_type}: Price ({current_price}) reached {model_name} {level_name} ({level_val})"
                })
    return alerts

def dispatch_calendar_webhook(webhook_url: str, alert_payload: dict):
    """Safely dispatches alert notification to user's Calendar/Clock webhook."""
    try:
        parsed = urlparse(webhook_url)
        if parsed.scheme not in ("http", "https"):
            return
        # Avoid internal IP targeting
        host = parsed.hostname.lower() if parsed.hostname else ""
        if host in ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254"):
            return
        requests.post(webhook_url, json=alert_payload, timeout=3)
    except Exception as e:
        logger.warning(f"Webhook dispatch notification failed: {e}")

# Frontend Template
INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UMARMATHI | Forex & Metals Institutional Pivot Engine</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0A0D14;
            --bg-card: #121722;
            --bg-input: #182030;
            --border-color: #232D42;
            --accent-gold: #D4AF37;
            --accent-gold-hover: #F59E0B;
            --accent-green: #10B981;
            --accent-red: #EF4444;
            --text-primary: #F3F4F6;
            --text-secondary: #9CA3AF;
            --text-muted: #6B7280;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; }
        body { background-color: var(--bg-primary); color: var(--text-primary); min-height: 100vh; display: flex; flex-direction: column; }
        
        /* Top Navigation Header */
        header {
            background-color: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
            padding: 16px 28px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .brand-container { display: flex; align-items: center; gap: 14px; }
        .brand-logo {
            background: linear-gradient(135deg, var(--accent-gold), #F59E0B);
            color: #000;
            font-weight: 800;
            font-size: 18px;
            padding: 8px 14px;
            border-radius: 8px;
            letter-spacing: 1.5px;
        }
        .brand-title { font-weight: 700; font-size: 18px; color: var(--text-primary); }
        .brand-sub { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }

        .time-badge {
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            padding: 8px 16px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: var(--accent-gold);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .pulse-dot { width: 8px; height: 8px; background-color: var(--accent-green); border-radius: 50%; animation: pulse 1.5s infinite; }

        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }

        /* Main Container */
        .main-layout {
            display: grid;
            grid-template-columns: 1fr 420px;
            gap: 20px;
            padding: 24px;
            max-width: 1750px;
            margin: 0 auto;
            width: 100%;
            flex: 1;
        }

        /* Symbol Preset Switcher */
        .symbol-bar {
            display: flex;
            gap: 10px;
            margin-bottom: 16px;
            overflow-x: auto;
            padding-bottom: 4px;
        }
        .symbol-btn {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 10px 18px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s ease;
            white-space: nowrap;
        }
        .symbol-btn:hover { border-color: var(--accent-gold); color: var(--text-primary); }
        .symbol-btn.active {
            background: rgba(212, 175, 55, 0.12);
            border-color: var(--accent-gold);
            color: var(--accent-gold);
        }

        /* Card Panels */
        .panel {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
        }
        .panel-title { font-weight: 700; font-size: 15px; color: var(--text-primary); display: flex; align-items: center; gap: 8px; }

        /* Chart Container */
        .chart-wrapper {
            height: 520px;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            background-color: #000;
        }

        /* Inputs Form Grid */
        .form-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 14px;
        }
        .form-group { display: flex; flex-direction: column; gap: 6px; }
        .form-group label { font-size: 12px; font-weight: 600; color: var(--text-secondary); }
        .form-control {
            background-color: var(--bg-input);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 10px 14px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s;
        }
        .form-control:focus { border-color: var(--accent-gold); }

        .btn-primary {
            background: linear-gradient(135deg, var(--accent-gold), var(--accent-gold-hover));
            color: #000;
            font-weight: 700;
            font-size: 14px;
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: opacity 0.2s;
            width: 100%;
            margin-top: 10px;
        }
        .btn-primary:hover { opacity: 0.9; }

        /* Pivot Results Tables */
        .pivot-tabs { display: flex; gap: 8px; margin-bottom: 12px; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }
        .tab-btn {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 12px;
            padding: 6px 12px;
            cursor: pointer;
            border-radius: 6px;
        }
        .tab-btn.active { background: var(--bg-input); color: var(--accent-gold); }

        .pivot-table { width: 100%; border-collapse: collapse; margin-top: 8px; }
        .pivot-table th, .pivot-table td {
            padding: 10px 12px;
            text-align: left;
            font-size: 13px;
            border-bottom: 1px solid rgba(35, 45, 66, 0.5);
        }
        .pivot-table th { color: var(--text-secondary); font-weight: 600; font-size: 11px; text-transform: uppercase; }
        .level-tag { font-family: 'JetBrains Mono', monospace; font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 11px; }
        .tag-res { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); }
        .tag-pp { background: rgba(212, 175, 55, 0.15); color: var(--accent-gold); }
        .tag-sup { background: rgba(16, 185, 129, 0.15); color: var(--accent-green); }

        /* Alert & Calendar Integration Box */
        .webhook-box {
            background: var(--bg-input);
            border: 1px dashed var(--accent-gold);
            padding: 16px;
            border-radius: 10px;
            margin-top: 14px;
        }
        .webhook-box h4 { font-size: 13px; color: var(--accent-gold); margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }
        .webhook-box p { font-size: 11px; color: var(--text-secondary); margin-bottom: 12px; line-height: 1.4; }

        .alert-feed { max-height: 160px; overflow-y: auto; margin-top: 10px; }
        .alert-item {
            background: rgba(239, 68, 68, 0.1);
            border-left: 3px solid var(--accent-red);
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 12px;
            margin-bottom: 6px;
            font-family: 'JetBrains Mono', monospace;
        }

        @media (max-width: 1024px) {
            .main-layout { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>

    <header>
        <div class="brand-container">
            <div class="brand-logo">UMARMATHI</div>
            <div>
                <div class="brand-title">Forex & Metals Institutional Pivot Engine</div>
                <div class="brand-sub">Real-Time Precision Support & Resistance Analytics</div>
            </div>
        </div>
        <div class="time-badge">
            <div class="pulse-dot"></div>
            <span id="utc-clock">00:00:00 UTC</span>
        </div>
    </header>

    <div class="main-layout">
        
        <!-- Left Column: Chart & OHLC Setup -->
        <div>
            <!-- Symbol Selector Bar -->
            <div class="symbol-bar">
                <button class="symbol-btn active" onclick="setSymbol('OANDA:XAUUSD', 'Gold / US Dollar', 2650.50, 2632.10, 2645.80, 2638.00)">🥇 XAU/USD (Gold)</button>
                <button class="symbol-btn" onclick="setSymbol('OANDA:XAGUSD', 'Silver / US Dollar', 31.85, 31.20, 31.60, 31.35)">🥈 XAG/USD (Silver)</button>
                <button class="symbol-btn" onclick="setSymbol('FX:EURUSD', 'Euro / US Dollar', 1.0980, 1.0910, 1.0955, 1.0925)">🇪🇺 EUR/USD</button>
                <button class="symbol-btn" onclick="setSymbol('FX:GBPUSD', 'British Pound / USD', 1.3120, 1.3030, 1.3085, 1.3045)">🇬🇧 GBP/USD</button>
                <button class="symbol-btn" onclick="setSymbol('FX:USDJPY', 'USD / Japanese Yen', 149.20, 147.80, 148.60, 148.10)">🇯🇵 USD/JPY</button>
                <button class="symbol-btn" onclick="setSymbol('FX:AUDUSD', 'Australian Dollar / USD', 0.6780, 0.6710, 0.6745, 0.6720)">🇦🇺 AUD/USD</button>
            </div>

            <!-- TradingView Live Chart Panel -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title" id="active-symbol-title">🥇 OANDA:XAUUSD — Live Institutional Chart</div>
                    <span style="font-size: 12px; color: var(--accent-green);" id="live-tick-status">● Live Feed Stream Active</span>
                </div>
                <div class="chart-wrapper" id="tv_chart_container"></div>
            </div>

            <!-- Manual / Quick Session Input Form -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">⚙️ Session Parameters & Proximity Thresholds</div>
                </div>
                <div class="form-grid">
                    <div class="form-group">
                        <label>Previous High</label>
                        <input type="number" step="0.0001" id="input-high" class="form-control" value="2650.50">
                    </div>
                    <div class="form-group">
                        <label>Previous Low</label>
                        <input type="number" step="0.0001" id="input-low" class="form-control" value="2632.10">
                    </div>
                    <div class="form-group">
                        <label>Previous Close</label>
                        <input type="number" step="0.0001" id="input-close" class="form-control" value="2645.80">
                    </div>
                    <div class="form-group">
                        <label>Previous Open</label>
                        <input type="number" step="0.0001" id="input-open" class="form-control" value="2638.00">
                    </div>
                    <div class="form-group">
                        <label>Live Price</label>
                        <input type="number" step="0.0001" id="input-current" class="form-control" value="2649.80">
                    </div>
                    <div class="form-group">
                        <label>Alert Sensitivity (%)</label>
                        <input type="number" step="0.05" id="input-tolerance" class="form-control" value="0.15">
                    </div>
                </div>
                <button class="btn-primary" onclick="calculatePivots()">Calculate & Sync Alert Thresholds</button>
            </div>
        </div>

        <!-- Right Column: Pivot Levels & Calendar Integration -->
        <div>
            
            <!-- Calculated Pivots Monitor -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">🎯 Calculated Pivot Levels</div>
                </div>
                <div class="pivot-tabs">
                    <button class="tab-btn active" onclick="switchPivotTab('Standard')">Standard</button>
                    <button class="tab-btn" onclick="switchPivotTab('Fibonacci')">Fibonacci</button>
                    <button class="tab-btn" onclick="switchPivotTab('Woodie')">Woodie</button>
                    <button class="tab-btn" onclick="switchPivotTab('Camarilla')">Camarilla</button>
                    <button class="tab-btn" onclick="switchPivotTab('DeMark')">DeMark</button>
                </div>
                <table class="pivot-table">
                    <thead>
                        <tr>
                            <th>Level</th>
                            <th>Target Price</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody id="pivot-rows">
                        <!-- Populated by JavaScript -->
                    </tbody>
                </table>
            </div>

            <!-- Calendar & Clock Webhook Sync Panel -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">🔔 Calendar / Clock Alert Sync</div>
                </div>
                
                <div class="webhook-box">
                    <h4>📅 Link to Calendar / Clock Webhook</h4>
                    <p>Enter your Google Calendar, iCal, Zapier, Make, or Smart Clock Webhook URL. When price hits a Support or Resistance zone, an automated alert trigger will post directly to your calendar/clock feed.</p>
                    <input type="text" id="webhook-url" class="form-control" placeholder="https://maker.ifttt.com/trigger/pivot_alert/with/key/..." style="width: 100%; font-size: 12px; margin-bottom: 10px;">
                    <div style="display: flex; gap: 8px;">
                        <button class="btn-primary" style="margin-top: 0; font-size: 12px; padding: 8px;" onclick="testWebhook()">Test Calendar Sync</button>
                        <button class="btn-primary" style="margin-top: 0; font-size: 12px; padding: 8px; background: #374151; color: #FFF;" onclick="toggleAudioChime()">🔊 Sound Chime: ON</button>
                    </div>
                </div>

                <div style="margin-top: 16px;">
                    <div style="font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 8px;">Real-Time Alert Feed Log</div>
                    <div class="alert-feed" id="alert-feed-box">
                        <div style="font-size: 12px; color: var(--text-muted); text-align: center; padding: 12px;">No active level triggers detected yet.</div>
                    </div>
                </div>

            </div>

        </div>

    </div>

    <!-- TradingView Script -->
    <script src="https://s3.tradingview.com/tv.js"></script>
    <script>
        let currentTVWidget = null;
        let activePivotData = null;
        let currentPivotFramework = 'Standard';
        let audioEnabled = true;

        function updateUTCClock() {
            const now = new Date();
            document.getElementById('utc-clock').innerText = now.toUTCString().split(' ')[4] + ' UTC';
        }
        setInterval(updateUTCClock, 1000);
        updateUTCClock();

        function loadTradingViewChart(symbolName) {
            document.getElementById('tv_chart_container').innerHTML = '';
            currentTVWidget = new TradingView.widget({
                "autosize": true,
                "symbol": symbolName,
                "interval": "15",
                "timezone": "Etc/UTC",
                "theme": "dark",
                "style": "1",
                "locale": "en",
                "toolbar_bg": "#121722",
                "enable_publishing": false,
                "hide_side_toolbar": false,
                "container_id": "tv_chart_container"
            });
        }

        function setSymbol(symbol, title, high, low, close, open) {
            document.querySelectorAll('.symbol-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('active-symbol-title').innerText = `🥇 ${symbol} — Live Institutional Chart`;
            
            document.getElementById('input-high').value = high;
            document.getElementById('input-low').value = low;
            document.getElementById('input-close').value = close;
            document.getElementById('input-open').value = open;
            
            loadTradingViewChart(symbol);
            calculatePivots();
        }

        function calculatePivots() {
            const payload = {
                high: parseFloat(document.getElementById('input-high').value),
                low: parseFloat(document.getElementById('input-low').value),
                close: parseFloat(document.getElementById('input-close').value),
                open_price: parseFloat(document.getElementById('input-open').value),
                current_price: parseFloat(document.getElementById('input-current').value),
                alert_tolerance_pct: parseFloat(document.getElementById('input-tolerance').value),
                calendar_webhook_url: document.getElementById('webhook-url').value
            };

            fetch('/api/v1/calculate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    activePivotData = data.data.pivots;
                    renderPivotTable();
                    renderAlerts(data.data.alerts);
                }
            });
        }

        function switchPivotTab(framework) {
            currentPivotFramework = framework;
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            renderPivotTable();
        }

        function renderPivotTable() {
            if (!activePivotData || !activePivotData[currentPivotFramework]) return;
            const levels = activePivotData[currentPivotFramework];
            const currentPrice = parseFloat(document.getElementById('input-current').value);
            const tbody = document.getElementById('pivot-rows');
            tbody.innerHTML = '';

            for (const [level, val] of Object.entries(levels)) {
                if (val === null) continue;
                let tagClass = 'tag-pp';
                if (level.includes('R')) tagClass = 'tag-res';
                if (level.includes('S')) tagClass = 'tag-sup';

                const diff = Math.abs(currentPrice - val) / val * 100;
                let statusText = `<span style="color: var(--text-muted);">${diff.toFixed(2)}% away</span>`;
                if (diff <= parseFloat(document.getElementById('input-tolerance').value)) {
                    statusText = `<span style="color: var(--accent-gold); font-weight:700;">🚨 IN ZONE</span>`;
                }

                tbody.innerHTML += `
                    <tr>
                        <td><span class="level-tag ${tagClass}">${level}</span></td>
                        <td style="font-family: 'JetBrains Mono', monospace; font-weight:700;">$${val.toFixed(2)}</td>
                        <td>${statusText}</td>
                    </tr>
                `;
            }
        }

        function renderAlerts(alerts) {
            const box = document.getElementById('alert-feed-box');
            if (!alerts || alerts.length === 0) {
                box.innerHTML = `<div style="font-size: 12px; color: var(--text-muted); text-align: center; padding: 12px;">No active level triggers detected yet.</div>`;
                return;
            }
            box.innerHTML = '';
            alerts.forEach(a => {
                box.innerHTML += `<div class="alert-item">${a.message}</div>`;
            });

            if (audioEnabled && alerts.length > 0) {
                playChimeSound();
            }
        }

        function playChimeSound() {
            try {
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = 'sine';
                osc.frequency.value = 880; // A5 pitch
                gain.gain.setValueAtTime(0.1, ctx.currentTime);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start();
                osc.stop(ctx.currentTime + 0.25);
            } catch(e){}
        }

        function toggleAudioChime() {
            audioEnabled = !audioEnabled;
            event.target.innerText = audioEnabled ? "🔊 Sound Chime: ON" : "🔇 Sound Chime: OFF";
        }

        function testWebhook() {
            const url = document.getElementById('webhook-url').value;
            if (!url) {
                alert("Please enter a valid Calendar/Clock Webhook URL first.");
                return;
            }
            fetch('/api/v1/webhook-test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ webhook_url: url })
            })
            .then(res => res.json())
            .then(data => alert(data.message));
        }

        // Initialize default view
        window.onload = function() {
            loadTradingViewChart('OANDA:XAUUSD');
            calculatePivots();
        };
    </script>
</body>
</html>
"""

# API Routes
@app.route("/")
def index():
    """Serves the institutional UMARMATHI trading dashboard."""
    return render_template_string(INDEX_HTML)

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "UMARMATHI Pivot Engine", "version": "2.0.0"}), 200

@app.route("/api/v1/calculate", methods=["POST"])
def api_calculate_pivots():
    """Calculates pivots, evaluates proximity alerts, and dispatches calendar/clock webhooks."""
    try:
        data = request.get_json(force=True)
        validated = PivotRequestSchema(**data)
    except ValidationError as e:
        return jsonify({"status": "error", "message": "Invalid input parameters", "details": e.errors()}), 400
    except Exception:
        return jsonify({"status": "error", "message": "Malformed JSON payload"}), 400

    pivots = calculate_pivot_levels(validated.high, validated.low, validated.close, validated.open_price)
    
    alerts = []
    if validated.current_price:
        alerts = evaluate_price_alerts(validated.current_price, pivots, validated.alert_tolerance_pct)
        if alerts and validated.calendar_webhook_url:
            dispatch_calendar_webhook(validated.calendar_webhook_url, {
                "event": "SUPPORT_RESISTANCE_ALERT",
                "symbol": "FOREX_METALS",
                "alerts": alerts,
                "alert_count": len(alerts)
            })

    return jsonify({
        "status": "success",
        "data": {
            "pivots": pivots,
            "alerts": alerts,
            "alert_count": len(alerts)
        }
    }), 200

@app.route("/api/v1/webhook-test", methods=["POST"])
def api_webhook_test():
    """Tests connection to user's Calendar/Clock webhook."""
    try:
        data = request.get_json(force=True)
        validated = WebhookTestSchema(**data)
        dispatch_calendar_webhook(validated.webhook_url, {
            "event": "CALENDAR_SYNC_TEST",
            "message": "✅ UMARMATHI Calendar & Clock Webhook Sync Successful!"
        })
        return jsonify({"status": "success", "message": "Sync payload dispatched to your Calendar/Clock webhook!"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Webhook test failed: {e}"}), 400

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
