"""
Secure Pivot Point Calculator & Alert System (OWASP Top 10 Compliant)
===================================================================
A production-ready Python web application built with Flask, Pydantic, and Security Hardening.
Integrates live market data feeds, multi-model pivot calculations, real-time alert thresholds,
and an embedded TradingView interactive charting interface with live WebSockets.
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
TICKER_REGEX = re.compile(r"^[A-Z0-9\-]{2,10}$")

# OWASP Security Headers Middleware
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://s3.tradingview.com https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://s3.tradingview.com; "
        "connect-src 'self' https://api.binance.com wss://stream.binance.com:9443; "
        "frame-src 'self' https://s.tradingview.com https://www.tradingview-widget.com;"
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
    alert_tolerance_pct: float = Field(0.2, ge=0.01, le=5.0, description="Alert proximity threshold in %")

class MarketDataFetchSchema(BaseModel):
    symbol: str = Field(..., min_length=2, max_length=10)
    provider: str = Field("binance")

def is_safe_url(url: str) -> bool:
    """SSRF Prevention: Ensure URL belongs to explicit whitelist and non-internal IP."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname.lower() if parsed.hostname else ""
        if host in ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254") or host.startswith("10.") or host.startswith("192.168."):
            return False
        return any(whitelisted in host for whitelisted in ["binance.com", "yahoo.com"])
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

# HTML Dashboard Template
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Pivot Point Calculator & Live Trading Chart</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; }
        .form-control, .form-select { background-color: #0f172a; border-color: #475569; color: #f8fafc; }
        .form-control:focus { background-color: #0f172a; color: #f8fafc; border-color: #3b82f6; box-shadow: none; }
        .btn-primary { background-color: #3b82f6; border: none; font-weight: 600; }
        .btn-primary:hover { background-color: #2563eb; }
        .table-dark { --bs-table-bg: #1e293b; }
        .alert-box { max-height: 200px; overflow-y: auto; }
        #tradingview_widget { height: 500px; width: 100%; border-radius: 8px; overflow: hidden; }
    </style>
</head>
<body class="py-4">
    <div class="container-fluid px-4">
        <header class="d-flex justify-content-between align-items-center mb-4 pb-3 border-bottom border-secondary">
            <div>
                <h2 class="fw-bold mb-0 text-white">📊 Secure Pivot Calculator & Live Chart</h2>
                <small class="text-secondary">OWASP Top 10 Hardened Trading Engine · Real-time Proximity Alerts</small>
            </div>
            <div class="d-flex align-items-center gap-3">
                <span class="badge bg-outline-info text-info border border-info px-3 py-2">
                    Live Stream: <strong id="live-symbol">BTCUSDT</strong> (<span id="live-price" class="text-warning">$0.00</span>)
                </span>
                <span class="badge bg-success px-3 py-2">Status: Online</span>
            </div>
        </header>

        <div class="row g-4">
            <!-- Left Panel: Input & Controls -->
            <div class="col-lg-4">
                <div class="card p-4 mb-4">
                    <h5 class="fw-bold text-info mb-3">1. Market Data Inputs</h5>
                    <form id="pivot-form">
                        <div class="mb-3">
                            <label class="form-label small text-secondary">Fetch Live OHLC (Binance Ticker)</label>
                            <div class="input-group">
                                <input type="text" id="symbol-input" class="form-control" value="BTC" placeholder="BTC, ETH, SOL...">
                                <button type="button" id="btn-fetch" class="btn btn-outline-info">Fetch</button>
                            </div>
                        </div>

                        <hr class="border-secondary my-3">

                        <div class="row g-2 mb-2">
                            <div class="col-6">
                                <label class="form-label small text-secondary">High Price ($)</label>
                                <input type="number" step="any" id="high-input" class="form-control" value="65000" required>
                            </div>
                            <div class="col-6">
                                <label class="form-label small text-secondary">Low Price ($)</label>
                                <input type="number" step="any" id="low-input" class="form-control" value="62000" required>
                            </div>
                        </div>

                        <div class="row g-2 mb-2">
                            <div class="col-6">
                                <label class="form-label small text-secondary">Close Price ($)</label>
                                <input type="number" step="any" id="close-input" class="form-control" value="64500" required>
                            </div>
                            <div class="col-6">
                                <label class="form-label small text-secondary">Open Price ($)</label>
                                <input type="number" step="any" id="open-input" class="form-control" value="62500">
                            </div>
                        </div>

                        <div class="row g-2 mb-3">
                            <div class="col-6">
                                <label class="form-label small text-secondary">Live Price ($)</label>
                                <input type="number" step="any" id="current-input" class="form-control" value="64900">
                            </div>
                            <div class="col-6">
                                <label class="form-label small text-secondary">Alert Buffer (%)</label>
                                <input type="number" step="0.05" id="tolerance-input" class="form-control" value="0.2">
                            </div>
                        </div>

                        <button type="submit" class="btn btn-primary w-100">Calculate & Evaluate Alerts</button>
                    </form>
                </div>

                <!-- Alert Feed Card -->
                <div class="card p-4">
                    <h5 class="fw-bold text-warning mb-3">🚨 Live Proximity Alert Feed</h5>
                    <div id="alert-container" class="alert-box">
                        <p class="text-secondary small mb-0">No alerts triggered yet. Waiting for price to approach support or resistance...</p>
                    </div>
                </div>
            </div>

            <!-- Right Panel: Live Chart & Pivot Results -->
            <div class="col-lg-8">
                <!-- TradingView Embed Chart -->
                <div class="card p-3 mb-4">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <h5 class="fw-bold text-white mb-0">2. Interactive Live Market Chart</h5>
                        <small class="text-secondary">Powered by TradingView</small>
                    </div>
                    <div id="tradingview_widget"></div>
                </div>

                <!-- Pivot Calculations Table -->
                <div class="card p-4">
                    <h5 class="fw-bold text-success mb-3">3. Pivot Level Matrix</h5>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped align-middle" id="pivot-table">
                            <thead>
                                <tr class="text-secondary">
                                    <th>Model</th>
                                    <th>Pivot (PP)</th>
                                    <th>Support 1 (S1)</th>
                                    <th>Support 2 (S2)</th>
                                    <th>Resistance 1 (R1)</th>
                                    <th>Resistance 2 (R2)</th>
                                </tr>
                            </thead>
                            <tbody id="pivot-tbody">
                                <tr><td colspan="6" class="text-center text-secondary">Click 'Calculate' to generate pivot levels</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- TradingView Embed Script -->
    <script type="text/javascript" src="https://s3.tradingview.com/tv.js"></script>
    <script>
        let tvWidget;

        function loadTradingViewChart(symbolName) {
            tvWidget = new TradingView.widget({
                "autosize": true,
                "symbol": "BINANCE:" + symbolName + "USDT",
                "interval": "15",
                "timezone": "Etc/UTC",
                "theme": "dark",
                "style": "1",
                "locale": "en",
                "toolbar_bg": "#0f172a",
                "enable_publishing": false,
                "hide_side_toolbar": false,
                "allow_symbol_change": true,
                "container_id": "tradingview_widget"
            });
        }

        loadTradingViewChart("BTC");

        // Live WebSocket Feed Connection (Binance Stream)
        let ws;
        function connectWebSocket(symbol) {
            if (ws) ws.close();
            const wsSymbol = symbol.toLowerCase() + "usdt";
            ws = new WebSocket(`wss://stream.binance.com:9443/ws/${wsSymbol}@ticker`);

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                const livePrice = parseFloat(data.c);
                document.getElementById("live-symbol").innerText = symbol.toUpperCase() + "USDT";
                document.getElementById("live-price").innerText = "$" + livePrice.toFixed(2);
                document.getElementById("current-input").value = livePrice.toFixed(2);
            };
        }

        connectWebSocket("BTC");

        // Form Submission Logic
        document.getElementById("pivot-form").addEventListener("submit", async (e) => {
            e.preventDefault();
            const payload = {
                high: parseFloat(document.getElementById("high-input").value),
                low: parseFloat(document.getElementById("low-input").value),
                close: parseFloat(document.getElementById("close-input").value),
                open_price: parseFloat(document.getElementById("open-input").value) || null,
                current_price: parseFloat(document.getElementById("current-input").value) || null,
                alert_tolerance_pct: parseFloat(document.getElementById("tolerance-input").value) || 0.2
            };

            const response = await fetch("/api/v1/calculate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const resData = await response.json();
            if (resData.status === "success") {
                renderPivotTable(resData.data.pivots);
                renderAlerts(resData.data.alerts);
            }
        });

        // Fetch Live OHLC Button
        document.getElementById("btn-fetch").addEventListener("click", async () => {
            const symbol = document.getElementById("symbol-input").value.trim().toUpperCase();
            if (!symbol) return;

            const response = await fetch("/api/v1/fetch-market-data", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ symbol: symbol, provider: "binance" })
            });

            const resData = await response.json();
            if (resData.status === "success") {
                document.getElementById("high-input").value = resData.ohlc.high;
                document.getElementById("low-input").value = resData.ohlc.low;
                document.getElementById("close-input").value = resData.ohlc.close;
                document.getElementById("open-input").value = resData.ohlc.open;
                document.getElementById("current-input").value = resData.ohlc.current;

                loadTradingViewChart(symbol);
                connectWebSocket(symbol);
            }
        });

        function renderPivotTable(pivots) {
            const tbody = document.getElementById("pivot-tbody");
            tbody.innerHTML = "";
            for (const [model, levels] of Object.entries(pivots)) {
                if (Object.keys(levels).length === 0) continue;
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td class="fw-bold text-info">${model}</td>
                    <td class="text-warning">${levels.PP !== undefined ? levels.PP : '-'}</td>
                    <td class="text-danger">${levels.S1 !== undefined ? levels.S1 : '-'}</td>
                    <td class="text-danger">${levels.S2 !== undefined ? levels.S2 : '-'}</td>
                    <td class="text-success">${levels.R1 !== undefined ? levels.R1 : '-'}</td>
                    <td class="text-success">${levels.R2 !== undefined ? levels.R2 : '-'}</td>
                `;
                tbody.appendChild(tr);
            }
        }

        function renderAlerts(alerts) {
            const alertBox = document.getElementById("alert-container");
            if (alerts.length === 0) {
                alertBox.innerHTML = '<p class="text-secondary small mb-0">No alerts triggered. Current price is clear of nearby pivot levels.</p>';
                return;
            }

            alertBox.innerHTML = "";
            alerts.forEach(alert => {
                const div = document.createElement("div");
                div.className = "alert alert-warning py-2 px-3 mb-2 small";
                div.innerText = alert.message;
                alertBox.appendChild(div);
            });
        }
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

@app.route("/health", methods=["GET"])
def healthcheck():
    return jsonify({"status": "healthy", "service": "SecurePivotApp", "version": "1.0.0"}), 200

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

    return jsonify({
        "status": "success",
        "data": {
            "inputs": validated.dict(),
            "pivots": pivots,
            "alerts": alerts,
            "alert_count": len(alerts)
        }
    }), 200

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
        logger.warning(f"Invalid ticker pattern attempt: {symbol}")
        return jsonify({"status": "error", "message": "Invalid ticker symbol format"}) , 400

    if validated.provider not in ALLOWED_DATA_PROVIDERS:
        return jsonify({"status": "error", "message": "Provider not supported"}), 400

    target_url = ALLOWED_DATA_PROVIDERS[validated.provider]
    if not is_safe_url(target_url):
        logger.error(f"SSRF violation attempt blocked: {target_url}")
        return jsonify({"status": "error", "message": "Security policy violation"}), 403

    try:
        if validated.provider == "binance":
            resp = requests.get(target_url, params={"symbol": f"{symbol}USDT"}, timeout=5)
            if resp.status_code == 200:
                res_data = resp.json()
                high = float(res_data["highPrice"])
                low = float(res_data["lowPrice"])
                close = float(res_data["lastPrice"])
                open_p = float(res_data["openPrice"])
                return jsonify({
                    "status": "success",
                    "symbol": symbol,
                    "ohlc": {"high": high, "low": low, "close": close, "open": open_p, "current": close}
                })
    except Exception as err:
        logger.error(f"Trading API connection error: {err}")
        return jsonify({"status": "error", "message": "Unable to connect to live market engine"}), 502

    return jsonify({"status": "error", "message": "Data unavailable"}), 404

if __name__ == "__main__":
    print("Starting OWASP Top 10 Secured Pivot Point Web Application Server...")
    app.run(host="0.0.0.0", port=5000, debug=False)
