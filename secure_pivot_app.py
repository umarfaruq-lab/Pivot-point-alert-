import os, re, sqlite3, logging, secrets
from typing import Dict, Any, Optional, List
import requests
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from pydantic import BaseModel, Field, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
DB_FILE = os.path.join(os.path.dirname(__file__), 'users.db')

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, name TEXT, password_hash TEXT)')
    conn.commit()
    conn.close()

init_db()

@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

class PivotRequestSchema(BaseModel):
    high: float = Field(..., gt=0)
    low: float = Field(..., gt=0)
    close: float = Field(..., gt=0)
    open_price: Optional[float] = Field(None, gt=0)
    current_price: Optional[float] = Field(None, gt=0)
    alert_tolerance_pct: float = Field(0.2, ge=0.001, le=5.0)
    phone_webhook_url: Optional[str] = Field(None)

class RegisterSchema(BaseModel):
    email: str
    password: str = Field(..., min_length=6)
    name: str = Field(..., min_length=2)

class LoginSchema(BaseModel):
    email: str
    password: str

class TestAlertSchema(BaseModel):
    phone_webhook_url: str = Field(..., min_length=5)
    test_symbol: Optional[str] = Field('XAUUSD')

def calculate_pivot_levels(high: float, low: float, close: float, open_price: Optional[float] = None) -> Dict[str, Any]:
    rng = high - low
    pp_std = (high + low + close) / 3.0
    r1_std, s1_std = (2 * pp_std) - low, (2 * pp_std) - high
    r2_std, s2_std = pp_std + rng, pp_std - rng
    r3_std, s3_std = high + 2 * (pp_std - low), low - 2 * (high - pp_std)
    r4_std, s4_std = pp_std + (rng * 3), pp_std - (rng * 3)

    r1_fib, s1_fib = pp_std + (rng * 0.382), pp_std - (rng * 0.382)
    r2_fib, s2_fib = pp_std + (rng * 0.618), pp_std - (rng * 0.618)
    r3_fib, s3_fib = pp_std + (rng * 1.000), pp_std - (rng * 1.000)
    r4_fib, s4_fib = pp_std + (rng * 1.382), pp_std - (rng * 1.382)

    pp_wood = (high + low + 2 * close) / 4.0
    r1_wood, s1_wood = (2 * pp_wood) - low, (2 * pp_wood) - high
    r2_wood, s2_wood = pp_wood + rng, pp_wood - rng
    r3_wood, s3_wood = high + 2 * (pp_wood - low), low - 2 * (high - pp_wood)
    r4_wood, s4_wood = r3_wood + rng, s3_wood - rng

    r1_cam, s1_cam = close + (rng * 1.1 / 12.0), close - (rng * 1.1 / 12.0)
    r2_cam, s2_cam = close + (rng * 1.1 / 6.0), close - (rng * 1.1 / 6.0)
    r3_cam, s3_cam = close + (rng * 1.1 / 4.0), close - (rng * 1.1 / 4.0)
    r4_cam, s4_cam = close + (rng * 1.1 / 2.0), close - (rng * 1.1 / 2.0)

    demark_res = {}
    if open_price is not None:
        if close < open_price: x = high + (2 * low) + close
        elif close > open_price: x = (2 * high) + low + close
        else: x = high + low + (2 * close)
        pp_dem = x / 4.0
        demark_res = {'PP': round(pp_dem, 4), 'R1': round((x / 2.0) - low, 4), 'S1': round((x / 2.0) - high, 4)}

    return {
        'Standard': {'PP': round(pp_std, 4), 'R1': round(r1_std, 4), 'S1': round(s1_std, 4), 'R2': round(r2_std, 4), 'S2': round(s2_std, 4), 'R3': round(r3_std, 4), 'S3': round(s3_std, 4), 'R4': round(r4_std, 4), 'S4': round(s4_std, 4)},
        'Fibonacci': {'PP': round(pp_std, 4), 'R1': round(r1_fib, 4), 'S1': round(s1_fib, 4), 'R2': round(r2_fib, 4), 'S2': round(s2_fib, 4), 'R3': round(r3_fib, 4), 'S3': round(s3_fib, 4), 'R4': round(r4_fib, 4), 'S4': round(s4_fib, 4)},
        'Woodie': {'PP': round(pp_wood, 4), 'R1': round(r1_wood, 4), 'S1': round(s1_wood, 4), 'R2': round(r2_wood, 4), 'S2': round(s2_wood, 4), 'R3': round(r3_wood, 4), 'S3': round(s3_wood, 4), 'R4': round(r4_wood, 4), 'S4': round(s4_wood, 4)},
        'Camarilla': {'R1': round(r1_cam, 4), 'S1': round(s1_cam, 4), 'R2': round(r2_cam, 4), 'S2': round(s2_cam, 4), 'R3': round(r3_cam, 4), 'S3': round(s3_cam, 4), 'R4': round(r4_cam, 4), 'S4': round(s4_cam, 4)},
        'DeMark': demark_res
    }

def evaluate_price_alerts(current_price: float, pivot_levels: Dict[str, Any], tolerance_pct: float) -> List[Dict[str, Any]]:
    alerts = []
    for model_name, levels in pivot_levels.items():
        for level_name, level_val in levels.items():
            if level_val is None: continue
            diff_pct = abs(current_price - level_val) / level_val * 100.0
            if diff_pct <= tolerance_pct:
                alert_type = 'RESISTANCE_TOUCH' if 'R' in level_name else ('SUPPORT_TOUCH' if 'S' in level_name else 'PIVOT_CROSS')
                alerts.append({
                    'model': model_name,
                    'level': level_name,
                    'target_price': level_val,
                    'current_price': current_price,
                    'difference_pct': round(diff_pct, 3),
                    'alert_type': alert_type,
                    'message': f'🏛️ UMARMATHI ALERT [{model_name} {level_name}]: Price  is within {diff_pct:.2f}% of target '
                })
    return alerts

def dispatch_phone_webhook_alert(url: str, alert_data: dict):
    try:
        payload = {
            'title': f"🚨 UMARMATHI PHONE ALERT: {alert_data.get('model')} {alert_data.get('level')}",
            'body': alert_data.get('message'),
            'target_price': alert_data.get('target_price'),
            'current_price': alert_data.get('current_price'),
            'difference_pct': alert_data.get('difference_pct'),
            'source': 'UMARMATHI Executive Pivot Suite'
        }
        requests.post(url, json=payload, timeout=3)
    except Exception as e:
        logger.warning(f'Phone dispatch error: {e}')

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'service': 'UMARMATHI Executive Pivot Suite'}), 200

@app.route('/api/v1/calculate', methods=['POST'])
def api_calculate_pivots():
    try:
        data = request.get_json(force=True)
        validated = PivotRequestSchema(**data)
    except ValidationError as e:
        return jsonify({'status': 'error', 'message': 'Invalid parameters', 'details': e.errors()}), 400
    except Exception:
        return jsonify({'status': 'error', 'message': 'Malformed JSON payload'}), 400

    pivots = calculate_pivot_levels(validated.high, validated.low, validated.close, validated.open_price)
    alerts = []
    if validated.current_price:
        alerts = evaluate_price_alerts(validated.current_price, pivots, validated.alert_tolerance_pct)
        if alerts and validated.phone_webhook_url:
            for alert in alerts[:3]:
                dispatch_phone_webhook_alert(validated.phone_webhook_url, alert)

    return jsonify({
        'status': 'success',
        'data': {'inputs': validated.dict(), 'pivots': pivots, 'alerts': alerts, 'alert_count': len(alerts)}
    }), 200

@app.route('/api/v1/test-phone-alert', methods=['POST'])
def api_test_phone_alert():
    try:
        data = request.get_json(force=True)
        validated = TestAlertSchema(**data)
    except ValidationError as e:
        return jsonify({'status': 'error', 'message': 'Invalid webhook format'}), 400

    dummy_alert = {
        'model': 'Standard',
        'level': 'R1',
        'target_price': 2685.50,
        'current_price': 2682.10,
        'difference_pct': 0.12,
        'alert_type': 'RESISTANCE_TOUCH',
        'message': '📱 TEST ALERT [XAUUSD]: Current Price (682.10) touched Standard R1 (685.50).'
    }
    dispatch_phone_webhook_alert(validated.phone_webhook_url, dummy_alert)
    return jsonify({
        'status': 'success',
        'message': 'Phone notification dispatched successfully to your endpoint!',
        'sample_payload': dummy_alert
    }), 200

@app.route('/api/v1/auth/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json(force=True)
        validated = RegisterSchema(**data)
    except ValidationError as e:
        return jsonify({'status': 'error', 'message': 'Validation error', 'details': e.errors()}), 400

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute('SELECT id FROM users WHERE email = ?', (validated.email,))
    if cur.fetchone():
        conn.close()
        return jsonify({'status': 'error', 'message': 'Email address already registered'}), 400

    pass_hash = generate_password_hash(validated.password)
    cur.execute('INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)', (validated.email, validated.name, pass_hash))
    conn.commit()
    conn.close()
    
    session['user_email'] = validated.email
    session['user_name'] = validated.name
    return jsonify({'status': 'success', 'message': 'Registration successful', 'user': {'email': validated.email, 'name': validated.name}}), 201

@app.route('/api/v1/auth/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json(force=True)
        validated = LoginSchema(**data)
    except ValidationError as e:
        return jsonify({'status': 'error', 'message': 'Validation error'}), 400

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute('SELECT name, password_hash FROM users WHERE email = ?', (validated.email,))
    user = cur.fetchone()
    conn.close()

    if not user or not check_password_hash(user[1], validated.password):
        return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401

    session['user_email'] = validated.email
    session['user_name'] = user[0]
    return jsonify({'status': 'success', 'message': 'Login successful', 'user': {'email': validated.email, 'name': user[0]}}), 200

@app.route('/api/v1/auth/logout', methods=['POST', 'GET'])
def api_logout():
    session.clear()
    return redirect(url_for('index_page'))

@app.route('/api/v1/auth/me', methods=['GET'])
def api_me():
    if 'user_email' in session:
        return jsonify({'authenticated': True, 'user': {'email': session['user_email'], 'name': session.get('user_name', 'Executive')}}), 200
    return jsonify({'authenticated': False}), 200


@app.route('/', methods=['GET'])
def index_page():
    tpl_path = os.path.join(os.path.dirname(__file__), 'templates', 'index.html')
    if os.path.exists(tpl_path):
        with open(tpl_path, 'r') as f:
            return render_template_string(f.read())
    return render_template_string('<h1>UMARMATHI Executive Suite</h1>')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
