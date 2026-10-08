# 📈 OWASP Top 10 Secured Pivot Point Web Application & Alert Engine

A production-ready, OWASP Top 10 compliant web application and API that calculates multi-model pivot points (Standard, Fibonacci, Woodie's, Camarilla, DeMark) and triggers real-time price alerts when live asset prices approach key support or resistance levels.

---

## 🚀 Quick Deploy to Render (1-Click Blueprint)

1. Fork or push this repository to your **GitHub** account.
2. Log into **[Render.com](https://render.com)**.
3. Click **New +** -> **Blueprint**.
4. Connect your GitHub repository containing this project.
5. Render will automatically read `render.yaml` and configure the service:
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn wsgi:app`
   - **Health Check Path**: `/health`
6. Click **Apply** to deploy!

---

## 🛠️ Manual Configuration on Render

If deploying manually without Blueprint:
- **Environment**: Python 3
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn wsgi:app`
- **Health Check Path**: `/health`

If deploying as a **Docker** service on Render:
- **Environment**: Docker
- **Environment Variable**: Set `PORT=5000`

---

## 💻 Local Execution

```bash
pip install -r requirements.txt
python wsgi.py
```
Open `http://localhost:5000` in your web browser.

---

## 🔒 Security Architecture (OWASP Top 10 Compliant)

- **A01:2021 – Access Control & SSRF**: Domain whitelisting for external trading APIs and internal IP blocking.
- **A03:2021 – Injection Prevention**: Strict type checking via Pydantic schemas and regex ticker sanitization.
- **A05:2021 – Security Headers**: Automatic application of CSP, HSTS, X-Frame-Options (DENY), and X-Content-Type-Options.
- **A09:2021 – Logging & Audit**: Structured security logs for alerts and parameters.
