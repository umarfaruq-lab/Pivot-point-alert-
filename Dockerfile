# ==========================================
# OWASP Hardened Production Dockerfile
# ==========================================
FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt gunicorn

# Final Runtime Stage
FROM python:3.12-slim AS runner

WORKDIR /app

# Create a non-root dedicated security user/group WITH home directory (-m)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser

COPY --from=builder /install /usr/local
COPY . /app

# Adjust permissions for non-root execution on both /app and /home/appuser
RUN chown -R appuser:appgroup /app /home/appuser

USER appuser:appgroup

ENV HOME=/home/appuser

EXPOSE 5000

# Healthcheck to monitor app status
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health').read()" || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--worker-tmp-dir", "/dev/shm", "--timeout", "60", "wsgi:app"]
