# ── ThreatWeaver ──────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# ---------------------------------------------------------------------------
# System dependencies — everything the app needs to run, installed once.
# nmap: port/service scanning (run_nmap tool)
# iputils-ping: used if any future diagnostic tool needs ping
# curl: useful for health-check debugging
# We set the setuid bit on nmap so the non-root app user can run raw-socket
# version probes without needing NET_RAW capabilities.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        iputils-ping \
        curl \
        libssl-dev \
        ca-certificates \
    && chmod u+s /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Python dependencies
# ---------------------------------------------------------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Application source
# ---------------------------------------------------------------------------
COPY app/ ./app/

# ---------------------------------------------------------------------------
# Runtime directories and non-root user
# ---------------------------------------------------------------------------
RUN mkdir -p /data /tmp/threatweaver/reports \
    && useradd -r -u 1001 -s /bin/false appuser \
    && chown -R appuser:appuser /app /data /tmp/threatweaver

USER appuser

# ---------------------------------------------------------------------------
# Environment defaults (override in docker-compose.yml or .env)
# ---------------------------------------------------------------------------
ENV DATABASE_URL="sqlite+aiosqlite:////data/threatweaver.db" \
    REPORT_DIR="/tmp/threatweaver/reports" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -fs http://localhost:8000/sign-in > /dev/null || exit 1

# ---------------------------------------------------------------------------
# Run uvicorn with proxy-headers so the app respects X-Forwarded-Proto
# (required when running behind Traefik, Nginx, Azure App Gateway, etc.)
# ---------------------------------------------------------------------------
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
