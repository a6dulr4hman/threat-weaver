# ── Stage 1: build deps ───────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install nmap (needed for recon) and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        gcc \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# nmap must be in the runtime image too (subprocess calls it at scan time)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY app/ ./app/
COPY requirements.txt .

# Persistent data dirs (override with named volumes in docker-compose)
RUN mkdir -p /data /tmp/threatweaver/reports

# Non-root user for safety
RUN useradd -r -s /bin/false appuser \
    && chown -R appuser /app /data /tmp/threatweaver
USER appuser

# Uvicorn
ENV DATABASE_URL="sqlite+aiosqlite:////data/threatweaver.db" \
    REPORT_DIR="/tmp/threatweaver/reports" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/sign-in')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]
