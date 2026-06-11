# ── Nimbus CRM — intentionally vulnerable demo scan target ────────────────
# WARNING: This container is deliberately insecure. Run it only on an
# isolated network you control and tear it down after the demo.
FROM python:3.11-slim

WORKDIR /app

# ping (used by /admin/diagnostics) + iproute2 for basic network utils
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ ./templates/

# Seed data lives in /tmp inside the container (ephemeral is fine for a demo)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 80

HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost/login')" || exit 1

# Use gunicorn with a single sync worker — the app uses blocking sqlite/subprocess
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:80", "--workers", "1", "--timeout", "60"]
