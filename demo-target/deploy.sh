#!/usr/bin/env bash
#
# Nimbus CRM -- one-shot deploy script (ThreatWeaver demo target).
#
# Run this ON YOUR OWN demo VM (e.g. the throwaway Azure box). It installs the
# Nimbus CRM app as a systemd service on port 80.
#
# Usage:
#   chmod +x deploy.sh
#   sudo ./deploy.sh
#
# Tuned for a small VM (1 GB RAM / 1 CPU): a single gunicorn worker.
#
# NOTE: this app intentionally contains realistic security flaws so the
# ThreatWeaver scanner has something to find. Only run it on a disposable
# machine you control and tear it down after the demo (see teardown below).

set -euo pipefail

APP_DIR="/opt/nimbus-crm"
SERVICE_NAME="nimbus-crm"
PORT="80"

echo "==> Installing system packages (python3, venv, pip)..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3 python3-venv python3-pip iputils-ping
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip iputils
fi

echo "==> Copying application to ${APP_DIR}..."
mkdir -p "${APP_DIR}/templates"
cp "$(dirname "$0")/app.py" "${APP_DIR}/"
cp "$(dirname "$0")/requirements.txt" "${APP_DIR}/"
cp "$(dirname "$0")/templates/"*.html "${APP_DIR}/templates/"

echo "==> Creating virtualenv and installing dependencies..."
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --upgrade pip
"${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

echo "==> Seeding database and demo documents..."
"${APP_DIR}/venv/bin/python" - <<'PYEOF'
import sys
sys.path.insert(0, "/opt/nimbus-crm")
import app
app.init_db()
app.seed_docs()
print("seeded.")
PYEOF

echo "==> Writing systemd unit /etc/systemd/system/${SERVICE_NAME}.service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Nimbus CRM (ThreatWeaver demo target)
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
# Optional: set the verification nonce from your ThreatWeaver workspace so the
# HTTP /threatweaver.txt check passes. Replace the value, then re-run deploy.
Environment=TW_NONCE=
# Binding to port 80 requires the capability below (gunicorn runs as root here
# for demo simplicity; fine on a throwaway VM).
ExecStart=${APP_DIR}/venv/bin/gunicorn --workers 1 --bind 0.0.0.0:${PORT} app:app
Restart=on-failure
# Light resource cap so the demo can't exhaust a 1GB box.
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF

echo "==> Enabling and starting the service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

sleep 2
echo
echo "==> Done. Service status:"
systemctl --no-pager status "${SERVICE_NAME}" | head -n 8 || true
echo
PUBLIC_IP="$(curl -s --max-time 5 ifconfig.me || echo '<your-server-ip>')"
echo "============================================================"
echo " Nimbus CRM is live on port ${PORT}."
echo "   Local check : curl http://localhost/"
echo "   From outside: http://${PUBLIC_IP}/"
echo "   Login       : admin / S3cur3Adm1n!  (or sales / letmein)"
echo
echo " Point ThreatWeaver at: ${PUBLIC_IP}  (or your DNS name, DNS-only)"
echo
echo " IMPORTANT: open port ${PORT} in your Azure Network Security Group."
echo " Teardown after the demo:"
echo "   sudo systemctl disable --now ${SERVICE_NAME}"
echo "   sudo rm -rf ${APP_DIR} /etc/systemd/system/${SERVICE_NAME}.service"
echo "============================================================"
