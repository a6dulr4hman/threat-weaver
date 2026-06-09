#!/usr/bin/env bash
#
# Nimbus CRM -- one-shot deploy script for the ThreatWeaver demo target.
#
# Usage:
#   chmod +x deploy.sh
#   sudo ./deploy.sh
#
# Only run this on a disposable machine you control.
# Tear it down after the demo (see end of script).

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

# --- vsftpd 2.3.4 (compiled from archived source) -------------------------
echo "==> Building vsftpd 2.3.4 from source..."

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
    # The extracted directory name varies (e.g. vsftpd-2.3.4-infected-master or
    # vsftpd-2.3.4-infected-vsftpd_original depending on the default branch).
    # Just find and enter whatever single directory was extracted.
    VSFTPD_DIR="$(find . -maxdepth 1 -type d -name 'vsftpd-2.3.4*' | head -1)"
    if [ -z "$VSFTPD_DIR" ]; then
        echo "    ERROR: could not find extracted vsftpd directory."
    else
        cd "$VSFTPD_DIR"

        # Fix for modern linkers: libcrypt, libpam, libcap, libssl all need
        # explicit linking on modern distros (they used to be pulled implicitly).
        sed -i 's|^LIBS\s*=.*|& -lcrypt -lpam -lcap -lssl|' Makefile 2>/dev/null || true

        if make -j"$(nproc)" 2>&1 | tail -3; then
            cp vsftpd /usr/local/sbin/vsftpd_234
            chmod 755 /usr/local/sbin/vsftpd_234
            VSFTPD_OK=true
            echo "    Built successfully: /usr/local/sbin/vsftpd_234"
        else
            echo "    ERROR: compilation failed."
        fi
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
Description=vsftpd 2.3.4
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
    echo "    vsftpd 2.3.4 is running on port 21."
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
echo " vsftpd 2.3.4 is on port 21."
echo
echo " Point ThreatWeaver at: ${PUBLIC_IP}  (or your DNS name)"
echo
echo " IMPORTANT: open these ports in your Azure NSG:"
echo "   80   = Nimbus CRM web app"
echo "   21   = vsftpd (FTP)"
echo "   6200 = (opened dynamically)"
echo
echo " Teardown after the demo:"
echo "   sudo systemctl disable --now ${SERVICE_NAME} vsftpd-backdoor"
echo "   sudo rm -rf ${APP_DIR} /etc/systemd/system/${SERVICE_NAME}.service"
echo "   sudo rm -rf /etc/systemd/system/vsftpd-backdoor.service"
echo "   sudo rm -rf /usr/local/sbin/vsftpd_234 /etc/vsftpd /srv/ftp"
echo "============================================================"
