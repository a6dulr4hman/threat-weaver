# Nimbus CRM (ThreatWeaver demo target)

A small, realistic-looking customer relationship management app — login,
customer dashboard, search, document export, admin diagnostics, and a report
builder. It's used as the **scan target** for demonstrating ThreatWeaver.

> ⚠️ **Intentionally insecure.** Run it only on a disposable demo host you
> control, and tear it down afterwards. Never put it on a production network.

## Deploy

On your demo VM:

```bash
git clone https://github.com/a6dulr4hman/threat-weaver.git
cd threat-weaver/demo-target
chmod +x deploy.sh
sudo ./deploy.sh
```

This installs Nimbus CRM as a systemd service on **port 80** and vsftpd on
**port 21**. It prints the public URL and login on completion.

### Open the firewall

In **Azure Portal → your VM → Networking → NSG**, add inbound rules allowing
TCP **80** (web), **21** (FTP control), and **40000-40010** (FTP passive data).

## Routing: use DNS-only, not the Cloudflare proxy

If you front this with a domain name, set the DNS record to **DNS-only (grey
cloud)**. The orange-cloud proxy would make nmap scan Cloudflare's edge instead
of your server, and may block payloads before they reach the app.

## Run the showcase

1. Create a ThreatWeaver workspace targeting your server IP or domain.
2. Verify the domain (set `TW_NONCE` in the service unit to serve
   `/threatweaver.txt`, or use `MOCK_VERIFICATION=true` for the demo).
3. Click **Start New Scan** and watch K2-Think-v2 drive the pipeline live.

## Quick smoke test

```bash
curl http://<server-ip>/login            # sign-in page (200)
nmap -sV -p 21,80 <server-ip>           # fingerprints services
```

## Tear it down after the demo

```bash
sudo systemctl disable --now nimbus-crm vsftpd-backdoor
sudo rm -rf /opt/nimbus-crm /etc/systemd/system/nimbus-crm.service
sudo rm -rf /etc/systemd/system/vsftpd-backdoor.service
sudo rm -rf /usr/local/sbin/vsftpd_234 /etc/vsftpd /srv/ftp
```
