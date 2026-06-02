# ThreatWeaver Demo Target

A **deliberately vulnerable** Flask app to showcase the ThreatWeaver scanner in
a live demo. Its vulnerabilities are hand-picked to trigger findings in *both*
halves of the scanner: static analysis (SAST) and active fuzzing (DAST).

> ⚠️ **This app is intentionally insecure.** Run it only on a disposable VM you
> control (e.g. a throwaway competition demo box) and tear it down afterwards.
> Never expose it on a production network.

## What it demonstrates

| Endpoint | Vulnerability | ThreatWeaver detector |
|----------|---------------|-----------------------|
| `/api/user?id=1` | SQL injection (f-string `.execute()`) | SAST `raw_sql` + DAST 500 |
| `/api/search?q=alice` | SQL injection, error-leaking | SAST `raw_sql` + DAST 500 |
| `/api/ping?host=127.0.0.1` | Command injection (`subprocess`, `shell=True`) | SAST `subprocess` |
| `/api/whoami?label=x` | Command injection (`os.system`) | SAST `subprocess` |
| `/api/calc?expr=1+1` | Code execution (`eval`) | SAST `code_execution` + DAST 500 |
| `/api/file?name=motd.txt` | Path traversal (`open()`) | SAST `file_io` |

The SAST layer scores `vulnerable_app.py` at **risk 100** with 9 findings.

## Deploy it on your server (you run this, not me)

I deliberately do **not** want your SSH credentials — you keep control of the
box. On your demo VM:

```bash
# 1. Clone your repo (or just copy the demo-target/ folder over)
git clone https://github.com/a6dulr4hman/threat-weaver.git
cd threat-weaver/demo-target

# 2. Run the one-shot deploy (installs a systemd service on port 8080)
chmod +x deploy.sh
sudo ./deploy.sh
```

The script prints your public IP and the URL to point ThreatWeaver at. It's
tuned for a 1 GB / 1 CPU box (single gunicorn worker, 256 MB memory cap).

### Open the firewall

In the **Azure Portal → your VM → Networking → Network Security Group**, add an
inbound rule allowing TCP **8080** (and 80/443 if you proxy it). Without this,
the scanner can't reach the target from outside.

## Run the showcase

1. In ThreatWeaver, create a workspace targeting your server's IP or domain.
2. **Domain verification** — pick one:
   - **HTTP:** copy the nonce from the workspace, set it on the server, and
     restart so `/threatweaver.txt` serves it:
     ```bash
     sudo sed -i "s/^Environment=TW_NONCE=.*/Environment=TW_NONCE=<paste-nonce>/" \
       /etc/systemd/system/tw-demo-target.service
     sudo systemctl daemon-reload && sudo systemctl restart tw-demo-target
     ```
   - **Shortcut for the demo:** set `MOCK_VERIFICATION=true` in ThreatWeaver to
     auto-accept (already supported).
3. Import the repo URL (`https://github.com/a6dulr4hman/threat-weaver`) — or a
   repo containing `vulnerable_app.py` — so the SAST layer has Python to chew on.
4. Click **Start New Scan** and watch K2-Think-v2 drive recon → DAST → PoC →
   remediation live.

## Quick smoke test

```bash
curl http://<server-ip>:8080/                       # endpoint listing
curl "http://<server-ip>:8080/api/user?id=1"         # normal response
curl "http://<server-ip>:8080/api/search?q=%27"      # -> HTTP 500 (anomaly)
```

## Tear it down after the demo

```bash
sudo systemctl disable --now tw-demo-target
sudo rm -rf /opt/tw-demo-target /etc/systemd/system/tw-demo-target.service
```
