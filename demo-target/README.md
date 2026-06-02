# Nimbus CRM (ThreatWeaver demo target)

A small, realistic-looking customer relationship management app — login,
customer dashboard, search, document export, admin diagnostics, and a report
builder. It's used as the **scan target** for demonstrating ThreatWeaver.

Unlike an obvious "hack me" target, Nimbus CRM looks like an ordinary internal
tool. The vulnerabilities are woven into normal features, so the demo shows the
scanner discovering flaws in something that resembles a real product.

> ⚠️ **Intentionally insecure.** The realistic features hide deliberate, common
> security mistakes. Run it only on a disposable demo host you control, and tear
> it down afterwards. Never put it on a production network.

## The app (what judges see)

| Page | Looks like | Hidden flaw | ThreatWeaver detector |
|------|-----------|-------------|-----------------------|
| `/login` | Sign-in form | SQL injection auth bypass (`admin' --`) | SAST `raw_sql` |
| `/customers?q=` | Customer search | SQL injection (error-leaking) | SAST `raw_sql` + DAST 500 |
| `/customer/<id>` | Account detail | SQL injection | SAST `raw_sql` + DAST 500 |
| `/download?file=` | Document export | Path traversal | SAST `file_io` |
| `/admin/diagnostics?host=` | Mail-host connectivity check | Command injection (`subprocess`) | SAST `subprocess` |
| `/admin/backup?label=` | Trigger backup | Command injection (`os.system`) | SAST `subprocess` |
| `/reports/compute?formula=` | Revenue formula builder | Code execution (`eval`) | SAST `code_execution` + DAST 500 |

The SAST layer scores `app.py` at **risk 100** with 15 findings spanning
`raw_sql`, `subprocess`, `code_execution`, and `file_io`.

**Demo credentials:** `admin` / `S3cur3Adm1n!` (or `sales` / `letmein`).
For the live show, the SQLi bypass `admin' --` with any password also logs in.

## Deploy it on your server (you run this, not me)

On your demo VM:

```bash
git clone https://github.com/a6dulr4hman/threat-weaver.git
cd threat-weaver/demo-target
chmod +x deploy.sh
sudo ./deploy.sh
```

This installs Nimbus CRM as a systemd service on **port 80**, tuned for a
1 GB / 1 CPU box (single gunicorn worker, 256 MB cap). It prints the public URL
and login on completion. The app is then reachable at `http://<server-ip>/`.

### Open the firewall

In **Azure Portal → your VM → Networking → NSG**, add an inbound rule allowing
TCP **80**. Without it, the scanner can't reach the target.

## Routing: use DNS-only, not the Cloudflare proxy

If you front this with `threatweaver.falak.dev`, set the DNS record to
**DNS-only (grey cloud)**. The orange-cloud proxy would (a) make nmap scan
Cloudflare's edge instead of your server, and (b) let Cloudflare's WAF block the
exploit payloads before they reach the app — both of which break the demo.

## Run the showcase

1. Create a ThreatWeaver workspace targeting your server IP or `threatweaver.falak.dev`.
2. Verify the domain (set `TW_NONCE` in the service unit to serve
   `/threatweaver.txt`, or use `MOCK_VERIFICATION=true` for the demo).
3. Import a repo containing `app.py` so the Python SAST layer has code to analyze.
4. Click **Start New Scan** and watch K2-Think-v2 drive recon → DAST → PoC →
   remediation live.

## Quick smoke test

```bash
curl http://<server-ip>/login                                  # sign-in page (200)
curl "http://<server-ip>/customer/abc"                          # -> 500 (SQLi anomaly)
curl "http://<server-ip>/reports/compute?formula=__import__(1)" # -> 500 (eval anomaly)
```

## Tear it down after the demo

```bash
sudo systemctl disable --now nimbus-crm
sudo rm -rf /opt/nimbus-crm /etc/systemd/system/nimbus-crm.service
```
