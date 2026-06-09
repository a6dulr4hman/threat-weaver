"""
Nimbus CRM -- a lightweight customer relationship management app.

A small internal tool for managing customers, viewing account records,
running reports, and downloading exported documents.

NOTE FOR REVIEWERS / DEMO OPERATORS
-----------------------------------
This application is used as the scan target for a ThreatWeaver demonstration.
It deliberately contains realistic, common security mistakes of the kind a real
CRM might ship with -- they are woven into ordinary-looking features (login,
search, document export, admin diagnostics, report builder) rather than
flagged as obvious "vulnerabilities". Run it ONLY on a disposable demo host.

Vulnerability map (for the scanner, not visible to end users):
  * Login form          -> SQL injection (auth bypass) via raw .execute()
  * Customer search      -> SQL injection (error-leaking 500s)
  * Document download    -> path traversal via open()
  * Admin "diagnostics"  -> command injection (subprocess / os.system)
  * Report builder        -> code execution via eval()
"""
import os
import sqlite3
import subprocess

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = "nimbus-crm-dev-key"  # demo only

DB_PATH = "/tmp/nimbus_crm.db"
DOCS_DIR = "/tmp/nimbus_docs"


def init_db():
    """Create and seed the CRM database (customers + app users)."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS customers ("
        "id INTEGER PRIMARY KEY, name TEXT, company TEXT, email TEXT, "
        "phone TEXT, status TEXT, mrr INTEGER)"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    cur.execute("DELETE FROM customers")
    cur.execute("DELETE FROM users")
    cur.executemany(
        "INSERT INTO customers (name, company, email, phone, status, mrr) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("Alice Tan", "Acme Corp", "alice@acme.example", "555-0101", "active", 1200),
            ("Bob Reyes", "Globex", "bob@globex.example", "555-0102", "active", 800),
            ("Carol Diaz", "Initech", "carol@initech.example", "555-0103", "churned", 0),
            ("David Lee", "Umbrella", "david@umbrella.example", "555-0104", "active", 2500),
            ("Eva Stone", "Soylent", "eva@soylent.example", "555-0105", "trial", 0),
        ],
    )
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("admin", "S3cur3Adm1n!", "admin"),
            ("sales", "letmein", "user"),
        ],
    )
    conn.commit()
    conn.close()


def seed_docs():
    """Create a few exportable documents for the download feature."""
    os.makedirs(DOCS_DIR, exist_ok=True)
    with open(os.path.join(DOCS_DIR, "welcome.txt"), "w") as f:
        f.write("Welcome to Nimbus CRM. This is your exported account summary.\n")
    with open(os.path.join(DOCS_DIR, "q1-report.txt"), "w") as f:
        f.write("Q1 revenue report: MRR up 12% QoQ.\n")


def login_required(view):
    """Simple session guard for authenticated pages."""
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapper.__name__ = view.__name__
    return wrapper


# --- Domain verification (kept inconspicuous) ------------------------------
@app.route("/threatweaver.txt")
def _verification():
    """Serve the ThreatWeaver ownership nonce from the TW_NONCE env var."""
    return app.response_class(os.environ.get("TW_NONCE", ""), mimetype="text/plain")


# --- Auth ------------------------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # Looks like an ordinary login lookup; actually SQL-injectable.
        query = (
            "SELECT id, username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        row = cur.execute(query).fetchone()
        conn.close()
        if row:
            session["user"] = row[1]
            session["role"] = row[2]
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Dashboard + customers -------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    customers = cur.execute(
        "SELECT id, name, company, email, phone, status, mrr FROM customers"
    ).fetchall()
    total_mrr = sum(c[6] for c in customers)
    active = sum(1 for c in customers if c[5] == "active")
    conn.close()
    return render_template(
        "dashboard.html",
        customers=customers,
        total_mrr=total_mrr,
        active=active,
        user=session.get("user"),
        role=session.get("role"),
    )


@app.route("/customers")
@login_required
def customer_search():
    """Customer search. The 'q' filter is concatenated straight into SQL."""
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = (
        "SELECT id, name, company, email, phone, status, mrr FROM customers "
        f"WHERE name LIKE '%{q}%' OR company LIKE '%{q}%'"
    )
    customers = cur.execute(query).fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        customers=customers,
        total_mrr=sum(c[6] for c in customers),
        active=sum(1 for c in customers if c[5] == "active"),
        user=session.get("user"),
        role=session.get("role"),
        search_term=q,
    )


@app.route("/customer/<cid>")
@login_required
def customer_detail(cid):
    """Customer detail lookup -- id is interpolated into the query."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT * FROM customers WHERE id = {cid}"
    rows = cur.execute(query).fetchall()
    conn.close()
    return jsonify({"customer": rows})


# --- Document export (path traversal) --------------------------------------
@app.route("/download")
@login_required
def download():
    """Download an exported document by filename."""
    name = request.args.get("file", "welcome.txt")
    with open(os.path.join(DOCS_DIR, name)) as f:
        content = f.read()
    return app.response_class(content, mimetype="text/plain")


# --- Admin diagnostics (command injection) ---------------------------------
@app.route("/admin")
@login_required
def admin_home():
    """Admin console hub linking to the maintenance tools."""
    return render_template(
        "admin.html", user=session.get("user"), role=session.get("role")
    )


@app.route("/admin/diagnostics")
@login_required
def diagnostics():
    """Admin tool to check connectivity to a customer's mail host."""
    host = request.args.get("host", "localhost")
    output = subprocess.check_output(
        f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT
    )
    return jsonify({"host": host, "result": output.decode("utf-8", errors="ignore")})


@app.route("/admin/backup")
@login_required
def backup():
    """Admin tool that triggers a labelled backup of the export directory."""
    label = request.args.get("label", "manual")
    os.system(f"tar czf /tmp/nimbus_backup_{label}.tgz {DOCS_DIR}")
    return jsonify({"status": "backup started", "label": label})


# --- Report builder (code execution) ---------------------------------------
@app.route("/reports/compute")
@login_required
def compute_report():
    """
    Report builder: evaluates a small formula over CRM metrics.
    e.g. ?formula=total_mrr * 12  -> projected annual revenue.
    """
    formula = request.args.get("formula", "total_mrr * 12")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    customers = cur.execute("SELECT mrr, status FROM customers").fetchall()
    conn.close()
    context = {
        "total_mrr": sum(c[0] for c in customers),
        "active": sum(1 for c in customers if c[1] == "active"),
        "count": len(customers),
    }
    # Looks like a formula evaluator; actually arbitrary code execution.
    result = eval(formula, {"__builtins__": {}}, context)  # noqa: S307
    return jsonify({"formula": formula, "result": result, "metrics": context})


# --- FTP backdoor simulator (CVE-2011-2523 / vsftpd 2.3.4) ----------------
# The real vulnerability: when a client sends a username ending with ":)" the
# trojanized vsftpd opens a root shell listener on port 6200. This simulator
# reproduces that behaviour so the ThreatWeaver PoC can confirm the backdoor.
# It runs as a background daemon thread alongside the Flask app.
import socket
import threading


def _ftp_backdoor_server():
    """
    Minimal FTP server that triggers the backdoor on USER x:)
    Opens port 6200 with a fake shell when the magic payload is sent.
    """
    BACKDOOR_PORT = 6200
    FTP_PORT = 2121  # Non-privileged; deploy.sh iptables-redirects 21 -> 2121

    def _handle_ftp_client(conn):
        """Handle one FTP client connection."""
        try:
            conn.sendall(b"220 vsftpd 2.3.4 ready\r\n")
            triggered = False
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                line = data.decode("utf-8", errors="ignore").strip()
                if line.upper().startswith("USER") and ":)" in line:
                    triggered = True
                    conn.sendall(b"331 Please specify the password.\r\n")
                elif line.upper().startswith("USER"):
                    conn.sendall(b"331 Please specify the password.\r\n")
                elif line.upper().startswith("PASS"):
                    if triggered:
                        conn.sendall(b"230 Login successful.\r\n")
                        # Open the backdoor shell on port 6200
                        _open_backdoor_shell()
                    else:
                        conn.sendall(b"530 Login incorrect.\r\n")
                elif line.upper() == "QUIT":
                    conn.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    conn.sendall(b"500 Unknown command.\r\n")
        except Exception:
            pass
        finally:
            conn.close()

    def _open_backdoor_shell():
        """Open a fake root shell on port 6200 for ~30 seconds."""
        def _shell_handler():
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", BACKDOOR_PORT))
                srv.listen(1)
                srv.settimeout(30)
                client, _ = srv.accept()
                client.sendall(b"uid=0(root) gid=0(root) groups=0(root)\n# ")
                while True:
                    cmd = client.recv(1024)
                    if not cmd:
                        break
                    cmd_str = cmd.decode("utf-8", errors="ignore").strip()
                    if cmd_str in ("exit", "quit"):
                        break
                    elif cmd_str == "id":
                        client.sendall(b"uid=0(root) gid=0(root) groups=0(root)\n# ")
                    elif cmd_str == "whoami":
                        client.sendall(b"root\n# ")
                    elif cmd_str == "uname -a":
                        client.sendall(b"Linux nimbus-crm 5.15.0 #1 SMP x86_64 GNU/Linux\n# ")
                    else:
                        client.sendall(f"{cmd_str}: command executed\n# ".encode())
                client.close()
            except Exception:
                pass
            finally:
                srv.close()
        threading.Thread(target=_shell_handler, daemon=True).start()

    # Main FTP listener loop
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", FTP_PORT))
        srv.listen(5)
        while True:
            client, _ = srv.accept()
            threading.Thread(target=_handle_ftp_client, args=(client,), daemon=True).start()
    except Exception:
        pass


# Start the FTP backdoor simulator in a background thread
threading.Thread(target=_ftp_backdoor_server, daemon=True).start()


if __name__ == "__main__":
    init_db()
    seed_docs()
    # Port 80 so the app is reachable at http://<host>/ with no port suffix.
    app.run(host="0.0.0.0", port=80)
