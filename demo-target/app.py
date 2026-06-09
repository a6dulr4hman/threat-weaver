"""
Nimbus CRM -- a lightweight customer relationship management app.

A small internal tool for managing customers, viewing account records,
running reports, and downloading exported documents.

Run with: python app.py
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
app.secret_key = "nimbus-crm-dev-key"

DB_PATH = "/tmp/nimbus_crm.db"
DOCS_DIR = "/tmp/nimbus_docs"


def init_db():
    """Create and seed the CRM database."""
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
    """Create exportable documents for the download feature."""
    os.makedirs(DOCS_DIR, exist_ok=True)
    with open(os.path.join(DOCS_DIR, "welcome.txt"), "w") as f:
        f.write("Welcome to Nimbus CRM. This is your exported account summary.\n")
    with open(os.path.join(DOCS_DIR, "q1-report.txt"), "w") as f:
        f.write("Q1 revenue report: MRR up 12% QoQ.\n")


def login_required(view):
    """Session guard for authenticated pages."""
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapper.__name__ = view.__name__
    return wrapper


# --- Domain verification ---------------------------------------------------
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
    """Search customers by name or company."""
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
    """Return customer record by ID."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT * FROM customers WHERE id = {cid}"
    rows = cur.execute(query).fetchall()
    conn.close()
    return jsonify({"customer": rows})


# --- Document export -------------------------------------------------------
@app.route("/download")
@login_required
def download():
    """Download an exported document by filename."""
    name = request.args.get("file", "welcome.txt")
    with open(os.path.join(DOCS_DIR, name)) as f:
        content = f.read()
    return app.response_class(content, mimetype="text/plain")


# --- Admin tools -----------------------------------------------------------
@app.route("/admin")
@login_required
def admin_home():
    """Admin console with maintenance utilities."""
    return render_template(
        "admin.html", user=session.get("user"), role=session.get("role")
    )


@app.route("/admin/diagnostics")
@login_required
def diagnostics():
    """Check connectivity to a host (ping)."""
    host = request.args.get("host", "localhost")
    output = subprocess.check_output(
        f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT
    )
    return jsonify({"host": host, "result": output.decode("utf-8", errors="ignore")})


@app.route("/admin/backup")
@login_required
def backup():
    """Trigger a labelled backup of the export directory."""
    label = request.args.get("label", "manual")
    os.system(f"tar czf /tmp/nimbus_backup_{label}.tgz {DOCS_DIR}")
    return jsonify({"status": "backup started", "label": label})


# --- Report builder --------------------------------------------------------
@app.route("/reports/compute")
@login_required
def compute_report():
    """
    Evaluate a formula over CRM metrics.
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
    result = eval(formula, {"__builtins__": {}}, context)
    return jsonify({"formula": formula, "result": result, "metrics": context})


if __name__ == "__main__":
    init_db()
    seed_docs()
    app.run(host="0.0.0.0", port=80)
