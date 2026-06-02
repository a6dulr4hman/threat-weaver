"""
ThreatWeaver Demo Target -- DELIBERATELY VULNERABLE web application.

!!! WARNING -------------------------------------------------------------- !!!
This application contains INTENTIONAL security vulnerabilities. It exists
solely as a scan target to demonstrate the ThreatWeaver scanner in a
controlled environment (e.g. a throwaway competition demo VM).

DO NOT:
  - deploy this on a production network
  - expose it to untrusted users
  - reuse any of this code in a real application

The vulnerabilities below are chosen to map onto what ThreatWeaver detects:
  * SQL injection      (raw .execute() with f-string)  -> SAST: raw_sql
  * Command injection  (os.system / subprocess)        -> SAST: subprocess
  * Code execution     (eval / exec)                    -> SAST: code_execution
  * Path traversal     (open() on user input)           -> SAST: file_io
  * Unauthenticated, error-leaking endpoints            -> DAST: 500 anomalies
!!! ---------------------------------------------------------------------- !!!
"""
import os
import sqlite3
import subprocess

from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__)

DB_PATH = "/tmp/demo_target.db"


def init_db():
    """Seed a tiny SQLite database used by the vulnerable endpoints."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)"
    )
    cur.execute("DELETE FROM users")
    cur.executemany(
        "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
        [
            ("alice", "alice@example.com", "admin"),
            ("bob", "bob@example.com", "user"),
            ("carol", "carol@example.com", "user"),
        ],
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    """Landing page listing the available (vulnerable) endpoints."""
    return jsonify({
        "service": "ThreatWeaver Demo Target",
        "warning": "Intentionally vulnerable. Demo use only.",
        "endpoints": [
            "/api/user?id=1            (SQL injection)",
            "/api/ping?host=127.0.0.1  (command injection)",
            "/api/calc?expr=1+1        (code execution via eval)",
            "/api/file?name=motd.txt   (path traversal)",
            "/api/search?q=alice       (reflected, error-leaking)",
        ],
    })


# --- Verification endpoint (so ThreatWeaver can verify domain ownership) ---
@app.route("/threatweaver.txt")
def threatweaver_verification():
    """
    Serve the verification nonce. Set the TW_NONCE env var to the nonce shown
    in the ThreatWeaver workspace, then HTTP verification will pass.
    """
    nonce = os.environ.get("TW_NONCE", "")
    return app.response_class(nonce, mimetype="text/plain")


# --- VULN 1: SQL injection (raw_sql) --------------------------------------
@app.route("/api/user")
def get_user():
    """VULNERABLE: builds SQL with an f-string from untrusted input."""
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Intentionally vulnerable: direct string interpolation into SQL.
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    rows = cur.execute(query).fetchall()
    conn.close()
    return jsonify({"query": query, "rows": rows})


# --- VULN 2: Command injection (subprocess) -------------------------------
@app.route("/api/ping")
def ping():
    """VULNERABLE: passes untrusted input straight into a shell command."""
    host = request.args.get("host", "127.0.0.1")
    # Intentionally vulnerable: shell=True with unsanitized input.
    output = subprocess.check_output(
        f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT
    )
    return jsonify({"output": output.decode("utf-8", errors="ignore")})


@app.route("/api/whoami")
def whoami():
    """VULNERABLE: os.system with attacker-influenced argument."""
    label = request.args.get("label", "user")
    os.system(f"echo current user: $(whoami) [{label}]")
    return jsonify({"status": "ran whoami"})


# --- VULN 3: Code execution (code_execution) ------------------------------
@app.route("/api/calc")
def calc():
    """VULNERABLE: evaluates an arbitrary expression from the request."""
    expr = request.args.get("expr", "1+1")
    # Intentionally vulnerable: eval on untrusted input.
    result = eval(expr)  # noqa: S307
    return jsonify({"expr": expr, "result": result})


# --- VULN 4: Path traversal (file_io) -------------------------------------
@app.route("/api/file")
def read_file():
    """VULNERABLE: opens a user-supplied path with no sanitization."""
    name = request.args.get("name", "motd.txt")
    # Intentionally vulnerable: no path validation -> ../ traversal.
    with open(os.path.join("/tmp/demo_files", name)) as f:
        content = f.read()
    return jsonify({"name": name, "content": content})


# --- VULN 5: Reflected, error-leaking search (DAST anomaly source) --------
@app.route("/api/search")
def search():
    """
    VULNERABLE: another SQL-injectable endpoint whose errors are unhandled,
    so malformed payloads bubble up as HTTP 500 -- exactly what the
    ThreatWeaver DAST fuzzer looks for.
    """
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT username, email FROM users WHERE username LIKE '%{q}%'"
    rows = cur.execute(query).fetchall()
    conn.close()
    return jsonify({"results": rows})


def seed_files():
    """Create a couple of files for the path-traversal endpoint to read."""
    os.makedirs("/tmp/demo_files", exist_ok=True)
    with open("/tmp/demo_files/motd.txt", "w") as f:
        f.write("Welcome to the ThreatWeaver demo target.\n")


if __name__ == "__main__":
    init_db()
    seed_files()
    # Bind to all interfaces so the scanner (and you) can reach it.
    app.run(host="0.0.0.0", port=8080)
