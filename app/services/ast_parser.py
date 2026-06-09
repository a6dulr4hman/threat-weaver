"""Code ingestion, AST analysis, and vulnerability deduplication."""
from __future__ import annotations

import ast
import hashlib
import os
import re
import zipfile
from pathlib import Path


def extract_zip(zip_path: str, dest_dir: str) -> str:
    """Safely extract a zip file to destination directory. Returns dest_dir path."""
    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            member_path = (dest / member).resolve()
            # Prevent zip slip attack
            if not str(member_path).startswith(str(dest)):
                raise ValueError(f"Zip slip detected: {member}")
        zf.extractall(dest_dir)

    return str(dest)


def analyze_codebase(directory: str) -> dict:
    """
    Walk directory, parse Python files with ast module.
    Identify high-risk patterns:
    - Raw SQL: cursor.execute, text(), raw queries
    - File I/O: open() calls with user-controlled paths
    - Subprocess: subprocess.*, os.system, os.popen
    - Code execution: eval(), exec(), compile()
    - Unauthenticated routes: FastAPI/Flask routes without auth dependencies

    Returns dict mapping file_path -> {
        "risk_score": int (0-100),
        "findings": [{"type": str, "line": int, "description": str}]
    }
    """
    results = {}

    for root, _dirs, files in os.walk(directory):
        for filename in files:
            if not filename.endswith(".py"):
                continue
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
            except (OSError, IOError):
                continue

            findings = _analyze_file(source, file_path)
            if findings:
                risk_score = min(100, len(findings) * 20)
                results[file_path] = {
                    "risk_score": risk_score,
                    "findings": findings,
                }

    return results


def _analyze_file(source: str, file_path: str) -> list[dict]:
    """Analyze a single Python file for high-risk patterns."""
    findings = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            finding = _check_call_node(node)
            if finding:
                findings.append(finding)

    return findings


def _check_call_node(node: ast.Call) -> dict | None:
    """Check a Call AST node for dangerous patterns."""
    # Check for eval/exec/compile
    if isinstance(node.func, ast.Name):
        if node.func.id in ("eval", "exec", "compile"):
            return {
                "type": "code_execution",
                "line": node.lineno,
                "description": f"Dangerous function call: {node.func.id}()",
            }
        if node.func.id == "open":
            return {
                "type": "file_io",
                "line": node.lineno,
                "description": "File I/O operation: open()",
            }

    # Check for attribute calls like subprocess.run, os.system, etc.
    if isinstance(node.func, ast.Attribute):
        attr_name = node.func.attr

        # subprocess methods
        if attr_name in ("run", "call", "Popen", "check_output", "check_call"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                return {
                    "type": "subprocess",
                    "line": node.lineno,
                    "description": f"Subprocess execution: subprocess.{attr_name}()",
                }

        # os.system, os.popen
        if attr_name in ("system", "popen"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                return {
                    "type": "subprocess",
                    "line": node.lineno,
                    "description": f"OS command execution: os.{attr_name}()",
                }

        # Raw SQL patterns - only flag if receiver looks like a DB cursor/connection
        # or if the argument contains string interpolation (f-strings, % formatting)
        if attr_name == "execute":
            receiver_name = None
            if isinstance(node.func.value, ast.Name):
                receiver_name = node.func.value.id
            elif isinstance(node.func.value, ast.Attribute):
                receiver_name = node.func.value.attr

            # Check if receiver looks like a database object
            db_receivers = (
                "cursor", "conn", "connection", "db", "cur",
                "session", "engine", "raw_connection",
            )
            is_db_receiver = receiver_name and receiver_name.lower() in db_receivers

            # Check if args contain string interpolation (f-string or % format)
            has_interpolation = False
            if node.args:
                for arg in node.args:
                    if isinstance(arg, ast.JoinedStr):  # f-string
                        has_interpolation = True
                        break
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                        has_interpolation = True
                        break

            if is_db_receiver or has_interpolation:
                return {
                    "type": "raw_sql",
                    "line": node.lineno,
                    "description": "Potential raw SQL execution: .execute()",
                }

    return None


# HTTP-method decorator names used by Flask / FastAPI route definitions.
_HTTP_METHOD_DECORATORS = {"get", "post", "put", "patch", "delete", "head", "options"}


def extract_routes(directory: str) -> list[dict]:
    """
    Extract declared HTTP routes from Flask / FastAPI source via the AST.

    This is what kills the agent's "blind guessing" of commodity paths like
    /api/v1/customers. By mapping the real, source-derived routes (e.g. from
    @app.route("/login", methods=["POST"]) or @router.get("/items")), the DAST
    phase can attack only endpoints that actually exist.

    Returns a list of:
        {"path": "/login", "methods": ["GET", "POST"], "handler": "login", "file": "app.py"}
    """
    routes: list[dict] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    for root, dirs, files in os.walk(directory):
        if ".git" in dirs:
            dirs.remove(".git")
        for filename in files:
            if not filename.endswith(".py"):
                continue
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
            except (OSError, IOError):
                continue
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for decorator in node.decorator_list:
                    parsed = _parse_route_decorator(decorator)
                    if parsed is None:
                        continue
                    path, methods = parsed
                    key = (path, tuple(sorted(methods)))
                    if key in seen:
                        continue
                    seen.add(key)
                    try:
                        rel = os.path.relpath(file_path, directory)
                    except ValueError:
                        rel = file_path
                    routes.append({
                        "path": path,
                        "methods": methods,
                        "handler": node.name,
                        "file": rel,
                        "requires_auth": _function_uses_login_required(node),
                    })

    routes.sort(key=lambda r: r["path"])
    return routes


def _parse_route_decorator(decorator: ast.expr) -> tuple[str, list[str]] | None:
    """
    Parse a single decorator node into (path, methods) if it is a route.

    Handles Flask `@app.route("/x", methods=[...])`, the method-specific
    shorthands `@app.get/post/...`, and FastAPI `@router.get("/x")`. The
    receiver name (app, router, bp, blueprint, api, ...) is not constrained, so
    blueprint/sub-router decorators are matched too.
    """
    if not isinstance(decorator, ast.Call):
        return None
    func = decorator.func
    if not isinstance(func, ast.Attribute):
        return None

    method_name = func.attr.lower()
    if method_name != "route" and method_name not in _HTTP_METHOD_DECORATORS:
        return None

    # The path must be a literal string first positional argument.
    if not decorator.args:
        return None
    first = decorator.args[0]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return None
    path = first.value
    if not path.startswith("/"):
        return None

    if method_name == "route":
        methods = ["GET"]
        for kw in decorator.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                extracted = [
                    elt.value.upper()
                    for elt in kw.value.elts
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                ]
                if extracted:
                    methods = extracted
    else:
        methods = [method_name.upper()]

    return path, methods


def _function_uses_login_required(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Heuristic: does this route handler have a login_required-style decorator?"""
    for decorator in node.decorator_list:
        # Skip the route decorator itself.
        if isinstance(decorator, ast.Call):
            func = decorator.func
            name = (func.attr if isinstance(func, ast.Attribute) else
                    func.id if isinstance(func, ast.Name) else "")
        elif isinstance(decorator, ast.Name):
            name = decorator.id
        elif isinstance(decorator, ast.Attribute):
            name = decorator.attr
        else:
            name = ""
        name_lower = name.lower()
        # Common auth decorator names across Flask/FastAPI/Django.
        if any(k in name_lower for k in (
            "login_required", "require_auth", "authenticated",
            "auth_required", "jwt_required", "token_required",
            "requires_auth", "login_check",
        )):
            return True
    return False


def generate_vuln_hash(file_path: str, vuln_type: str, line_number: int) -> str:
    """Generate MD5(file_path + vulnerability_type + line_number) for deduplication."""
    raw = f"{file_path}{vuln_type}{line_number}"
    return hashlib.md5(raw.encode()).hexdigest()


def filter_high_risk_files(
    analysis_result: dict, max_token_budget: int = 50000
) -> list[dict]:
    """
    Select only high-risk code segments. Strip comments and docstrings.
    Estimate tokens (~4 chars per token) and stay within budget.
    Returns list of {"file_path": str, "content": str, "findings": list}
    """
    # Sort files by risk score descending
    sorted_files = sorted(
        analysis_result.items(),
        key=lambda x: x[1]["risk_score"],
        reverse=True,
    )

    result = []
    total_tokens = 0

    for file_path, data in sorted_files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except (OSError, IOError):
            continue

        stripped = _strip_comments_and_docstrings(source)
        estimated_tokens = len(stripped) // 4

        if total_tokens + estimated_tokens > max_token_budget:
            # Try to fit a truncated version
            remaining_budget = max_token_budget - total_tokens
            if remaining_budget >= 1:
                truncated = stripped[: remaining_budget * 4]
                result.append({
                    "file_path": file_path,
                    "content": truncated,
                    "findings": data["findings"],
                })
            break

        total_tokens += estimated_tokens
        result.append({
            "file_path": file_path,
            "content": stripped,
            "findings": data["findings"],
        })

    return result


def _strip_comments_and_docstrings(source: str) -> str:
    """Remove comments and docstrings from Python source code."""
    # Remove single-line comments
    lines = source.split("\n")
    stripped_lines = []
    for line in lines:
        # Remove inline comments but keep strings
        stripped = re.sub(r"#[^\n]*", "", line)
        stripped_lines.append(stripped)

    result = "\n".join(stripped_lines)

    # Remove docstrings (triple-quoted strings at statement level)
    result = re.sub(r'"""[\s\S]*?"""', '""', result)
    result = re.sub(r"'''[\s\S]*?'''", "''", result)

    return result
