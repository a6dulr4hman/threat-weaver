"""Tests for the AST parser service."""
import os
import tempfile
import zipfile

from app.services.ast_parser import (
    analyze_codebase,
    extract_zip,
    filter_high_risk_files,
    generate_vuln_hash,
)


def test_extract_zip():
    """Create a temp zip with Python files, extract it, verify files exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "test.zip")
        dest_dir = os.path.join(tmpdir, "extracted")

        # Create a zip file with Python content
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("main.py", "print('hello')\n")
            zf.writestr("utils/helper.py", "def add(a, b): return a + b\n")

        result = extract_zip(zip_path, dest_dir)

        assert result == dest_dir
        assert os.path.exists(os.path.join(dest_dir, "main.py"))
        assert os.path.exists(os.path.join(dest_dir, "utils", "helper.py"))


def test_extract_zip_prevents_zip_slip():
    """Verify zip slip attack is prevented."""
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "evil.zip")
        dest_dir = os.path.join(tmpdir, "extracted")

        # Create a zip with a path traversal entry
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../../etc/passwd", "evil content")

        try:
            extract_zip(zip_path, dest_dir)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Zip slip" in str(e)


def test_analyze_codebase():
    """Verify analyze_codebase finds dangerous patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a Python file with known vulnerabilities
        vuln_code = """\
import subprocess
import os

user_input = input("Enter command: ")
result = eval(user_input)
subprocess.run(user_input, shell=True)
os.system("rm -rf /")
"""
        file_path = os.path.join(tmpdir, "vuln.py")
        with open(file_path, "w") as f:
            f.write(vuln_code)

        result = analyze_codebase(tmpdir)

        assert file_path in result
        findings = result[file_path]["findings"]
        assert len(findings) >= 3

        finding_types = [f["type"] for f in findings]
        assert "code_execution" in finding_types
        assert "subprocess" in finding_types


def test_analyze_codebase_empty_dir():
    """Verify analyze_codebase handles empty directories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        result = analyze_codebase(tmpdir)
        assert result == {}


def test_generate_vuln_hash():
    """Verify consistent MD5 for same inputs, different for different inputs."""
    hash1 = generate_vuln_hash("file.py", "sql_injection", 42)
    hash2 = generate_vuln_hash("file.py", "sql_injection", 42)
    hash3 = generate_vuln_hash("other.py", "sql_injection", 42)
    hash4 = generate_vuln_hash("file.py", "xss", 42)

    # Same inputs produce same hash
    assert hash1 == hash2
    # Different inputs produce different hashes
    assert hash1 != hash3
    assert hash1 != hash4
    # Hash is a 32-char hex string (MD5)
    assert len(hash1) == 32
    assert all(c in "0123456789abcdef" for c in hash1)


def test_filter_high_risk_files():
    """Verify filter respects token budget and strips comments."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a file with known content
        code = """\
# This is a comment
import os

def dangerous():
    \"\"\"This is a docstring that should be stripped.\"\"\"
    eval(input())
"""
        file_path = os.path.join(tmpdir, "risky.py")
        with open(file_path, "w") as f:
            f.write(code)

        analysis = analyze_codebase(tmpdir)
        result = filter_high_risk_files(analysis, max_token_budget=50000)

        assert len(result) > 0
        assert result[0]["file_path"] == file_path
        assert result[0]["findings"] is not None
        # Comments should be stripped
        assert "# This is a comment" not in result[0]["content"]


def test_filter_high_risk_files_budget_limit():
    """Verify filter respects small token budgets."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a large file
        code = "x = eval('test')\n" * 1000
        file_path = os.path.join(tmpdir, "big.py")
        with open(file_path, "w") as f:
            f.write(code)

        analysis = analyze_codebase(tmpdir)
        # Very small budget: 100 tokens = ~400 chars
        result = filter_high_risk_files(analysis, max_token_budget=100)

        assert len(result) > 0
        # Content should be truncated
        assert len(result[0]["content"]) <= 400
