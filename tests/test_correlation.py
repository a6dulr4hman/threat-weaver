"""Tests for vulnerability correlation, assessment reconciliation, and token
accounting — the fix for "4 detected but only 3 shown / all PoCs on one vuln"."""
from unittest.mock import MagicMock

import pytest

from app.services.correlation import correlate
from app.services.orchestrator import OrchestratorFSM


def _four_vuln_graph() -> dict:
    """A realistic graph with FOUR distinct vulnerabilities where the PoCs were
    all (mis)attributed to the login issue and the patches arrive out of order —
    exactly the situation the user reported."""
    return {
        "tool_results": [
            # Recon: vsftpd 2.3.4 (the FTP backdoor service)
            {"tool": "run_nmap", "arguments": {"target": "t"}, "result": {
                "results": [{"port": 21, "service": "ftp", "version": "2.3.4"}]}},
            # 1) SQLi auth bypass on /login (success-based, 200 + dashboard)
            {"tool": "send_http_request",
             "arguments": {"method": "POST", "endpoint": "http://t/login",
                           "form_data": {"username": "admin'-- ", "password": "x"}},
             "result": {"status_code": 200, "body": "Welcome to your dashboard, admin. Sign out"},
             "reasoning": "SQLi auth bypass"},
            # 2) Path traversal on /download (file disclosure)
            {"tool": "send_http_request",
             "arguments": {"method": "GET", "endpoint": "http://t/download?file=../../etc/passwd"},
             "result": {"status_code": 200, "body": "root:x:0:0:root:/root:/bin/bash"},
             "reasoning": "path traversal"},
            # 3) OS command injection on /admin/diagnostics
            {"tool": "send_http_request",
             "arguments": {"method": "GET", "endpoint": "http://t/admin/diagnostics?host=localhost;id"},
             "result": {"status_code": 200, "body": "uid=0(root) gid=0(root) groups=0(root)"},
             "reasoning": "command injection"},
            # 3 PoCs — all attributed to the login issue (the reported bug)
            {"tool": "execute_safe_poc",
             "arguments": {"sandbox_id": "login_poc_1"},
             "result": {"exploit_confirmed": True, "match_detail": "auth bypass confirmed"},
             "reasoning": "login sqli verification"},
            {"tool": "execute_safe_poc",
             "arguments": {"sandbox_id": "login_poc_2"},
             "result": {"exploit_confirmed": True, "match_detail": "login bypass again"},
             "reasoning": "login bypass retry"},
            {"tool": "execute_safe_poc",
             "arguments": {"sandbox_id": "vsftpd_backdoor_poc"},
             "result": {"exploit_confirmed": True, "match_detail": "shell on 6200"},
             "reasoning": "vsftpd 2.3.4 backdoor on ftp port 6200"},
            # 4 patches, arriving in a different order than detection
            {"tool": "generate_patch",
             "arguments": {"vuln_node": "download_path_traversal"},
             "result": {"vuln_node": "download_path_traversal", "risk_level": "High",
                        "cves": [], "recommendation": "sanitize path", "patch": "code1"}},
            {"tool": "generate_patch",
             "arguments": {"vuln_node": "login_sql_injection"},
             "result": {"vuln_node": "login_sql_injection", "risk_level": "High",
                        "cves": [], "recommendation": "parametrize", "patch": "code2"}},
            {"tool": "generate_patch",
             "arguments": {"vuln_node": "vsftpd_2_3_4_backdoor"},
             "result": {"vuln_node": "vsftpd_2_3_4_backdoor", "risk_level": "Critical",
                        "cves": ["CVE-2011-2523"], "recommendation": "upgrade vsftpd", "patch": "code3"}},
            {"tool": "generate_patch",
             "arguments": {"vuln_node": "admin_diagnostics_command_injection"},
             "result": {"vuln_node": "admin_diagnostics_command_injection", "risk_level": "Critical",
                        "cves": [], "recommendation": "avoid shell=True", "patch": "code4"}},
        ]
    }


def test_correlate_detected_equals_tested_equals_remediated():
    """Four distinct vulnerabilities -> 4 detected = 4 tested = 4 remediated."""
    out = correlate(_four_vuln_graph())
    counts = out["counts"]
    assert counts["detected"] == 4
    assert counts["tested"] == 4
    assert counts["remediated"] == 4
    assert counts["total"] == 4


def test_correlate_each_vuln_is_distinct_with_its_own_poc_and_patch():
    """No vulnerability shares an id; every one gets a verification + remediation."""
    vulns = correlate(_four_vuln_graph())["vulnerabilities"]
    assert len(vulns) == 4
    assert len({v["id"] for v in vulns}) == 4               # distinct ids
    assert all(v["verification"] is not None for v in vulns)  # all tested
    assert all(v["remediation"] is not None for v in vulns)   # all remediated
    # Endpoints are distinct -> PoCs no longer collapse onto one issue.
    assert len({v["endpoint"] for v in vulns}) == 4


def test_correlate_categories_match_observed_triggers():
    cats = {v["category"] for v in correlate(_four_vuln_graph())["vulnerabilities"]}
    assert "Broken Authentication" in cats     # /login SQLi auth bypass
    assert "Path Traversal" in cats            # /download
    assert "OS Command Injection" in cats      # /admin/diagnostics
    assert "Vulnerable Service" in cats        # vsftpd backdoor


def test_correlate_patch_severity_overrides_default():
    """The vsftpd backdoor patch is Critical -> the vuln is rated Critical."""
    vulns = correlate(_four_vuln_graph())["vulnerabilities"]
    ftp = next(v for v in vulns if v["category"] == "Vulnerable Service")
    assert ftp["severity"] == "Critical"
    assert "CVE-2011-2523" in (ftp["remediation"]["cves"])


def test_correlate_empty_graph():
    out = correlate({})
    assert out["counts"] == {"detected": 0, "tested": 0, "remediated": 0, "total": 0}
    assert out["vulnerabilities"] == []


def _five_patch_graph() -> dict:
    """The reported case: 5 patches were generated but only some surfaced as
    HTTP findings — the extra patches must still each become a vulnerability."""
    return {
        "tool_results": [
            {"tool": "run_nmap", "arguments": {}, "result": {
                "results": [{"port": 21, "service": "ftp", "version": "2.3.4"}]}},
            {"tool": "execute_safe_poc", "arguments": {"sandbox_id": "vsftpd_backdoor"},
             "result": {"exploit_confirmed": True, "match_detail": "shell"},
             "reasoning": "vsftpd 2.3.4 backdoor"},
            {"tool": "send_http_request",
             "arguments": {"method": "POST", "endpoint": "http://t/login",
                           "form_data": {"username": "admin'-- ", "password": "x"}},
             "result": {"status_code": 200, "body": "Welcome dashboard, sign out"},
             "reasoning": "SQLi auth bypass"},
            # 5 patches — only login + vsftpd have a matching detection above.
            {"tool": "generate_patch", "arguments": {"vuln_node": "admin_diagnostics_command_injection"},
             "result": {"vuln_node": "admin_diagnostics_command_injection", "risk_level": "Critical",
                        "cves": [], "recommendation": "no shell=True", "patch": "c1", "description": "cmd inj"}},
            {"tool": "generate_patch", "arguments": {"vuln_node": "download_path_traversal"},
             "result": {"vuln_node": "download_path_traversal", "risk_level": "High",
                        "cves": [], "recommendation": "sanitize path", "patch": "c2", "description": "traversal"}},
            {"tool": "generate_patch", "arguments": {"vuln_node": "vsftpd_2.3.4_backdoor"},
             "result": {"vuln_node": "vsftpd_2.3.4_backdoor", "risk_level": "Critical",
                        "cves": ["CVE-2011-2523"], "recommendation": "upgrade", "patch": "c3", "description": "backdoor"}},
            {"tool": "generate_patch", "arguments": {"vuln_node": "customer_sql_injection"},
             "result": {"vuln_node": "customer_sql_injection", "risk_level": "High",
                        "cves": [], "recommendation": "parametrize", "patch": "c4", "description": "sqli"}},
            {"tool": "generate_patch", "arguments": {"vuln_node": "login_sql_injection_auth_bypass"},
             "result": {"vuln_node": "login_sql_injection_auth_bypass", "risk_level": "Critical",
                        "cves": [], "recommendation": "prepared stmts", "patch": "c5", "description": "auth bypass"}},
        ]
    }


def test_every_patch_becomes_a_vulnerability_lane():
    """5 patches -> 5 remediated vulnerabilities, none dropped."""
    out = correlate(_five_patch_graph())
    vulns = out["vulnerabilities"]
    # The 5 patches must all be represented and remediated.
    assert out["counts"]["remediated"] == 5
    # Each vuln is verified (PoC-confirmed or observed) -> tested == detected.
    assert out["counts"]["tested"] == out["counts"]["detected"]
    assert out["counts"]["detected"] >= 5
    # Every distinct patch vuln_node shows up exactly once.
    nodes = {(v.get("remediation") or {}).get("vuln_node") for v in vulns if v.get("remediation")}
    assert {"admin_diagnostics_command_injection", "download_path_traversal",
            "vsftpd_2.3.4_backdoor", "customer_sql_injection",
            "login_sql_injection_auth_bypass"} <= nodes
    # Promoted patches get a sensible category.
    cats = {v["category"] for v in vulns}
    assert "OS Command Injection" in cats and "Path Traversal" in cats


# --- Assessment reconciliation + counting -------------------------------- #

@pytest.mark.asyncio
async def test_final_assessment_count_matches_detected_offline():
    """With no K2 key, the deterministic verdict still reports all 4 vulns."""
    fsm = OrchestratorFSM(db=MagicMock(), job_id="t")
    fsm.attack_graph = _four_vuln_graph()
    assessment = await fsm._generate_final_assessment()
    assert assessment["total_vulnerabilities"] == 4
    assert len(assessment["vulnerabilities"]) == 4
    # Every entry carries a severity + numeric CVSS.
    assert all(v.get("severity") for v in assessment["vulnerabilities"])
    assert all(isinstance(v.get("cvss"), (int, float)) for v in assessment["vulnerabilities"])


def test_reconcile_pins_count_to_canonical_even_if_k2_drifts():
    """K2 returning the wrong number of entries cannot change the count."""
    fsm = OrchestratorFSM(db=MagicMock(), job_id="t")
    canonical = correlate(_four_vuln_graph())["vulnerabilities"]
    # K2 returns only 2 entries (dropped some) + 1 hallucinated extra.
    k2_vulns = [
        {"id": canonical[0]["id"], "name": "Better name", "severity": "Critical", "cvss": 9.8},
        {"id": "ghost", "name": "Invented", "severity": "Low"},
    ]
    out = fsm._reconcile_assessment(canonical, k2_vulns)
    assert len(out) == len(canonical) == 4
    # K2 enrichment applied to the matched entry.
    matched = next(v for v in out if v["id"] == canonical[0]["id"])
    assert matched["name"] == "Better name"
    assert matched["cvss"] == 9.8


# --- Token accounting ---------------------------------------------------- #

def test_accumulate_usage_sums_across_calls():
    fsm = OrchestratorFSM(db=MagicMock(), job_id="t")
    fsm.attack_graph = {}
    fsm._accumulate_usage({"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140})
    fsm._accumulate_usage({"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
    tu = fsm.attack_graph["token_usage"]
    assert tu["prompt_tokens"] == 110
    assert tu["completion_tokens"] == 45
    assert tu["total_tokens"] == 155
    assert tu["llm_calls"] == 2


def test_accumulate_usage_ignores_non_dict_and_empty():
    """Mocked clients (MagicMock last_usage) and empty usage are ignored."""
    fsm = OrchestratorFSM(db=MagicMock(), job_id="t")
    fsm.attack_graph = {}
    fsm._accumulate_usage(None)
    fsm._accumulate_usage(MagicMock())
    fsm._accumulate_usage({})
    assert "token_usage" not in fsm.attack_graph


def test_accumulate_usage_derives_total_when_missing():
    fsm = OrchestratorFSM(db=MagicMock(), job_id="t")
    fsm.attack_graph = {}
    fsm._accumulate_usage({"prompt_tokens": 30, "completion_tokens": 20})
    assert fsm.attack_graph["token_usage"]["total_tokens"] == 50
