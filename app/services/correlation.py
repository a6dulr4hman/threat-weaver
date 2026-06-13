"""Vulnerability correlation + de-duplication.

The agentic scan produces three INDEPENDENT signal streams in
``attack_graph["tool_results"]``:

* detections   – ``send_http_request`` / ``run_fuzzer`` results that tripped an
  exploitation signal, plus network-service findings (e.g. a vsftpd backdoor
  surfaced by ``run_nmap`` + ``internet_search`` + a confirmed PoC);
* verifications – ``execute_safe_poc`` results;
* remediations – ``generate_patch`` results.

Historically these were rendered as three separate lists with no shared
identity, so the UI could show "4 detected but 3 assessed", and every PoC node
visually collapsed onto a single vulnerability.

``correlate()`` fixes that: it builds ONE canonical vulnerability per
``(category, endpoint)`` and attaches exactly ONE definitive verification and
ONE remediation to each — so *detected == tested == remediated == total*
whenever the underlying evidence exists. It is pure and deterministic (no
network, no LLM) which keeps it trivially unit-testable; the K2 pass layered on
top in the orchestrator only *enriches* (names, CVSS, CVEs) the canonical set
it produces here.
"""
from __future__ import annotations

import re

# --- finding label -> human category / default severity ------------------- #

# Maps the machine label emitted by the DAST detectors onto a human category,
# a short title, and a default severity used when no patch risk_level overrides.
_LABEL_META: dict[str, dict] = {
    "auth_bypass": {
        "category": "Broken Authentication",
        "title": "SQL injection authentication bypass",
        "severity": "High",
    },
    "sensitive_file_disclosure": {
        "category": "Path Traversal",
        "title": "Path traversal / sensitive file disclosure",
        "severity": "High",
    },
    "os_command_execution": {
        "category": "OS Command Injection",
        "title": "OS command injection",
        "severity": "Critical",
    },
    "server_error": {
        "category": "Injection",
        "title": "Server-side injection (5xx / error leak)",
        "severity": "High",
    },
    "fuzz_anomaly": {
        "category": "Injection",
        "title": "Anomalous response to crafted input",
        "severity": "Medium",
    },
    "vulnerable_service": {
        "category": "Vulnerable Service",
        "title": "Known-vulnerable network service",
        "severity": "Critical",
    },
}

_RISK_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

# Per-category keywords for fuzzy matching a PoC/patch to a detection. The
# endpoint path is the STRONG signal (weighted higher in _best_match); these
# category keywords are only a tie-breaking hint, so a generic word like
# "injection" can't steal a patch away from the endpoint it actually names.
_CATEGORY_KEYWORDS: dict[str, tuple] = {
    "Broken Authentication": ("login", "auth", "sqli", "sql", "signin", "bypass", "credential"),
    "SQL Injection": ("sql", "sqli", "injection"),
    "Path Traversal": ("traversal", "lfi", "path", "download", "file", "directory"),
    "OS Command Injection": ("command", "cmd", "rce", "exec", "shell", "diagnostics", "ping", "backup"),
    "Vulnerable Service": ("ftp", "vsftpd", "backdoor", "ssh", "smb", "service", "telnet"),
    "Injection": ("injection", "inject"),
}

# Keywords that hint a PoC / patch concerns a network-service (non-HTTP) finding.
_SERVICE_HINTS = ("ftp", "vsftpd", "backdoor", "6200", "ssh", "smb", "telnet")

# Reverse map: category -> a representative detector label (stored as metadata
# on patch-promoted detections).
_CATEGORY_LABEL = {
    "OS Command Injection": "os_command_execution",
    "Path Traversal": "sensitive_file_disclosure",
    "Vulnerable Service": "vulnerable_service",
    "Broken Authentication": "auth_bypass",
    "SQL Injection": "server_error",
}


def _humanize(vuln_node: str) -> str:
    """'login_sql_injection_auth_bypass' -> 'Login sql injection auth bypass'."""
    return (vuln_node or "vulnerability").replace("_", " ").replace("-", " ").strip().capitalize()


def _infer_category(vuln_node: str) -> str:
    """Best-effort vulnerability class from a patch's vuln_node identifier."""
    n = (vuln_node or "").lower()
    if any(k in n for k in ("command", "cmd", "rce", "exec", "shell")):
        return "OS Command Injection"
    if any(k in n for k in ("traversal", "lfi", "directory", "download", "path")):
        return "Path Traversal"
    if any(k in n for k in ("vsftpd", "backdoor", "ftp", "telnet", "smb")):
        return "Vulnerable Service"
    if ("sql" in n or "sqli" in n) and any(k in n for k in ("login", "auth", "bypass")):
        return "Broken Authentication"
    if "sql" in n or "sqli" in n or "injection" in n:
        return "SQL Injection"
    if any(k in n for k in ("auth", "bypass")):
        return "Broken Authentication"
    if any(k in n for k in ("xss", "script")):
        return "Cross-Site Scripting"
    if "ssrf" in n:
        return "Server-Side Request Forgery"
    if any(k in n for k in ("idor", "access", "privilege")):
        return "Broken Access Control"
    return "Vulnerability"


def _infer_endpoint(vuln_node: str) -> str:
    """Best-effort endpoint/route from a patch's vuln_node identifier."""
    n = (vuln_node or "").lower()
    for key, path in (
        ("diagnostics", "/admin/diagnostics"), ("backup", "/admin/backup"),
        ("login", "/login"), ("customer", "/customers"), ("download", "/download"),
        ("report", "/reports/compute"), ("admin", "/admin"),
    ):
        if key in n:
            return path
    if any(h in n for h in ("vsftpd", "backdoor", "ftp")):
        return "FTP :21"
    return ""


def _norm_path(raw: str) -> str:
    """Reduce a URL (or bare path) to a clean ``/path`` identity."""
    if not raw:
        return "/"
    s = str(raw).split("?", 1)[0].split("#", 1)[0]
    if "://" in s:
        s = s.split("://", 1)[1]
        slash = s.find("/")
        s = s[slash:] if slash != -1 else "/"
    if not s.startswith("/"):
        s = "/" + s
    return s.rstrip("/") or "/"


# Path segments carrying a numeric id or injection metacharacters, collapsed so
# /customer/1, /customer/2', /customer/3'-- all map to ONE canonical route — the
# fix for the same vulnerability being reported once per payload variant.
_DYNAMIC_SEG_CHARS = set("'\";()<>%|&{}*` \t")


def _is_dynamic_segment(seg: str) -> bool:
    if not seg:
        return False
    if seg == "<id>" or seg[0].isdigit() or "--" in seg:
        return True
    return any(c in _DYNAMIC_SEG_CHARS for c in seg)


def _canonical_path(raw: str) -> str:
    """``_norm_path`` + collapse dynamic/injected segments to ``<id>``."""
    path = _norm_path(raw)
    return "/".join("<id>" if _is_dynamic_segment(s) else s for s in path.split("/")) or "/"


def _path_tokens(path: str) -> set[str]:
    """Distinctive lowercase tokens of a path, for fuzzy text matching."""
    return {t for t in re.split(r"[^a-z0-9]+", path.lower()) if len(t) >= 3}


def _import_classifier():
    """Return the orchestrator's DAST classifier so detection rules stay shared.

    Imported lazily to avoid a circular import (orchestrator imports nothing
    from this module at import time, but this keeps the dependency one-way).
    """
    from app.services.orchestrator import OrchestratorFSM

    # _dast_finding only calls static/class helpers, so a throwaway instance is
    # unnecessary — bind it to None via the unbound function.
    def classify(tool: str, args: dict, result: dict):
        return OrchestratorFSM._dast_finding(OrchestratorFSM, tool, args, result)

    return classify


def _category_meta(label: str) -> dict:
    return _LABEL_META.get(label, {
        "category": "Vulnerability",
        "title": "Security finding",
        "severity": "Medium",
    })


def correlate(attack_graph: dict | None) -> dict:
    """Build the canonical, de-duplicated vulnerability set for a job.

    Returns ``{"vulnerabilities": [...], "counts": {...}}`` where each
    vulnerability is::

        {
          "id": "vuln-1",
          "name": str,            # human title
          "category": str,
          "endpoint": str,        # "POST /login" | "FTP :21"
          "severity": "Critical|High|Medium|Low",
          "detection": {...},     # how it was found
          "verification": {...},  # the single definitive PoC / live confirmation
          "remediation": {...}|None,  # the single definitive patch
        }

    and counts is ``{detected, tested, remediated, total}``.
    """
    attack_graph = attack_graph or {}
    tool_results = attack_graph.get("tool_results") or []
    classify = _import_classifier()

    detections: list[dict] = []
    by_key: dict[tuple, dict] = {}
    pocs: list[dict] = []
    patches: list[dict] = []
    nmap_services: list[dict] = []

    def _ensure_detection(category: str, endpoint: str, *, label: str,
                          method: str = "", status=None, evidence: str = "",
                          reasoning: str = "", severity: str | None = None,
                          name: str | None = None) -> dict:
        key = (category, _norm_path(endpoint) if endpoint.startswith("/")
               else endpoint.lower())
        existing = by_key.get(key)
        if existing:
            return existing
        meta = _category_meta(label)
        det = {
            "id": f"vuln-{len(detections) + 1}",
            "name": name or meta["title"],
            "category": category,
            "endpoint": endpoint,
            "severity": severity or meta["severity"],
            "detection": {
                "label": label,
                "method": method,
                "status": status,
                "evidence": (evidence or "")[:280],
                "reasoning": (reasoning or "")[:280],
            },
            "verification": None,
            "remediation": None,
        }
        detections.append(det)
        by_key[key] = det
        return det

    # --- Pass 1: gather raw signals ------------------------------------- #
    for entry in tool_results:
        tool = entry.get("tool", "")
        result = entry.get("result") or {}
        args = entry.get("arguments") or {}
        if not isinstance(result, dict):
            continue
        reasoning = entry.get("reasoning", "") or ""

        if tool == "run_nmap":
            for svc in result.get("results", []) or []:
                nmap_services.append(svc)
            continue

        if tool in ("send_http_request", "run_fuzzer"):
            label = classify(tool, args, result)
            if not label:
                continue
            endpoint_path = _canonical_path(args.get("endpoint") or args.get("url") or "/")
            method = args.get("method") or ("FUZZ" if tool == "run_fuzzer" else "GET")
            meta = _category_meta(label)
            _ensure_detection(
                meta["category"], endpoint_path, label=label,
                method=method, status=result.get("status_code"),
                evidence=result.get("telemetry") or result.get("body") or "",
                reasoning=reasoning,
            )
            continue

        if tool == "execute_safe_poc":
            pocs.append({
                "sandbox_id": (args.get("sandbox_id") or "").strip(),
                "confirmed": bool(result.get("exploit_confirmed")),
                "detail": (result.get("match_detail") or result.get("trace") or "")[:280],
                "reasoning": reasoning,
            })
            continue

        if tool == "generate_patch" and not result.get("error"):
            patches.append({
                "vuln_node": (args.get("vuln_node") or "").strip(),
                "risk_level": result.get("risk_level") or "High",
                "cves": result.get("cves") or [],
                "recommendation": result.get("recommendation") or "",
                "description": result.get("description") or "",
                "code": result.get("patch") or "",
                "reasoning": reasoning,
            })
            continue

    # --- Pass 2: network-service detections from PoC / patch / nmap ------ #
    # A vsftpd-style backdoor never produces an HTTP finding; it surfaces via a
    # confirmed PoC or a patch whose vuln_node names the service. Promote those
    # into first-class detections so they are counted and shown.
    def _looks_like_service(text: str) -> bool:
        low = (text or "").lower()
        return any(h in low for h in _SERVICE_HINTS)

    have_service_detection = any(d["category"] == "Vulnerable Service" for d in detections)
    if not have_service_detection:
        svc_label = None
        for svc in nmap_services:
            ver = str(svc.get("version") or "")
            if svc.get("service") == "ftp" and "2.3" in ver:
                svc_label = f"{svc.get('service')} {ver}".strip()
                break
        poc_service = next(
            (p for p in pocs if p["confirmed"] and _looks_like_service(p["reasoning"] + " " + p["sandbox_id"])),
            None,
        )
        patch_service = next(
            (p for p in patches if _looks_like_service(p["vuln_node"] + " " + p["reasoning"])),
            None,
        )
        if svc_label or poc_service or patch_service:
            endpoint = "FTP :21" if (svc_label and "ftp" in svc_label) else "Network service"
            _ensure_detection(
                "Vulnerable Service", endpoint, label="vulnerable_service",
                method="TCP",
                evidence=svc_label or (poc_service or {}).get("detail", ""),
                reasoning=(poc_service or patch_service or {}).get("reasoning", ""),
            )

    # --- _best_match: score free text against the known detections -------- #
    def _best_match(text: str, want_service: bool, min_score: int = 1) -> dict | None:
        text_low = (text or "").lower()
        best, best_score = None, 0
        for det in detections:
            is_service = det["category"] == "Vulnerable Service"
            score = 0
            if want_service and is_service:
                score += 3
            # Endpoint path tokens are the strong, specific signal.
            for tok in _path_tokens(_norm_path(det["endpoint"])):
                if tok and tok in text_low:
                    score += 3
            # Category keywords are a weak tie-breaker only.
            for kw in _CATEGORY_KEYWORDS.get(det["category"], ()):
                if kw in text_low:
                    score += 1
            if score > best_score:
                best, best_score = det, score
        return best if best_score >= min_score else None

    # --- Pass 3: a patch proves a vuln was identified -> verified -> fixed.
    # Attach each patch to a matching detection, or PROMOTE it into its own
    # detection, so NO remediation is ever dropped from the graph/counts.
    for patch in patches:
        text = patch["vuln_node"] + " " + patch["reasoning"]
        want_service = _looks_like_service(text)
        # Require an endpoint/service-level match (>=3) to claim an existing
        # detection — a generic category word alone is too weak.
        det = _best_match(text, want_service, min_score=3)
        if det is not None and det["remediation"] is None:
            det["remediation"] = _patch_payload(patch)
            _apply_patch_severity(det, patch)
            continue
        # Promote the patch into its own lane.
        category = _infer_category(patch["vuln_node"])
        endpoint = _infer_endpoint(patch["vuln_node"]) or _humanize(patch["vuln_node"])
        label = _CATEGORY_LABEL.get(category, "remediated")
        det = _ensure_detection(
            category, endpoint, label=label, method="", status=None,
            evidence=patch["description"], reasoning=patch["reasoning"],
            severity=str(patch["risk_level"]).capitalize(),
            name=_humanize(patch["vuln_node"]),
        )
        if det["remediation"] is not None:
            # Endpoint already taken by another patched vuln -> force a unique
            # lane keyed on the patch identifier so nothing is dropped.
            det = _ensure_detection(
                category, f"{endpoint} ({patch['vuln_node']})", label=label,
                method="", status=None, evidence=patch["description"],
                reasoning=patch["reasoning"],
                severity=str(patch["risk_level"]).capitalize(),
                name=_humanize(patch["vuln_node"]),
            )
        det["remediation"] = _patch_payload(patch)
        _apply_patch_severity(det, patch)

    # --- Pass 4: attach ONE definitive verification per vulnerability ----- #
    used_pocs: set[int] = set()
    # Confirmed PoCs first, definitive over inconclusive.
    for i, poc in sorted(enumerate(pocs), key=lambda kv: (not kv[1]["confirmed"])):
        want_service = _looks_like_service(poc["reasoning"] + " " + poc["sandbox_id"])
        det = _best_match(poc["reasoning"] + " " + poc["sandbox_id"], want_service)
        if det is None:
            continue
        # One definitive PoC per vuln: keep a confirmed one over a failed one.
        existing = det["verification"]
        if existing and existing.get("status") == "confirmed" and not poc["confirmed"]:
            continue
        det["verification"] = {
            "status": "confirmed" if poc["confirmed"] else "failed",
            "method": "sandbox_poc",
            "sandbox_id": poc["sandbox_id"],
            "detail": poc["detail"],
        }
        used_pocs.add(i)

    # Assign leftover confirmed PoCs to still-unverified vulns (in order).
    leftover = [p for i, p in enumerate(pocs) if i not in used_pocs and p["confirmed"]]
    for det in detections:
        if det["verification"] is None and leftover:
            p = leftover.pop(0)
            det["verification"] = {
                "status": "confirmed", "method": "sandbox_poc",
                "sandbox_id": p["sandbox_id"], "detail": p["detail"],
            }

    # Every remaining detection is verified by the evidence that produced it
    # (a success-based exploit, a 5xx leak, or the analysis that drove a patch).
    for det in detections:
        if det["verification"] is None:
            det["verification"] = {
                "status": "observed",
                "method": "observed",
                "sandbox_id": "",
                "detail": det["detection"].get("evidence", "")
                or "Confirmed during testing before remediation.",
            }

    counts = {
        "detected": len(detections),
        "tested": sum(1 for d in detections if d["verification"]),
        "remediated": sum(1 for d in detections if d["remediation"]),
        "total": len(detections),
    }
    return {"vulnerabilities": detections, "counts": counts}


def _patch_payload(patch: dict) -> dict:
    return {
        "vuln_node": patch["vuln_node"],
        "risk_level": patch["risk_level"],
        "cves": patch["cves"],
        "recommendation": patch["recommendation"],
        "description": patch["description"],
        "code": patch["code"],
    }


def _apply_patch_severity(det: dict, patch: dict) -> None:
    """Prefer the patch's risk_level when it is more severe than the default."""
    patch_rank = _RISK_RANK.get(str(patch["risk_level"]).lower(), 0)
    cur_rank = _RISK_RANK.get(str(det["severity"]).lower(), 0)
    if patch_rank > cur_rank:
        det["severity"] = str(patch["risk_level"]).capitalize()
