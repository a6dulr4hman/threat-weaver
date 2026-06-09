"""PDF vulnerability report generation.

ReportService turns a job's attack graph + stored mitigations into a polished,
downloadable PDF: executive summary, severity, confirmed findings, exposed
services, and the full remediation code for each patched vulnerability.
"""
from __future__ import annotations

import asyncio
import os
import re
import textwrap
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AnalysisJob, Mitigation

# Where generated PDF reports are written.
REPORT_DIR = os.getenv("REPORT_DIR", "/tmp/threatweaver/reports")

# Severity -> accent colour (plain hex string; avoids .hexval() method).
_SEVERITY_HEX = {
    "extreme": "#dc2626",
    "high":    "#ea580c",
    "medium":  "#d97706",
    "low":     "#4b5563",
}

# Page width minus margins = usable text width.
_TEXT_WIDTH = LETTER[0] - 1.6 * inch  # 0.8 in each side


def _truncate(value, limit: int = 400) -> str:
    value = str(value)
    return value if len(value) <= limit else value[:limit] + " ..."


# Characters that are valid in XML 1.0 (the subset reportlab uses).
# Anything outside this set will cause a black replacement box.
_VALID_XML_CHARS = re.compile(
    r"[^\x09\x0A\x0D\x20-\x7E\xA0-\uD7FF\uE000-\uFFFD]"
)

# Typography replacements: swap smart/fancy Unicode chars that aren't
# in Helvetica's standard encoding for their plain ASCII equivalents.
_UNICODE_REPLACEMENTS = str.maketrans({
    "\u2014": "--",    # em dash
    "\u2013": "-",     # en dash
    "\u2018": "'",     # left single quote
    "\u2019": "'",     # right single quote
    "\u201c": '"',     # left double quote
    "\u201d": '"',     # right double quote
    "\u2026": "...",   # ellipsis
    "\u00a0": " ",     # non-breaking space
    "\u2011": "-",     # non-breaking hyphen
})


def _safe_text(text) -> str:
    """
    Sanitise a string so it is safe to embed inside a reportlab Paragraph.

    Steps:
      1. Coerce to str, replacing lone surrogates.
      2. Swap fancy Unicode typography to plain ASCII equivalents
         (em-dash, curly quotes, etc. cause black replacement boxes when
         the font doesn't include those glyphs).
      3. Strip any remaining control characters that are invalid in XML 1.0.
      4. XML-escape &, <, > so the Paragraph mini-parser doesn't mistake
         them for markup tags. We intentionally do NOT escape " because
         we never put these values inside XML attribute values.
    """
    s = str(text or "").encode("utf-8", errors="replace").decode("utf-8")
    s = s.translate(_UNICODE_REPLACEMENTS)
    s = _VALID_XML_CHARS.sub("", s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _esc(text) -> str:
    """Alias kept for backward-compat; _safe_text is preferred for PDF."""
    return _safe_text(text)


def build_report_data(attack_graph: dict, severity: str) -> dict:
    """
    Extract a human-readable report structure from the raw attack graph.

    Returns: summary, severity, findings[], recon_ports[], remediations[],
    patched_nodes[], and a UTC timestamp.
    """
    attack_graph = attack_graph or {}
    tool_results = attack_graph.get("tool_results", []) or []
    recon_ports: list[dict] = []
    remediations: list[dict] = []
    findings_by_key: dict[tuple, dict] = {}

    # Recon services are always derived from nmap regardless of mode.
    for entry in tool_results:
        if entry.get("tool") == "run_nmap":
            result = entry.get("result") or {}
            if isinstance(result, dict):
                for svc in result.get("results", []) or []:
                    recon_ports.append({
                        "port": str(svc.get("port", "")),
                        "service": svc.get("service") or "unknown",
                        "version": svc.get("version") or "",
                    })

    # Prefer the canonical, de-duplicated vulnerability set so the PDF's
    # findings/remediations match the UI (detected == tested == remediated).
    canonical = attack_graph.get("vulnerabilities") or []
    if canonical:
        findings = []
        for v in canonical:
            det = v.get("detection") or {}
            ver = v.get("verification") or {}
            verdict = {
                "confirmed": "Confirmed in sandbox PoC",
                "observed": "Confirmed from live exploitation",
            }.get((ver.get("status") or ""), "Observed")
            findings.append({
                "title": f"{v.get('name') or v.get('category') or 'Finding'}",
                "kind": v.get("category", ""),
                "endpoint": v.get("endpoint", ""),
                "method": det.get("method", ""),
                "payload": "",
                "detail": _truncate(det.get("evidence") or ver.get("detail") or verdict),
                "count": 1,
            })
            if v.get("remediation"):
                remediations.append({"vuln_node": v["remediation"].get("vuln_node", v.get("name", "unknown"))})
        return {
            "summary": attack_graph.get("k2_summary") or "",
            "severity": severity,
            "assessment": attack_graph.get("final_assessment"),
            "findings": findings,
            "recon_ports": recon_ports,
            "remediations": remediations,
            "patched_nodes": attack_graph.get("patched_nodes", []),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        }

    for entry in tool_results:
        tool = entry.get("tool")
        result = entry.get("result") or {}
        args = entry.get("arguments") or {}
        if not isinstance(result, dict):
            continue

        if tool == "run_nmap":
            # recon_ports were already gathered in the pre-loop above.
            continue

        elif tool in ("send_http_request", "run_fuzzer"):
            is_anomaly = (
                result.get("is_server_error")
                or result.get("stack_trace_detected")
                or result.get("server_crash_suspected")
                or result.get("anomalies_found", 0)
            )
            if not is_anomaly:
                continue
            endpoint = args.get("endpoint") or args.get("url") or "(unknown endpoint)"
            method = args.get("method") or ("FUZZ" if tool == "run_fuzzer" else "GET")
            if result.get("stack_trace_detected"):
                kind = "Stack trace / source leak"
            elif result.get("server_crash_suspected"):
                kind = "Server crash on crafted input"
            elif result.get("is_server_error"):
                kind = "Server-side error (HTTP 5xx)"
            else:
                kind = "Anomalous response"
            payload = (
                args.get("json_body") or args.get("params") or args.get("payloads")
            )
            # Store payload as a clean human-readable string. Do NOT call
            # json.dumps here — that produces {"key": "value"} which would
            # then get double-escaped later. Use repr-style or just pretty-print.
            if payload and isinstance(payload, dict):
                payload_str = ", ".join(
                    f"{k}: {v}" for k, v in list(payload.items())[:4]
                )
            elif payload:
                payload_str = _truncate(str(payload))
            else:
                payload_str = ""
            key = (endpoint, kind)
            if key in findings_by_key:
                findings_by_key[key]["count"] += 1
            else:
                findings_by_key[key] = {
                    "title": f"{kind} — {method} {endpoint}",
                    "kind": kind,
                    "endpoint": endpoint,
                    "method": method,
                    "payload": _truncate(payload_str),
                    "detail": _truncate(result.get("telemetry") or ""),
                    "count": 1,
                }

        elif tool == "execute_safe_poc":
            if result.get("exploit_confirmed"):
                key = ("poc", entry.get("iteration"))
                findings_by_key[key] = {
                    "title": "Confirmed exploit (verified in sandbox PoC)",
                    "kind": "Confirmed exploit",
                    "endpoint": args.get("sandbox_id", ""),
                    "method": "",
                    "payload": "",
                    "detail": _truncate(result.get("trace") or ""),
                    "count": 1,
                }

        elif tool == "generate_patch":
            remediations.append({"vuln_node": args.get("vuln_node", "unknown")})

    return {
        "summary": attack_graph.get("k2_summary") or "",
        "severity": severity,
        "assessment": attack_graph.get("final_assessment"),
        "findings": list(findings_by_key.values()),
        "recon_ports": recon_ports,
        "remediations": remediations,
        "patched_nodes": attack_graph.get("patched_nodes", []),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def _make_styles() -> dict:
    """
    Build all ParagraphStyle objects fresh each call.

    We use unique names with a random suffix so repeated calls never trigger
    reportlab's 'style already defined' error (which crashes the second PDF
    generated in the same process).
    """
    import uuid
    suffix = uuid.uuid4().hex[:8]
    base = getSampleStyleSheet()

    def st(name, **kw) -> ParagraphStyle:
        parent = kw.pop("parent", base["BodyText"])
        return ParagraphStyle(f"{name}_{suffix}", parent=parent, **kw)

    return {
        "title": st("title", parent=base["Title"],
                    textColor=colors.HexColor("#0f172a"),
                    fontSize=24, spaceAfter=2, alignment=TA_LEFT),
        "sub":   st("sub", fontSize=9, textColor=colors.HexColor("#64748b"),
                    spaceAfter=2),
        "h2":    st("h2", parent=base["Heading2"],
                    fontSize=13, spaceBefore=14, spaceAfter=4),
        "body":  st("body", fontSize=10, leading=15, alignment=TA_LEFT),
        "bold":  st("bold", fontSize=11, fontName="Helvetica-Bold",
                    leading=15, spaceBefore=6),
        "label": st("label", fontSize=9, textColor=colors.HexColor("#6b7280")),
        "value": st("value", fontSize=9, textColor=colors.HexColor("#111827"),
                    fontName="Helvetica-Bold"),
    }


class ReportService:
    """Builds report data and renders a downloadable PDF for a job."""

    def __init__(self, report_dir: str | None = None):
        self.report_dir = report_dir or REPORT_DIR

    def report_path(self, job_id: str) -> str:
        return os.path.join(self.report_dir, f"{job_id}.pdf")

    async def _load_mitigations(self, db: AsyncSession, job_id: str) -> list[dict]:
        result = await db.execute(
            select(Mitigation).where(Mitigation.job_id == job_id)
        )
        rows = []
        for m in result.scalars().all():
            meta = m.finding_metadata or {}
            rows.append({
                "vuln_node":      m.vulnerability_node,
                "code":           m.remediation_code or "",
                "description":    meta.get("description", ""),
                "risk_level":     meta.get("risk_level", ""),
                "cves":           meta.get("cves", []),
                "recommendation": meta.get("recommendation", ""),
            })
        return rows

    async def generate(
        self, db: AsyncSession, job_id: str, severity: str, attack_graph: dict
    ) -> str:
        """Build report data, render the PDF to disk, return its path."""
        data = build_report_data(attack_graph, severity)
        mitigations = await self._load_mitigations(db, job_id)
        target = await self._job_target(db, job_id)

        os.makedirs(self.report_dir, exist_ok=True)
        path = self.report_path(job_id)
        # Run the synchronous reportlab renderer off the event loop so it
        # doesn't block the async worker on larger documents.
        await asyncio.to_thread(
            self._render_pdf, path, job_id, target, data, mitigations
        )
        return path

    async def _job_target(self, db: AsyncSession, job_id: str) -> str:
        from app.models import Workspace

        result = await db.execute(
            select(AnalysisJob).where(AnalysisJob.id == job_id)
        )
        job = result.scalar_one_or_none()
        if not job:
            return ""
        ws = await db.execute(
            select(Workspace).where(Workspace.id == job.workspace_id)
        )
        workspace = ws.scalar_one_or_none()
        return workspace.target_url if workspace else ""

    # ------------------------------------------------------------------ #
    # PDF rendering                                                        #
    # ------------------------------------------------------------------ #

    def _render_pdf(
        self,
        path: str,
        job_id: str,
        target: str,
        data: dict,
        mitigations: list[dict],
    ) -> None:
        sty = _make_styles()
        severity = data.get("severity", "low")
        accent_hex = _SEVERITY_HEX.get(severity, "#4b5563")
        accent = colors.HexColor(accent_hex)

        # Override h2 colour per severity.
        sty["h2"].textColor = accent

        doc = SimpleDocTemplate(
            path,
            pagesize=LETTER,
            topMargin=0.65 * inch,
            bottomMargin=0.65 * inch,
            leftMargin=0.8 * inch,
            rightMargin=0.8 * inch,
            title=f"ThreatWeaver Report – {job_id[:8]}",
            author="ThreatWeaver Autonomous Security Engine",
        )
        story: list = []

        # ── Header banner ──────────────────────────────────────────── #
        story.append(Paragraph("ThreatWeaver Security Report", sty["title"]))
        story.append(Paragraph(
            f"Overall severity: <b>{severity.upper()}</b>",
            ParagraphStyle(
                f"sev_{severity}_{id(story)}",
                parent=sty["body"],
                textColor=accent,
                fontSize=11,
                spaceAfter=3,
            ),
        ))
        story.append(Paragraph(f"Target: {_esc(target) or 'n/a'}", sty["sub"]))
        story.append(Paragraph(f"Job ID: {job_id}", sty["sub"]))
        story.append(Paragraph(f"Generated: {data['timestamp']}", sty["sub"]))
        story.append(Spacer(1, 4))
        story.append(HRFlowable(
            width="100%", thickness=1.5, color=accent, spaceAfter=6
        ))

        # ── Executive Summary ──────────────────────────────────────── #
        if data.get("summary"):
            story.append(Paragraph("Executive Summary", sty["h2"]))
            story.append(Paragraph(_esc(data["summary"]), sty["body"]))

        # ── K2-Think-v2 Security Assessment (final verdict) ─────────── #
        assessment = data.get("assessment")
        if isinstance(assessment, dict):
            story.append(Paragraph("K2-Think-v2 Security Assessment", sty["h2"]))
            total = assessment.get("total_vulnerabilities")
            risk = str(assessment.get("overall_risk", "n/a"))
            story.append(Paragraph(
                f"Vulnerabilities identified: <b>{_esc(total)}</b> &nbsp;&middot;&nbsp; "
                f"Overall risk: <b>{_esc(risk)}</b>",
                sty["body"],
            ))
            if assessment.get("executive_summary"):
                story.append(Spacer(1, 3))
                story.append(Paragraph(_esc(assessment["executive_summary"]), sty["body"]))

            vulns = [v for v in (assessment.get("vulnerabilities") or []) if isinstance(v, dict)]
            if vulns:
                rows = [[
                    Paragraph("<b>#</b>", sty["label"]),
                    Paragraph("<b>Vulnerability</b>", sty["label"]),
                    Paragraph("<b>Severity</b>", sty["label"]),
                    Paragraph("<b>CVSS</b>", sty["label"]),
                    Paragraph("<b>Confidence</b>", sty["label"]),
                ]]
                for i, v in enumerate(vulns, 1):
                    title = v.get("name") or v.get("category") or "Finding"
                    endpoint = v.get("endpoint")
                    label_txt = _safe_text(title)
                    if endpoint:
                        label_txt += f"<br/><font size=7 color='#64748b'>{_safe_text(endpoint)}</font>"
                    rows.append([
                        Paragraph(str(i), sty["body"]),
                        Paragraph(label_txt, sty["body"]),
                        Paragraph(_safe_text(v.get("severity", "")), sty["body"]),
                        Paragraph(_safe_text(v.get("cvss", "")), sty["body"]),
                        Paragraph(_safe_text(v.get("confidence", "")), sty["body"]),
                    ])
                t = Table(
                    rows,
                    colWidths=[0.3 * inch, _TEXT_WIDTH - 2.55 * inch,
                               0.85 * inch, 0.55 * inch, 0.85 * inch],
                    hAlign="LEFT",
                )
                t.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("FONTSIZE",      (0, 0), (-1, -1), 8),
                    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                    ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
                    ("TOPPADDING",    (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ]))
                story.append(Spacer(1, 4))
                story.append(t)

        # ── Findings ──────────────────────────────────────────────── #
        findings = data.get("findings", [])
        story.append(Paragraph(f"Vulnerabilities ({len(findings)})", sty["h2"]))
        if findings:
            for f in findings:
                count = f.get("count", 1)
                suffix = f" (x{count})" if count > 1 else ""
                story.append(Paragraph(_esc(f["title"]) + suffix, sty["bold"]))
                # 2-column detail table (Label | Value) for structure.
                # Payload and Detail use Preformatted so JSON/exception text
                # is rendered literally without any XML interpretation.
                rows = []
                if f.get("endpoint"):
                    rows.append([
                        Paragraph("<b>Endpoint</b>", sty["label"]),
                        Paragraph(_safe_text(f["endpoint"]), sty["body"]),
                    ])
                if f.get("payload"):
                    payload_pre = Preformatted(
                        _truncate(str(f["payload"]), 200),
                        ParagraphStyle(
                            f"pl_{id(f)}",
                            fontName="Courier", fontSize=7.5, leading=10,
                        ),
                    )
                    rows.append([Paragraph("<b>Payload</b>", sty["label"]), payload_pre])
                if f.get("detail"):
                    # Telemetry strings contain raw exception text with \x
                    # escapes and punctuation that would break XML parsing.
                    detail_pre = Preformatted(
                        _truncate(str(f["detail"]), 300),
                        ParagraphStyle(
                            f"dl_{id(f)}",
                            fontName="Courier", fontSize=7.5, leading=10,
                        ),
                    )
                    rows.append([Paragraph("<b>Detail</b>", sty["label"]), detail_pre])
                if rows:
                    t = Table(
                        rows,
                        colWidths=[1.1 * inch, _TEXT_WIDTH - 1.1 * inch],
                        hAlign="LEFT",
                    )
                    t.setStyle(TableStyle([
                        ("FONTSIZE",    (0, 0), (-1, -1), 8),
                        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING",  (0, 0), (-1, -1), 2),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                        ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("LINEBELOW",   (0, -1), (-1, -1), 0.3,
                         colors.HexColor("#e2e8f0")),
                    ]))
                    story.append(Spacer(1, 2))
                    story.append(t)
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph(
                "No exploitable anomalies were confirmed during this scan.",
                sty["body"],
            ))

        # ── Exposed Services ──────────────────────────────────────── #
        ports = data.get("recon_ports", [])
        if ports:
            story.append(Paragraph("Exposed Services", sty["h2"]))
            rows = [["Port", "Service", "Version"]]
            for p in ports:
                rows.append([
                    p.get("port", ""),
                    _esc(p.get("service", "")),
                    _esc(p.get("version", "")),
                ])
            t = Table(
                rows,
                colWidths=[0.8 * inch, 1.6 * inch, _TEXT_WIDTH - 2.4 * inch],
                hAlign="LEFT",
            )
            t.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 9),
                ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ]))
            story.append(t)

        # ── Remediations ──────────────────────────────────────────── #
        story.append(Paragraph(f"Remediations ({len(mitigations)})", sty["h2"]))
        if mitigations:
            # Risk badge colours
            risk_colors = {
                "critical": ("#7f1d1d", "#fee2e2"),
                "high":     ("#7c2d12", "#fed7aa"),
                "medium":   ("#713f12", "#fef9c3"),
                "low":      ("#14532d", "#dcfce7"),
            }
            for idx, m in enumerate(mitigations):
                if idx > 0:
                    story.append(HRFlowable(
                        width="100%", thickness=0.4,
                        color=colors.HexColor("#e2e8f0"), spaceAfter=4,
                    ))

                vuln = _esc(m["vuln_node"])
                risk = (m.get("risk_level") or "High").strip().lower()
                risk_label = risk.capitalize()
                fg, bg = risk_colors.get(risk, ("#1e3a5f", "#dbeafe"))

                # ── Finding title + risk badge ── #
                badge_style = ParagraphStyle(
                    f"badge_{idx}_{id(story)}",
                    parent=sty["bold"],
                    fontSize=12,
                )
                story.append(Paragraph(
                    f"{vuln} &nbsp;"
                    f'<font color="{fg}" backColor="{bg}"'
                    f'> {risk_label} </font>',
                    badge_style,
                ))
                story.append(Spacer(1, 4))

                # ── Description ── #
                if m.get("description"):
                    detail_rows = [
                        [Paragraph("<b>Description</b>", sty["label"]),
                         Paragraph(_esc(m["description"]), sty["body"])],
                    ]
                    # ── CVEs ── #
                    if m.get("cves"):
                        cve_text = "  ".join(m["cves"])
                        detail_rows.append([
                            Paragraph("<b>CVEs</b>", sty["label"]),
                            Paragraph(
                                f'<font color="#dc2626"><b>{_esc(cve_text)}</b></font>',
                                sty["body"],
                            ),
                        ])
                    # ── Recommendation ── #
                    if m.get("recommendation"):
                        detail_rows.append([
                            Paragraph("<b>Fix strategy</b>", sty["label"]),
                            Paragraph(_esc(m["recommendation"]), sty["body"]),
                        ])

                    detail_t = Table(
                        detail_rows,
                        colWidths=[1.2 * inch, _TEXT_WIDTH - 1.2 * inch],
                        hAlign="LEFT",
                    )
                    detail_t.setStyle(TableStyle([
                        ("FONTSIZE",      (0, 0), (-1, -1), 9),
                        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING",    (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                    ]))
                    story.append(detail_t)
                    story.append(Spacer(1, 6))

                # ── Patched code ── #
                raw_code = m.get("code") or "# No remediation code available"
                wrapped_lines = []
                for line in raw_code.splitlines():
                    if len(line) <= 90:
                        wrapped_lines.append(line)
                    else:
                        wrapped_lines.extend(
                            textwrap.wrap(line, width=90,
                                          subsequent_indent="    ",
                                          break_long_words=True)
                        )
                code_text = "\n".join(wrapped_lines)
                story.append(Paragraph("<b>Patched code</b>", sty["label"]))
                story.append(Spacer(1, 2))
                story.append(Preformatted(
                    code_text,
                    ParagraphStyle(
                        f"code_{idx}_{id(story)}",
                        fontName="Courier",
                        fontSize=7.5,
                        leading=11,
                        backColor=colors.HexColor("#f1f5f9"),
                        borderPadding=(4, 6, 4, 6),
                        leftIndent=0,
                        spaceAfter=8,
                    ),
                ))
        else:
            story.append(Paragraph("No remediations were generated.", sty["body"]))

        # ── Footer ────────────────────────────────────────────────── #
        story.append(Spacer(1, 16))
        story.append(HRFlowable(
            width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")
        ))
        story.append(Paragraph(
            "Generated by ThreatWeaver Autonomous Security Engine.",
            ParagraphStyle(
                f"footer_{id(story)}",
                parent=sty["sub"],
                alignment=TA_CENTER,
            ),
        ))

        doc.build(story)

    @staticmethod
    def _esc(text) -> str:
        """Kept for backward-compat; module-level _esc is preferred."""
        return _esc(text)
