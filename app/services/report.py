"""PDF vulnerability report generation (replaces the email alert system).

ReportService turns a job's attack graph + stored mitigations into a polished,
downloadable PDF: executive summary, severity, confirmed findings, exposed
services, and the full remediation code for each patched vulnerability.
"""
import json
import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
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

# Severity -> accent colour for the PDF header.
_SEVERITY_COLORS = {
    "extreme": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#d97706"),
    "low": colors.HexColor("#4b5563"),
}


def _truncate(value, limit: int = 400) -> str:
    value = str(value)
    return value if len(value) <= limit else value[:limit] + " ..."


def build_report_data(attack_graph: dict, severity: str) -> dict:
    """
    Extract a human-readable report structure from the raw attack graph.

    Produces: summary, severity, findings[], recon_ports[], remediations[]
    (vuln_node only here; full code is attached separately from the DB),
    plus a generated timestamp. Mirrors what the email builder used to do.
    """
    attack_graph = attack_graph or {}
    tool_results = attack_graph.get("tool_results", []) or []
    recon_ports: list[dict] = []
    remediations: list[dict] = []
    findings_by_key: dict[tuple, dict] = {}

    for entry in tool_results:
        tool = entry.get("tool")
        result = entry.get("result") or {}
        args = entry.get("arguments") or {}
        if not isinstance(result, dict):
            continue

        if tool == "run_nmap":
            for svc in result.get("results", []) or []:
                recon_ports.append({
                    "port": svc.get("port"),
                    "service": svc.get("service") or "unknown",
                    "version": svc.get("version") or "",
                })

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
            payload = args.get("json_body") or args.get("params") or args.get("payloads")
            key = (endpoint, kind)
            if key in findings_by_key:
                findings_by_key[key]["count"] += 1
            else:
                findings_by_key[key] = {
                    "title": f"{kind} \u2014 {method} {endpoint}",
                    "kind": kind,
                    "endpoint": endpoint,
                    "method": method,
                    "payload": _truncate(json.dumps(payload)) if payload else "",
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
        "findings": list(findings_by_key.values()),
        "recon_ports": recon_ports,
        "remediations": remediations,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


class ReportService:
    """Builds report data and renders a downloadable PDF for a job."""

    def __init__(self, report_dir: str | None = None):
        self.report_dir = report_dir or REPORT_DIR

    def report_path(self, job_id: str) -> str:
        """Filesystem path where this job's PDF lives (may not exist yet)."""
        return os.path.join(self.report_dir, f"{job_id}.pdf")

    async def _load_mitigations(self, db: AsyncSession, job_id: str) -> list[dict]:
        result = await db.execute(
            select(Mitigation).where(Mitigation.job_id == job_id)
        )
        return [
            {"vuln_node": m.vulnerability_node, "code": m.remediation_code or ""}
            for m in result.scalars().all()
        ]

    async def generate(
        self, db: AsyncSession, job_id: str, severity: str, attack_graph: dict
    ) -> str:
        """
        Build the report data, render the PDF to disk, and return its path.

        Always succeeds in producing a file (even with no findings), so the
        download is reliably available after a scan.
        """
        data = build_report_data(attack_graph, severity)
        mitigations = await self._load_mitigations(db, job_id)
        target = await self._job_target(db, job_id)

        os.makedirs(self.report_dir, exist_ok=True)
        path = self.report_path(job_id)
        # reportlab is synchronous; render directly (small documents, fast).
        self._render_pdf(path, job_id, target, data, mitigations)
        return path

    async def _job_target(self, db: AsyncSession, job_id: str) -> str:
        from app.models import Workspace

        result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
        job = result.scalar_one_or_none()
        if not job:
            return ""
        ws = await db.execute(
            select(Workspace).where(Workspace.id == job.workspace_id)
        )
        workspace = ws.scalar_one_or_none()
        return workspace.target_url if workspace else ""

    def _render_pdf(
        self,
        path: str,
        job_id: str,
        target: str,
        data: dict,
        mitigations: list[dict],
    ) -> None:
        styles = getSampleStyleSheet()
        accent = _SEVERITY_COLORS.get(data["severity"], colors.HexColor("#4b5563"))

        title_style = ParagraphStyle(
            "TWTitle", parent=styles["Title"], textColor=colors.HexColor("#0f172a"),
            fontSize=22, spaceAfter=4,
        )
        h2 = ParagraphStyle(
            "TWH2", parent=styles["Heading2"], textColor=accent, fontSize=14,
            spaceBefore=14, spaceAfter=6,
        )
        body = ParagraphStyle(
            "TWBody", parent=styles["BodyText"], fontSize=10, leading=14,
            alignment=TA_LEFT,
        )
        meta = ParagraphStyle(
            "TWMeta", parent=styles["BodyText"], fontSize=9,
            textColor=colors.HexColor("#64748b"),
        )
        code = ParagraphStyle(
            "TWCode", parent=styles["Code"], fontSize=8, leading=11,
            textColor=colors.HexColor("#0f172a"),
            backColor=colors.HexColor("#f1f5f9"), borderPadding=6,
        )
        finding_title = ParagraphStyle(
            "TWFinding", parent=body, fontSize=11, textColor=colors.HexColor("#111827"),
            spaceBefore=8, fontName="Helvetica-Bold",
        )

        doc = SimpleDocTemplate(
            path, pagesize=LETTER,
            topMargin=0.7 * inch, bottomMargin=0.7 * inch,
            leftMargin=0.8 * inch, rightMargin=0.8 * inch,
            title=f"ThreatWeaver Report {job_id[:8]}",
        )
        story = []

        # --- Header ---
        story.append(Paragraph("ThreatWeaver Security Report", title_style))
        sev = data["severity"].upper()
        story.append(Paragraph(
            f'<font color="{accent.hexval()}"><b>Overall severity: {sev}</b></font>',
            body,
        ))
        story.append(Paragraph(f"Target: {self._esc(target) or 'n/a'}", meta))
        story.append(Paragraph(f"Job ID: {job_id}", meta))
        story.append(Paragraph(f"Generated: {data['timestamp']}", meta))
        story.append(Spacer(1, 6))
        story.append(HRFlowable(width="100%", thickness=1, color=accent))

        # --- Executive summary ---
        if data["summary"]:
            story.append(Paragraph("Executive Summary", h2))
            story.append(Paragraph(self._esc(data["summary"]), body))

        # --- Findings ---
        story.append(Paragraph(
            f"Vulnerabilities ({len(data['findings'])})", h2
        ))
        if data["findings"]:
            for f in data["findings"]:
                suffix = f" (x{f['count']})" if f.get("count", 1) > 1 else ""
                story.append(Paragraph(self._esc(f["title"]) + suffix, finding_title))
                if f.get("payload"):
                    story.append(Paragraph(
                        f"<b>Payload:</b> <font face='Courier'>{self._esc(f['payload'])}</font>",
                        body,
                    ))
                if f.get("detail"):
                    story.append(Paragraph(self._esc(f["detail"]), body))
        else:
            story.append(Paragraph(
                "No exploitable anomalies were confirmed during this scan.", body
            ))

        # --- Exposed services ---
        if data["recon_ports"]:
            story.append(Paragraph("Exposed Services", h2))
            rows = [["Port", "Service", "Version"]]
            for p in data["recon_ports"]:
                rows.append([
                    str(p.get("port", "")),
                    self._esc(p.get("service", "")),
                    self._esc(p.get("version", "")),
                ])
            table = Table(rows, colWidths=[1.0 * inch, 2.2 * inch, 3.0 * inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#f8fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(table)

        # --- Remediations (full code from the mitigations table) ---
        story.append(Paragraph(
            f"Remediations ({len(mitigations)})", h2
        ))
        if mitigations:
            for m in mitigations:
                story.append(Paragraph(
                    f"Patch for: <b>{self._esc(m['vuln_node'])}</b>", body
                ))
                code_text = self._esc(m["code"] or "No remediation code available")
                # Preserve line breaks for the code block.
                code_text = code_text.replace("\n", "<br/>").replace(" ", "&nbsp;")
                story.append(Paragraph(code_text, code))
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("No remediations were generated.", body))

        # --- Footer note ---
        story.append(Spacer(1, 16))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#cbd5e1")))
        story.append(Paragraph(
            "Generated by ThreatWeaver Autonomous Security Engine.", meta
        ))

        doc.build(story)

    @staticmethod
    def _esc(text) -> str:
        """Escape text for reportlab's mini-HTML paragraph markup."""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
