"""Tests for the PDF report system (replaces the email/notifier tests)."""
import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base
from app.models import AnalysisJob, Mitigation, Workspace
from app.services.report import ReportService, build_report_data

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestAsyncSession = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest_asyncio.fixture
async def db_session():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with TestAsyncSession() as session:
        yield session
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def _sample_attack_graph():
    return {
        "endpoint_attempts": {"http://t/login": 0},
        "exhausted_endpoints": [],
        "k2_summary": "The /login endpoint crashed on malformed JSON input.",
        "overall_severity": "high",
        "tool_results": [
            {"tool": "run_nmap", "arguments": {}, "result": {"results": [
                {"port": 22, "service": "ssh", "version": "9.6p1"},
                {"port": 80, "service": "http", "version": ""},
            ]}},
            {"tool": "send_http_request",
             "arguments": {"method": "POST", "endpoint": "http://t/login",
                           "json_body": {"username": "admin", "password": ""}},
             "result": {"status_code": 0, "is_server_error": True,
                        "server_crash_suspected": True,
                        "telemetry": "socket ReadError: connection dropped."}},
            {"tool": "generate_patch", "arguments": {"vuln_node": "login_json_vuln"},
             "result": {"patch": "..."}},
        ],
    }


# --- build_report_data extraction ---


def test_build_report_extracts_findings():
    """build_report_data turns the raw attack graph into real findings."""
    report = build_report_data(_sample_attack_graph(), "high")

    assert report["summary"].startswith("The /login endpoint crashed")
    assert len(report["findings"]) == 1
    assert "POST http://t/login" in report["findings"][0]["title"]
    assert {(p["port"], p["service"]) for p in report["recon_ports"]} == {
        ("22", "ssh"), ("80", "http")
    }
    assert report["remediations"] == [{"vuln_node": "login_json_vuln"}]
    assert report["timestamp"] != "N/A"


def test_build_report_no_findings():
    """A clean scan produces an empty findings list (not an error)."""
    report = build_report_data({"k2_summary": "nothing", "tool_results": []}, "low")
    assert report["findings"] == []
    assert report["severity"] == "low"


def test_build_report_only_anomalies_become_findings():
    """Benign 200 responses are NOT reported as findings."""
    graph = {
        "tool_results": [
            {"tool": "send_http_request",
             "arguments": {"method": "GET", "endpoint": "http://t/ok"},
             "result": {"status_code": 200, "is_server_error": False}},
        ],
    }
    report = build_report_data(graph, "low")
    assert report["findings"] == []


# --- PDF generation ---


@pytest.mark.asyncio
async def test_generate_pdf_creates_valid_file(db_session, tmp_path):
    """ReportService.generate writes a real PDF with the full patch code."""
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    db_session.add(Workspace(
        id=workspace_id, target_url="http://t", verification_nonce="n",
        verification_status=True,
    ))
    await db_session.commit()
    db_session.add(AnalysisJob(
        id=job_id, workspace_id=workspace_id, status="complete",
        attack_graph_data=_sample_attack_graph(),
    ))
    db_session.add(Mitigation(
        id=str(uuid.uuid4()), job_id=job_id, vulnerability_node="login_json_vuln",
        remediation_code="if not request.is_json:\n    return {'error': 'bad'}, 400",
    ))
    await db_session.commit()

    svc = ReportService(report_dir=str(tmp_path))
    path = await svc.generate(db_session, job_id, "high", _sample_attack_graph())

    assert os.path.exists(path)
    with open(path, "rb") as f:
        assert f.read(5) == b"%PDF-"
    assert os.path.getsize(path) > 0


@pytest.mark.asyncio
async def test_generate_pdf_with_no_findings(db_session, tmp_path):
    """A report still generates cleanly when there are no findings."""
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    db_session.add(Workspace(
        id=workspace_id, target_url="http://t", verification_nonce="n",
        verification_status=True,
    ))
    await db_session.commit()
    db_session.add(AnalysisJob(
        id=job_id, workspace_id=workspace_id, status="complete",
        attack_graph_data={"tool_results": []},
    ))
    await db_session.commit()

    svc = ReportService(report_dir=str(tmp_path))
    path = await svc.generate(db_session, job_id, "low", {"tool_results": []})
    assert os.path.exists(path)


def test_report_path_uses_dir():
    """report_path is derived from the configured report dir + job id."""
    svc = ReportService(report_dir="/some/dir")
    assert svc.report_path("abc123") == "/some/dir/abc123.pdf"


def test_build_report_escapes_nothing_but_is_safe():
    """Malicious telemetry is carried through; the PDF renderer escapes it."""
    graph = {
        "tool_results": [
            {"tool": "send_http_request",
             "arguments": {"method": "GET", "endpoint": "http://t/x"},
             "result": {"is_server_error": True,
                        "telemetry": "<script>alert(1)</script>"}},
        ],
    }
    report = build_report_data(graph, "medium")
    # The finding is captured; escaping happens at render time via _esc.
    assert len(report["findings"]) == 1
    assert ReportService._esc("<script>") == "&lt;script&gt;"
