"""Tests for K2-driven email recipient routing in NotifierService."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base
from app.models import RoutingConfig
from app.services.notifier import NotifierService

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


async def _seed_roles(db, roles: dict[str, str]):
    for role, email in roles.items():
        db.add(RoutingConfig(role=role, email_address=email))
    await db.commit()


@pytest.mark.asyncio
async def test_k2_chooses_recipients(db_session):
    """K2's chosen roles are resolved to the saved email addresses."""
    await _seed_roles(db_session, {
        "ciso": "ciso@corp.example",
        "head_of_security": "sec@corp.example",
        "head_engineer": "eng@corp.example",
    })

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=(
        '{"to_roles": ["ciso", "head_of_security"], "cc_roles": ["head_engineer"], '
        '"reasoning": "Extreme severity escalates to leadership."}'
    ))

    notifier = NotifierService(llm_client=mock_llm)
    to_list, cc_list = await notifier.get_recipients(db_session, "extreme")

    assert set(to_list) == {"ciso@corp.example", "sec@corp.example"}
    assert cc_list == ["eng@corp.example"]


@pytest.mark.asyncio
async def test_k2_hallucinated_roles_are_ignored(db_session):
    """Roles K2 invents that aren't saved are dropped."""
    await _seed_roles(db_session, {"head_engineer": "eng@corp.example"})

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=(
        '{"to_roles": ["head_engineer", "cto", "ceo"], "cc_roles": ["board"]}'
    ))

    notifier = NotifierService(llm_client=mock_llm)
    to_list, cc_list = await notifier.get_recipients(db_session, "low")

    assert to_list == ["eng@corp.example"]
    assert cc_list == []


@pytest.mark.asyncio
async def test_falls_back_to_matrix_on_api_error(db_session):
    """When K2 returns an API error, the static severity matrix is used."""
    await _seed_roles(db_session, {
        "head_of_security": "sec@corp.example",
        "head_engineer": "eng@corp.example",
    })

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value="Error: API returned status 403")

    notifier = NotifierService(llm_client=mock_llm)
    to_list, cc_list = await notifier.get_recipients(db_session, "high")

    # high -> to=[head_of_security], cc=[head_engineer]
    assert to_list == ["sec@corp.example"]
    assert cc_list == ["eng@corp.example"]


@pytest.mark.asyncio
async def test_falls_back_on_unparseable_response(db_session):
    """Garbage from K2 falls back to the static matrix."""
    await _seed_roles(db_session, {"head_engineer": "eng@corp.example"})

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value="I think maybe send it to someone?")

    notifier = NotifierService(llm_client=mock_llm)
    to_list, _ = await notifier.get_recipients(db_session, "low")

    assert to_list == ["eng@corp.example"]


@pytest.mark.asyncio
async def test_no_saved_roles_returns_empty(db_session):
    """With no routing config saved, no recipients are returned (no LLM call)."""
    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value="{}")

    notifier = NotifierService(llm_client=mock_llm)
    to_list, cc_list = await notifier.get_recipients(db_session, "extreme")

    assert to_list == []
    assert cc_list == []
    mock_llm.chat.assert_not_called()


@pytest.mark.asyncio
async def test_k2_reasoning_wrapped_response(db_session):
    """A <think>-wrapped routing decision is parsed correctly."""
    await _seed_roles(db_session, {"head_of_security": "sec@corp.example"})

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=(
        "<think>Medium severity, route to security lead.</think>\n"
        '{"to_roles": ["head_of_security"], "cc_roles": []}'
    ))

    notifier = NotifierService(llm_client=mock_llm)
    to_list, cc_list = await notifier.get_recipients(db_session, "medium")

    assert to_list == ["sec@corp.example"]
    assert cc_list == []



# --- send_alert outcome tests ---


@pytest.mark.asyncio
async def test_send_alert_skipped_without_api_key(db_session, monkeypatch):
    """No RESEND_API_KEY -> skipped with a clear reason, never crashes."""
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    await _seed_roles(db_session, {"head_engineer": "eng@corp.example"})

    notifier = NotifierService(llm_client=MagicMock())
    result = await notifier.send_alert(db_session, "job-1", "low", {})

    assert result["status"] == "skipped"
    assert "RESEND_API_KEY" in result["reason"]


@pytest.mark.asyncio
async def test_send_alert_skipped_without_recipients(db_session, monkeypatch):
    """API key present but no routing rules -> skipped with guidance."""
    monkeypatch.setenv("RESEND_API_KEY", "re_test")

    notifier = NotifierService(llm_client=MagicMock())
    # No roles seeded -> get_recipients returns empty.
    result = await notifier.send_alert(db_session, "job-1", "high", {})

    assert result["status"] == "skipped"
    assert "/config" in result["reason"]


@pytest.mark.asyncio
async def test_send_alert_sent(db_session, monkeypatch):
    """Happy path: API key + recipients + successful Resend send -> sent."""
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    await _seed_roles(db_session, {"head_engineer": "eng@corp.example"})

    # LLM unavailable -> falls back to the static matrix (low -> head_engineer).
    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value="Error: API returned status 403")

    notifier = NotifierService(llm_client=mock_llm)

    import app.services.notifier as notifier_mod

    with patch.object(
        notifier_mod.resend.Emails, "send", return_value={"id": "email_123"}
    ) as mock_send:
        result = await notifier.send_alert(db_session, "job-1", "low", {"k2_summary": "x"})

    assert result["status"] == "sent"
    assert result["to"] == ["eng@corp.example"]
    assert result["message_id"] == "email_123"
    mock_send.assert_called_once()


@pytest.mark.asyncio
async def test_send_alert_failed_on_resend_error(db_session, monkeypatch):
    """A Resend exception -> failed status with the error reason."""
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    await _seed_roles(db_session, {"head_engineer": "eng@corp.example"})

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value="Error: API returned status 403")
    notifier = NotifierService(llm_client=mock_llm)

    import app.services.notifier as notifier_mod

    with patch.object(
        notifier_mod.resend.Emails, "send", side_effect=RuntimeError("boom")
    ):
        result = await notifier.send_alert(db_session, "job-1", "low", {})

    assert result["status"] == "failed"
    assert "boom" in result["reason"]



# --- Email report content tests (regression for the "useless email") ---


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
             "result": {"patch": "...."}},
        ],
    }


def test_build_report_extracts_findings():
    """_build_report turns the raw attack graph into real findings, not dict keys."""
    svc = NotifierService(llm_client=MagicMock())
    report = svc._build_report(_sample_attack_graph(), "high")

    assert report["summary"].startswith("The /login endpoint crashed")
    assert len(report["findings"]) == 1
    assert "POST http://t/login" in report["findings"][0]["title"]
    assert {(p["port"], p["service"]) for p in report["recon_ports"]} == {
        (22, "ssh"), (80, "http")
    }
    assert report["remediations"] == [{"vuln_node": "login_json_vuln"}]
    assert report["timestamp"] != "N/A"


def test_render_email_contains_real_content():
    """The rendered HTML shows findings/summary/ports - never raw dict keys."""
    svc = NotifierService(llm_client=MagicMock())
    html = svc.render_email("high", _sample_attack_graph(), "job-12345678")

    assert "What we found" in html
    assert "Server crash on crafted input" in html
    assert "http://t/login" in html
    assert "ssh" in html
    assert "login_json_vuln" in html
    # The old bug dumped these raw top-level keys into the email body.
    assert "endpoint_attempts" not in html
    assert "exhausted_endpoints" not in html
    # Timestamp must be populated, not the old "N/A".
    assert "Generated: N/A" not in html


def test_render_email_no_findings_message():
    """With no anomalies, the email says so explicitly instead of being blank."""
    svc = NotifierService(llm_client=MagicMock())
    graph = {"k2_summary": "Nothing exploitable found.", "tool_results": []}
    html = svc.render_email("low", graph, "job-1")

    assert "No exploitable anomalies were confirmed" in html


def test_render_email_autoescapes_malicious_body():
    """Attacker-controlled response text is HTML-escaped in the email."""
    svc = NotifierService(llm_client=MagicMock())
    graph = {
        "tool_results": [
            {"tool": "send_http_request",
             "arguments": {"method": "GET", "endpoint": "http://t/x"},
             "result": {"is_server_error": True,
                        "telemetry": "<script>alert(1)</script>"}},
        ],
    }
    html = svc.render_email("medium", graph, "job-1")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
