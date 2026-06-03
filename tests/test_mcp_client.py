"""Tests for the MCP client service."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.mcp_client import MCPClient


async def test_run_nmap_handles_missing_binary():
    """Mock subprocess to raise FileNotFoundError, verify graceful error handling."""
    client = MCPClient()

    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
        result = await client.run_nmap("example.com", "1-1000")

    assert result["error"] == "nmap is not installed"
    assert result["results"] == []


async def test_run_nmap_handles_timeout():
    """Verify graceful handling of nmap timeout."""
    client = MCPClient()

    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
            result = await client.run_nmap("example.com", "1-65535")

    assert "timed out" in result["error"]
    assert result["results"] == []


async def test_run_fuzzer_basic():
    """Mock httpx responses, verify it returns execution matrix with correct structure."""
    client = MCPClient()

    payloads = [
        {"param": "' OR 1=1 --"},
        {"param": "<script>alert(1)</script>"},
    ]

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"OK"

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.run_fuzzer(
            "http://target.local/api/test", payloads, "query"
        )

    assert "results" in result
    assert "total_requests" in result
    assert "anomalies_found" in result
    assert result["total_requests"] == 2
    assert len(result["results"]) == 2

    for r in result["results"]:
        assert "payload" in r
        assert "status_code" in r
        assert "response_length" in r
        assert "response_time_ms" in r
        assert "anomaly_detected" in r


async def test_execute_safe_poc_timeout():
    """Mock subprocess timeout, verify returns error info."""
    client = MCPClient()

    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
            result = await client.execute_safe_poc(
                "sandbox-123",
                "import time; time.sleep(100)",
                {"marker": "exploit"},
            )

    assert result["exploit_confirmed"] is False
    assert "timed out" in result["error"]
    assert result["memory_profile"]["sandbox_id"] == "sandbox-123"


async def test_execute_safe_poc_missing_interpreter():
    """Verify graceful handling when Python is not found."""
    client = MCPClient()

    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
        result = await client.execute_safe_poc(
            "sandbox-456",
            "print('test')",
            {},
        )

    assert result["exploit_confirmed"] is False
    assert "not found" in result["error"]


async def test_query_hackclub_error(monkeypatch):
    """Mock httpx to return 500, verify graceful fallback."""
    monkeypatch.setenv("HACKCLUB_API_KEY", "sk-hc-v1-test")
    client = MCPClient()

    mock_response = MagicMock()
    mock_response.status_code = 500

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.query_hackclub("openssl", "1.0.1")

    assert result["references"] == []
    assert result["mitigations"] == []


async def test_query_hackclub_no_api_key(monkeypatch):
    """Without an API key, query_hackclub short-circuits with a helpful error."""
    monkeypatch.delenv("HACKCLUB_API_KEY", raising=False)
    client = MCPClient()

    result = await client.query_hackclub("nginx", "1.14.0")

    assert result["references"] == []
    assert "HACKCLUB_API_KEY" in result["error"]


async def test_query_hackclub_parses_web_results(monkeypatch):
    """A 200 response is parsed from data['web']['results'] into references."""
    monkeypatch.setenv("HACKCLUB_API_KEY", "sk-hc-v1-test")
    client = MCPClient()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"{}"
    mock_response.json = MagicMock(return_value={
        "web": {
            "results": [
                {
                    "title": "CVE-2014-0160 Heartbleed",
                    "url": "https://example.com/cve",
                    "description": "OpenSSL TLS heartbeat read overrun.",
                },
            ]
        }
    })

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.query_hackclub("openssl", "1.0.1")

    assert result["error"] is None
    assert len(result["references"]) == 1
    assert result["references"][0]["title"] == "CVE-2014-0160 Heartbleed"
    assert result["vulnerable_components"] == ["openssl@1.0.1"]


async def test_query_hackclub_network_error(monkeypatch):
    """Verify graceful handling of network errors."""
    monkeypatch.setenv("HACKCLUB_API_KEY", "sk-hc-v1-test")
    client = MCPClient()

    import httpx

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Network down"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.query_hackclub("nginx", "1.14.0")

    assert result["references"] == []
    assert result["vulnerable_components"] == []



async def test_run_fuzzer_transport_error_not_anomaly():
    """
    Connection failures (timeouts, refused) must NOT be flagged as anomalies.

    Regression test: previously a transport error counted as a confirmed
    anomaly, which led the agent to hallucinate a vulnerability against an
    unreachable endpoint.
    """
    import httpx

    client = MCPClient()
    payloads = [{"param": "page", "value": "php://filter/..."}]

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectTimeout("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.run_fuzzer(
            "https://unreachable.local/", payloads, "query"
        )

    assert result["anomalies_found"] == 0
    row = result["results"][0]
    assert row["anomaly_detected"] is False
    assert row["status_code"] == 0
    assert row["transport_error"] == "ConnectTimeout"


async def test_run_fuzzer_flags_500_as_anomaly():
    """A genuine 5xx response is still flagged as an anomaly."""
    client = MCPClient()
    payloads = [{"param": "id", "value": "abc"}]

    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.content = b"Internal Server Error"

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.run_fuzzer("http://target.local/", payloads, "query")

    assert result["anomalies_found"] == 1
    assert result["results"][0]["anomaly_detected"] is True
    assert result["results"][0]["status_code"] == 500



async def test_send_http_request_returns_body():
    """send_http_request returns the raw response body and status."""
    client = MCPClient()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "<html>ok</html>"
    mock_response.headers = {"content-type": "text/html"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)
        mock_client.cookies = {}
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.send_http_request(
            "GET", "http://target.local/", params={"q": "x"}
        )

    assert result["status_code"] == 200
    assert result["body"] == "<html>ok</html>"
    assert result["is_server_error"] is False
    assert result["stack_trace_detected"] is False
    assert result["transport_error"] is None


async def test_send_http_request_detects_stack_trace():
    """A 500 with a Python traceback is flagged for the agent to pivot on."""
    client = MCPClient()

    trace = (
        "Traceback (most recent call last):\n"
        '  File "app.py", line 42, in transfer\n'
        "    sqlite3.OperationalError: no such column: abc\n"
    )
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = trace
    mock_response.headers = {}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)
        mock_client.cookies = {}
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.send_http_request(
            "POST", "http://target.local/transfer", json_body={"amount": -100}
        )

    assert result["status_code"] == 500
    assert result["is_server_error"] is True
    assert result["stack_trace_detected"] is True


async def test_send_http_request_truncates_large_body():
    """Large bodies are truncated to protect the token budget."""
    client = MCPClient()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "A" * 10000
    mock_response.headers = {}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)
        mock_client.cookies = {}
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.send_http_request("GET", "http://target.local/")

    assert result["body_truncated"] is True
    assert len(result["body"]) == 4000
    assert result["response_length"] == 10000


async def test_send_http_request_transport_error_not_anomaly():
    """A connection failure is a transport error, not a server-side anomaly."""
    import httpx

    client = MCPClient()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=httpx.ConnectTimeout("nope"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.send_http_request("GET", "https://unreachable.local/")

    assert result["status_code"] == 0
    assert result["is_server_error"] is False
    assert result["stack_trace_detected"] is False
    assert result["transport_error"] == "ConnectTimeout"


async def test_send_http_request_rejects_bad_method():
    """An unsupported HTTP method is rejected without making a request."""
    client = MCPClient()
    result = await client.send_http_request("FROBNICATE", "http://target.local/")
    assert "Unsupported HTTP method" in result["error"]



async def test_send_http_request_read_error_is_crash_signal():
    """
    A mid-exchange connection DROP (ReadError) is treated as a suspected backend
    crash -> a real lead, not swallowed noise. Regression for the trace where a
    SQLi payload caused a ReadError that was hidden from the agent.
    """
    import httpx

    client = MCPClient()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=httpx.ReadError("dropped"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.send_http_request(
            "POST", "http://target.local/login", json_body={"username": "' OR 1=1--"}
        )

    assert result["transport_error"] == "ReadError"
    assert result["server_crash_suspected"] is True
    assert result["is_server_error"] is True
    assert "socket" in result["telemetry"].lower()


async def test_send_http_request_connect_error_is_not_a_lead():
    """
    A plain can't-connect failure (ConnectError) is infrastructure noise, NOT a
    suspected crash. Regression for the false 'php://filter RCE' on a filtered
    port.
    """
    import httpx

    client = MCPClient()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.send_http_request("GET", "https://filtered.local/")

    assert result["transport_error"] == "ConnectError"
    assert result["server_crash_suspected"] is False
    assert result["is_server_error"] is False


async def test_run_fuzzer_read_error_flagged_as_anomaly():
    """run_fuzzer now flags a ReadError (suspected crash) as an anomaly."""
    import httpx

    client = MCPClient()
    payloads = [{"param": "username", "value": "' OR 1=1--"}]

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ReadError("dropped"))
        mock_client.post = AsyncMock(side_effect=httpx.ReadError("dropped"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.run_fuzzer("http://target.local/login", payloads, "body")

    assert result["anomalies_found"] == 1
    row = result["results"][0]
    assert row["anomaly_detected"] is True
    assert row["server_crash_suspected"] is True


async def test_run_fuzzer_connect_error_not_anomaly():
    """A plain ConnectError in run_fuzzer is still NOT an anomaly."""
    import httpx

    client = MCPClient()
    payloads = [{"param": "q", "value": "x"}]

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await client.run_fuzzer("https://filtered.local/", payloads, "query")

    assert result["anomalies_found"] == 0
    assert result["results"][0]["anomaly_detected"] is False



# --- PoC JSON-output evaluation (flips exploit_confirmed) ---


def test_evaluate_poc_json_signature_match():
    """A printed JSON dict matching the expected signature confirms the exploit."""
    from app.services.mcp_client import _evaluate_poc_output

    confirmed, detail = _evaluate_poc_output(
        'starting\n{"server_crash": true}', "", {"server_crash": True}
    )
    assert confirmed is True
    assert "matched expected signature" in detail


def test_evaluate_poc_explicit_negative_not_confirmed():
    """An explicit {"server_crash": false} is trusted as a negative result."""
    from app.services.mcp_client import _evaluate_poc_output

    confirmed, _ = _evaluate_poc_output(
        '{"server_crash": false}', "", {"server_crash": True}
    )
    assert confirmed is False


def test_evaluate_poc_crash_marker_fallback():
    """A server-error marker in stderr confirms even if the JSON verdict is silent."""
    from app.services.mcp_client import _evaluate_poc_output

    confirmed, detail = _evaluate_poc_output(
        '{"note": "ran"}',
        "Traceback (most recent call last):\n  ...\nOperationalError: DB crashed",
        {"server_crash": True},
    )
    assert confirmed is True
    assert "crash marker" in detail


def test_evaluate_poc_no_signature_truthy_json():
    """With no signature, any truthy JSON verdict counts as a hit."""
    from app.services.mcp_client import _evaluate_poc_output

    confirmed, _ = _evaluate_poc_output('{"crashed": true}', "", {})
    assert confirmed is True


def test_evaluate_poc_nothing_matches():
    """Clean output with no marker and no matching JSON is not a confirmation."""
    from app.services.mcp_client import _evaluate_poc_output

    confirmed, _ = _evaluate_poc_output("all good", "", {"server_crash": True})
    assert confirmed is False


def test_evaluate_poc_prefers_last_json_object():
    """The LAST printed JSON object (the final verdict) wins."""
    from app.services.mcp_client import _evaluate_poc_output

    out = '{"server_crash": false}\nretrying...\n{"server_crash": true}'
    confirmed, _ = _evaluate_poc_output(out, "", {"server_crash": True})
    assert confirmed is True


async def test_execute_safe_poc_confirms_via_json():
    """End-to-end: a script printing a matching JSON verdict flips confirmed."""
    client = MCPClient()
    script = "import json\nprint(json.dumps({'server_crash': True}))"
    result = await client.execute_safe_poc("s1", script, {"server_crash": True})
    assert result["exploit_confirmed"] is True
    assert "match_detail" in result


def test_system_prompt_teaches_poc_json_contract():
    """The K2 prompt instructs printing a JSON verdict for execute_safe_poc."""
    from app.services.k2_agent import SYSTEM_PROMPT

    assert "execute_safe_poc" in SYSTEM_PROMPT
    assert "json" in SYSTEM_PROMPT.lower()
    assert "expected_signature" in SYSTEM_PROMPT
