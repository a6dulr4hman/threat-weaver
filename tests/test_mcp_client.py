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
