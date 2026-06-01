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

    assert result["error"] == "nmap scan timed out"
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


async def test_query_hackclub_error():
    """Mock httpx to return 500, verify graceful fallback."""
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
    assert result["vulnerable_components"] == []
    assert result["mitigations"] == []


async def test_query_hackclub_network_error():
    """Verify graceful handling of network errors."""
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
    assert result["mitigations"] == []
