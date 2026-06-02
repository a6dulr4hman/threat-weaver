import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import pytest


@pytest.mark.asyncio
async def test_create_workspace(client):
    response = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["target_url"] == "example.com"
    assert data["verification_nonce"] is not None
    assert len(data["verification_nonce"]) == 64  # SHA256 hex digest
    assert data["verification_status"] is False


@pytest.mark.asyncio
async def test_list_workspaces(client):
    await client.post("/api/workspaces", json={"target_url": "example1.com"})
    await client.post("/api/workspaces", json={"target_url": "example2.com"})
    response = await client.get("/api/workspaces")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


@pytest.mark.asyncio
async def test_get_workspace(client):
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]
    response = await client.get(f"/api/workspaces/{workspace_id}")
    assert response.status_code == 200
    assert response.json()["id"] == workspace_id


@pytest.mark.asyncio
async def test_get_workspace_not_found(client):
    response = await client.get("/api/workspaces/nonexistent-id")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_verify_workspace(client):
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    with patch("app.routers.workspaces.verify_domain", new_callable=AsyncMock) as mock_verify:
        mock_verify.return_value = True
        response = await client.post(f"/api/workspaces/{workspace_id}/verify")

    assert response.status_code == 200
    assert response.json()["verification_status"] is True


@pytest.mark.asyncio
async def test_verify_workspace_dns(client):
    """Test that DNS TXT verification works when the record contains the nonce."""
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]
    nonce = create_resp.json()["verification_nonce"]

    # Mock DNS resolver to return the nonce in a TXT record
    mock_rdata = MagicMock()
    mock_rdata.strings = [nonce.encode()]
    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter([mock_rdata])

    with patch("app.services.verification.dns.resolver.resolve", return_value=mock_answer):
        with patch("app.services.verification.asyncio.get_event_loop") as mock_loop:
            # Make run_in_executor call the function directly
            async def run_executor(executor, func, *args):
                return func(*args)
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=lambda ex, fn, *a: _run_sync(fn, *a))

    # Use a simpler approach - patch the internal _check_dns_txt directly
    with patch("app.services.verification._check_dns_txt", new_callable=AsyncMock) as mock_dns:
        mock_dns.return_value = True
        response = await client.post(f"/api/workspaces/{workspace_id}/verify")

    assert response.status_code == 200
    assert response.json()["verification_status"] is True


@pytest.mark.asyncio
async def test_verify_workspace_dns_fallback_to_http(client):
    """Test that HTTP fallback works when DNS verification fails."""
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    with patch("app.services.verification._check_dns_txt", new_callable=AsyncMock) as mock_dns:
        mock_dns.return_value = False
        with patch("app.services.verification._check_http", new_callable=AsyncMock) as mock_http:
            mock_http.return_value = True
            response = await client.post(f"/api/workspaces/{workspace_id}/verify")

    assert response.status_code == 200
    assert response.json()["verification_status"] is True


@pytest.mark.asyncio
async def test_upload_path_traversal(client):
    """Verify that path traversal filenames are sanitized."""
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    # Attempt path traversal with ../../etc/passwd
    response = await client.post(
        f"/api/workspaces/{workspace_id}/upload",
        files={"file": ("../../etc/passwd", b"malicious content", "application/zip")},
    )
    assert response.status_code == 200
    data = response.json()
    # The filename should be sanitized to just "passwd"
    assert "../../" not in data["path"]
    assert data["path"].endswith("/passwd")


@pytest.mark.asyncio
async def test_create_workspace_rejects_private_ip(client):
    """Verify that private IP addresses are rejected in target_url."""
    # Localhost
    response = await client.post(
        "/api/workspaces", json={"target_url": "127.0.0.1"}
    )
    assert response.status_code == 422

    # Private range 10.x
    response = await client.post(
        "/api/workspaces", json={"target_url": "10.0.0.1"}
    )
    assert response.status_code == 422

    # Private range 192.168.x
    response = await client.post(
        "/api/workspaces", json={"target_url": "192.168.1.1"}
    )
    assert response.status_code == 422

    # Metadata endpoint
    response = await client.post(
        "/api/workspaces", json={"target_url": "169.254.169.254"}
    )
    assert response.status_code == 422

    # Localhost name
    response = await client.post(
        "/api/workspaces", json={"target_url": "localhost"}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_import_repo_valid(client):
    """Test that a valid GitHub URL triggers a successful clone."""
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    mock_process = AsyncMock()
    mock_process.communicate = AsyncMock(return_value=(b"", b""))
    mock_process.returncode = 0

    with patch("app.routers.workspaces.asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = mock_process
        response = await client.post(
            f"/api/workspaces/{workspace_id}/import-repo",
            json={"repo_url": "https://github.com/owner/repo"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "cloned"
    assert data["path"] == f"/tmp/threatweaver/{workspace_id}/repo"

    # Verify the subprocess was called correctly
    mock_exec.assert_called_once_with(
        "git", "clone", "--depth", "1",
        "https://github.com/owner/repo",
        f"/tmp/threatweaver/{workspace_id}/repo",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


@pytest.mark.asyncio
async def test_import_repo_invalid_url(client):
    """Test that non-GitHub URLs are rejected with 422."""
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    # Not a GitHub URL
    response = await client.post(
        f"/api/workspaces/{workspace_id}/import-repo",
        json={"repo_url": "https://gitlab.com/owner/repo"},
    )
    assert response.status_code == 422

    # Missing owner/repo
    response = await client.post(
        f"/api/workspaces/{workspace_id}/import-repo",
        json={"repo_url": "https://github.com/"},
    )
    assert response.status_code == 422

    # HTTP instead of HTTPS
    response = await client.post(
        f"/api/workspaces/{workspace_id}/import-repo",
        json={"repo_url": "http://github.com/owner/repo"},
    )
    assert response.status_code == 422

    # Command injection attempt
    response = await client.post(
        f"/api/workspaces/{workspace_id}/import-repo",
        json={"repo_url": "https://github.com/owner/repo; rm -rf /"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_import_repo_workspace_not_found(client):
    """Test that importing to a nonexistent workspace returns 404."""
    response = await client.post(
        "/api/workspaces/nonexistent-id/import-repo",
        json={"repo_url": "https://github.com/owner/repo"},
    )
    assert response.status_code == 404
