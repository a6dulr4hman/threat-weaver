from unittest.mock import AsyncMock, patch

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
    nonce = create_resp.json()["verification_nonce"]

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.text = nonce

    with patch("app.routers.workspaces.verify_domain", new_callable=AsyncMock) as mock_verify:
        mock_verify.return_value = True
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
