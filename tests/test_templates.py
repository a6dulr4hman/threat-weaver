from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_index_page(client):
    response = await client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "ThreatWeaver" in response.text


@pytest.mark.asyncio
async def test_workspace_page(client):
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    response = await client.get(f"/workspaces/{workspace_id}")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "example.com" in response.text


@pytest.mark.asyncio
async def test_job_page(client):
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    with patch(
        "app.routers.workspaces.verify_domain", new_callable=AsyncMock
    ) as mock_verify:
        mock_verify.return_value = True
        await client.post(f"/api/workspaces/{workspace_id}/verify")

    job_resp = await client.post(
        "/api/jobs/", json={"workspace_id": workspace_id}
    )
    job_id = job_resp.json()["id"]

    response = await client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert job_id in response.text
