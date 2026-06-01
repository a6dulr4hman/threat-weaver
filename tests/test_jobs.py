from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_create_job_unverified(client):
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    response = await client.post(
        "/api/jobs/", json={"workspace_id": workspace_id}
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_create_job_verified(client):
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    # Verify the workspace
    with patch("app.routers.workspaces.verify_domain", new_callable=AsyncMock) as mock_verify:
        mock_verify.return_value = True
        await client.post(f"/api/workspaces/{workspace_id}/verify")

    response = await client.post(
        "/api/jobs/", json={"workspace_id": workspace_id}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "pending"
    assert data["workspace_id"] == workspace_id
    assert data["overall_severity"] is None
    assert data["attack_graph_data"] is None


@pytest.mark.asyncio
async def test_get_job(client):
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    with patch("app.routers.workspaces.verify_domain", new_callable=AsyncMock) as mock_verify:
        mock_verify.return_value = True
        await client.post(f"/api/workspaces/{workspace_id}/verify")

    job_resp = await client.post(
        "/api/jobs/", json={"workspace_id": workspace_id}
    )
    job_id = job_resp.json()["id"]

    response = await client.get(f"/api/jobs/{job_id}")
    assert response.status_code == 200
    assert response.json()["id"] == job_id


@pytest.mark.asyncio
async def test_get_mitigations(client):
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    with patch("app.routers.workspaces.verify_domain", new_callable=AsyncMock) as mock_verify:
        mock_verify.return_value = True
        await client.post(f"/api/workspaces/{workspace_id}/verify")

    job_resp = await client.post(
        "/api/jobs/", json={"workspace_id": workspace_id}
    )
    job_id = job_resp.json()["id"]

    response = await client.get(f"/api/jobs/{job_id}/mitigations")
    assert response.status_code == 200
    assert response.json() == []
