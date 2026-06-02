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



async def _create_verified_job(client):
    """Helper: create a verified workspace and a pending job, return job id."""
    create_resp = await client.post(
        "/api/workspaces", json={"target_url": "example.com"}
    )
    workspace_id = create_resp.json()["id"]

    with patch(
        "app.routers.workspaces.verify_domain", new_callable=AsyncMock
    ) as mock_verify:
        mock_verify.return_value = True
        await client.post(f"/api/workspaces/{workspace_id}/verify")

    job_resp = await client.post("/api/jobs/", json={"workspace_id": workspace_id})
    return job_resp.json()["id"]


@pytest.mark.asyncio
async def test_start_job_not_found(client):
    response = await client.post("/api/jobs/nonexistent-id/start")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_start_job_schedules_pipeline(client):
    job_id = await _create_verified_job(client)

    # Patch the background runner so the pipeline isn't actually executed.
    with patch(
        "app.routers.jobs._run_analysis_job", new_callable=AsyncMock
    ) as mock_run:
        response = await client.post(f"/api/jobs/{job_id}/start")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    mock_run.assert_awaited_once_with(job_id)


@pytest.mark.asyncio
async def test_start_job_already_complete(client):
    job_id = await _create_verified_job(client)

    # Drive the job to COMPLETE directly in the DB.
    from sqlalchemy import select

    from app.models import AnalysisJob
    from tests.conftest import test_async_session

    async with test_async_session() as db:
        result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
        job = result.scalar_one()
        job.status = "complete"
        await db.commit()

    response = await client.post(f"/api/jobs/{job_id}/start")
    assert response.status_code == 409



@pytest.mark.asyncio
async def test_report_job_not_found(client):
    response = await client.get("/api/jobs/nonexistent-id/report")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_report_no_data_yet(client):
    """A job with no analysis data can't produce a report (409)."""
    job_id = await _create_verified_job(client)
    response = await client.get(f"/api/jobs/{job_id}/report")
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_report_download_pdf(client):
    """A finished job returns a downloadable PDF."""
    job_id = await _create_verified_job(client)

    # Give the job some analysis data so a report can be built.
    from sqlalchemy import select

    from app.models import AnalysisJob
    from tests.conftest import test_async_session

    async with test_async_session() as db:
        result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
        job = result.scalar_one()
        job.status = "complete"
        job.overall_severity = "medium"
        job.attack_graph_data = {
            "k2_summary": "Found a server crash on /login.",
            "overall_severity": "medium",
            "tool_results": [
                {"tool": "send_http_request",
                 "arguments": {"method": "POST", "endpoint": "http://t/login"},
                 "result": {"is_server_error": True, "telemetry": "ReadError"}},
            ],
        }
        await db.commit()

    response = await client.get(f"/api/jobs/{job_id}/report")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content[:5] == b"%PDF-"
