import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AnalysisJob, Mitigation, Workspace
from app.schemas import JobCreate, JobResponse, MitigationResponse
from app.templating import templates

api_router = APIRouter(prefix="/api/jobs", tags=["jobs"])
html_router = APIRouter(prefix="/jobs", tags=["jobs-html"])


@api_router.post("/", response_model=JobResponse, status_code=201)
async def create_job(job_in: JobCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Workspace).where(Workspace.id == job_in.workspace_id)
    )
    workspace = result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if not workspace.verification_status:
        raise HTTPException(
            status_code=403, detail="Workspace is not verified"
        )

    job = AnalysisJob(
        id=str(uuid.uuid4()),
        workspace_id=job_in.workspace_id,
        status="pending",
        overall_severity=None,
        attack_graph_data=None,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    return job


@api_router.get("/{job_id}", response_model=JobResponse)
async def get_job(job_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@api_router.get("/{job_id}/mitigations", response_model=list[MitigationResponse])
async def get_mitigations(job_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Mitigation).where(Mitigation.job_id == job_id)
    )
    mitigations = result.scalars().all()
    return mitigations


@html_router.get("/{job_id}")
async def job_page(
    request: Request, job_id: str, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    mitigations_result = await db.execute(
        select(Mitigation).where(Mitigation.job_id == job_id)
    )
    mitigations = mitigations_result.scalars().all()
    return templates.TemplateResponse(
        request,
        "job_detail.html",
        {"job": job, "mitigations": mitigations},
    )


# Combined router for backwards compatibility with main.py include
router = APIRouter()
router.include_router(api_router)
router.include_router(html_router)
