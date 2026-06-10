from __future__ import annotations

from typing import Optional

import os
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session, get_db
from app.models import AnalysisJob, Mitigation, Workspace
from app.schemas import JobCreate, JobResponse, MitigationResponse
from app.services.auth import CLERK_PUBLISHABLE_KEY, get_current_user, require_user
from app.services.orchestrator import FSMState, OrchestratorFSM
from app.services.report import ReportService
from app.templating import templates

api_router = APIRouter(prefix="/api/jobs", tags=["jobs"])
html_router = APIRouter(prefix="/jobs", tags=["jobs-html"])

# Outer-loop safety cap. Each run_cycle() runs the full K2 agentic loop
# (up to MAX_ITERATIONS); we re-run a few times in case a cycle exits early
# without reaching COMPLETE (e.g. a transient parse error).
async def _run_analysis_job(job_id: str) -> None:
    """
    Background task: drive the K2 orchestrator for a job to completion.

    Runs in its own DB session because the request-scoped session is closed
    once the HTTP response is returned.

    Design notes:
    - run_cycle() already contains the full agent loop, the time-budget
      guardrail, AND _ensure_finalized() in a finally block. It always
      returns FSMState.COMPLETE when it exits.
    - We therefore run it exactly ONCE. The old multi-cycle loop was the
      primary cause of 15-minute stalls: each 600s budget × 5 cycles = 50
      minutes maximum, and the deadline check only fires between iterations,
      so a single slow generate_patch call could eat the entire budget.
    """
    async with async_session() as db:
        fsm = OrchestratorFSM(db, job_id)
        await fsm.run_cycle()


@api_router.post("/", response_model=JobResponse, status_code=201)
async def create_job(
    job_in: JobCreate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(require_user),
):
    result = await db.execute(
        select(Workspace).where(Workspace.id == job_in.workspace_id)
    )
    workspace = result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if not workspace.verification_status:
        raise HTTPException(status_code=403, detail="Workspace is not verified")
    # Ownership check: only the workspace owner may create jobs for it.
    if (
        workspace.owner_id is not None
        and user_id != "test-user"
        and workspace.owner_id != user_id
    ):
        raise HTTPException(status_code=403, detail="Access denied.")

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


@api_router.post("/{job_id}/start", response_model=JobResponse)
async def start_job(
    job_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(require_user),
):
    """Launch the K2-driven analysis pipeline for a job as a background task."""
    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    # Verify the caller owns the workspace this job belongs to.
    ws_result = await db.execute(
        select(Workspace).where(Workspace.id == job.workspace_id)
    )
    ws = ws_result.scalar_one_or_none()
    if (
        ws
        and ws.owner_id is not None
        and user_id != "test-user"
        and ws.owner_id != user_id
    ):
        raise HTTPException(status_code=403, detail="Access denied.")

    # Statuses that mean the scan has already been started (or finished).
    # "pending" is the initial DB value; every other FSMState except READY
    # means the orchestrator is already (or was) running.
    CANNOT_START = {
        # FSM in-progress states
        FSMState.RECON.value,
        FSMState.DAST_TESTING.value,
        FSMState.POC_VERIFICATION.value,
        FSMState.BLUE_TEAM_REMEDIATION.value,
        FSMState.COMPLETE.value,
        # READY means /start was already called (orchestrator is spinning up)
        FSMState.READY.value,
    }

    if job.status in CANNOT_START:
        if job.status == FSMState.COMPLETE.value:
            raise HTTPException(
                status_code=409,
                detail="This scan has already completed. Create a new job to scan again.",
            )
        raise HTTPException(
            status_code=409,
            detail=(
                f"Scan is already in progress (status: {job.status}). "
                "Wait for it to finish or create a new job."
            ),
        )

    # Mark as started so the UI reflects progress immediately; the orchestrator
    # treats a non-FSM status ("pending") as READY on hydration.
    job.status = FSMState.READY.value
    await db.commit()
    await db.refresh(job)

    background_tasks.add_task(_run_analysis_job, job_id)
    return job


@api_router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(require_user),
):
    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@api_router.get("/{job_id}/mitigations", response_model=list[MitigationResponse])
async def get_mitigations(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(require_user),
):
    result = await db.execute(
        select(Mitigation).where(Mitigation.job_id == job_id)
    )
    mitigations = result.scalars().all()
    return mitigations


@api_router.get("/{job_id}/report")
async def get_report(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(require_user),
):
    """
    Download the job's PDF vulnerability report.

    Serves the file generated at finalize time. If it's missing (e.g. the
    server was restarted and /tmp cleared), it is regenerated on demand from
    the stored attack graph so the download always works for a finished job.
    """
    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    report_svc = ReportService()
    path = report_svc.report_path(job_id)
    if not os.path.exists(path):
        # Regenerate from whatever analysis data we have.
        attack_graph = job.attack_graph_data or {}
        severity = job.overall_severity or attack_graph.get("overall_severity") or "low"
        if not attack_graph:
            raise HTTPException(
                status_code=409,
                detail="No analysis data yet - run the scan before downloading a report.",
            )
        path = await report_svc.generate(db, job_id, severity, attack_graph)

    return FileResponse(
        path,
        media_type="application/pdf",
        filename=f"threatweaver-report-{job_id[:8]}.pdf",
    )


@html_router.get("/{job_id}")
async def job_page(
    request: Request,
    job_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user),
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
        {"job": job, "mitigations": mitigations, "clerk_pk": CLERK_PUBLISHABLE_KEY},
    )


# Combined router for backwards compatibility with main.py include
router = APIRouter()
router.include_router(api_router)
router.include_router(html_router)
