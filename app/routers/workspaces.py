import asyncio
import os
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AnalysisJob, Workspace
from app.schemas import GitHubImportRequest, WorkspaceCreate, WorkspaceResponse
from app.services.crypto import generate_nonce
from app.services.verification import verify_domain
from app.templating import templates

MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB

api_router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])
html_router = APIRouter(prefix="/workspaces", tags=["workspaces-html"])


@api_router.post("/", response_model=WorkspaceResponse)
async def create_workspace(
    workspace_in: WorkspaceCreate, db: AsyncSession = Depends(get_db)
):
    workspace_id = str(uuid.uuid4())
    nonce = generate_nonce(workspace_in.target_url)
    workspace = Workspace(
        id=workspace_id,
        target_url=workspace_in.target_url,
        verification_nonce=nonce,
        verification_status=False,
    )
    db.add(workspace)
    await db.commit()
    await db.refresh(workspace)
    return workspace


@api_router.get("/", response_model=list[WorkspaceResponse])
async def list_workspaces(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Workspace))
    workspaces = result.scalars().all()
    return workspaces


@api_router.get("/{workspace_id}", response_model=WorkspaceResponse)
async def get_workspace(workspace_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return workspace


@api_router.post("/{workspace_id}/verify", response_model=WorkspaceResponse)
async def verify_workspace(workspace_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")

    verified = await verify_domain(workspace.target_url, workspace.verification_nonce)
    workspace.verification_status = verified
    await db.commit()
    await db.refresh(workspace)
    return workspace


@api_router.post("/{workspace_id}/upload")
async def upload_file(
    workspace_id: str, file: UploadFile, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")

    # Sanitize filename to prevent path traversal
    raw_filename = file.filename or "upload.zip"
    safe_filename = Path(raw_filename).name
    if not safe_filename or safe_filename in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    upload_dir = f"/tmp/threatweaver/{workspace_id}"
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, safe_filename)

    # Read in chunks and enforce size limit
    total_size = 0
    chunk_size = 1024 * 1024  # 1 MB chunks
    with open(file_path, "wb") as f:
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > MAX_UPLOAD_SIZE:
                f.close()
                os.remove(file_path)
                raise HTTPException(
                    status_code=413, detail="File too large. Maximum size is 100MB."
                )
            f.write(chunk)

    return {"status": "uploaded", "path": file_path}


@api_router.post("/{workspace_id}/import-repo")
async def import_repo(
    workspace_id: str, body: GitHubImportRequest, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")

    clone_dir = f"/tmp/threatweaver/{workspace_id}/repo"
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)
    os.makedirs(os.path.dirname(clone_dir), exist_ok=True)

    try:
        process = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--no-recurse-submodules",
            body.repo_url, clone_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
    except asyncio.TimeoutError:
        process.kill()
        raise HTTPException(
            status_code=500, detail="Clone operation timed out after 120 seconds"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Clone failed: {str(e)}")

    if process.returncode != 0:
        error_msg = stderr.decode().strip() if stderr else "Unknown error"
        raise HTTPException(status_code=500, detail=f"Clone failed: {error_msg}")

    workspace.github_repo_url = body.repo_url
    await db.commit()
    await db.refresh(workspace)

    return {"status": "cloned", "path": clone_dir}


@html_router.get("/{workspace_id}")
async def workspace_page(
    request: Request, workspace_id: str, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    jobs_result = await db.execute(
        select(AnalysisJob).where(AnalysisJob.workspace_id == workspace_id)
    )
    jobs = jobs_result.scalars().all()
    return templates.TemplateResponse(
        request,
        "workspace.html",
        {"workspace": workspace, "jobs": jobs},
    )


# Combined router for backwards compatibility with main.py include
router = APIRouter()
router.include_router(api_router)
router.include_router(html_router)
