import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AnalysisJob, Workspace
from app.schemas import WorkspaceCreate, WorkspaceResponse
from app.services.crypto import generate_nonce
from app.services.verification import lookup_txt_values, verify_domain
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


@api_router.post("/{workspace_id}/verify")
async def verify_workspace(workspace_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")

    verified = await verify_domain(workspace.target_url, workspace.verification_nonce)
    workspace.verification_status = verified
    await db.commit()
    await db.refresh(workspace)

    # When it fails, look up what's actually published so the UI can explain why.
    detail = None
    if not verified:
        found, err = await lookup_txt_values(workspace.target_url)
        if found:
            shown = ", ".join(f'"{v}"' for v in found)
            detail = (
                f"A TXT record exists at _threatweaver.{workspace.target_url} but "
                f"none matched. Expected \"{workspace.verification_nonce}\" but "
                f"found {shown}. Update the record to the expected value."
            )
        else:
            detail = err or (
                f"No matching TXT record at _threatweaver.{workspace.target_url}, and "
                f"the HTTP fallback (https://{workspace.target_url}/threatweaver.txt) "
                f"did not return the nonce."
            )

    return {
        "id": workspace.id,
        "target_url": workspace.target_url,
        "verification_nonce": workspace.verification_nonce,
        "verification_status": workspace.verification_status,
        "verification_detail": detail,
    }


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
