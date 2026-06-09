from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db, init_db
from app.models import Workspace
from app.routers import jobs, workspaces
from app.templating import templates

BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="ThreatWeaver", lifespan=lifespan)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

app.include_router(workspaces.router)
app.include_router(jobs.router)


@app.get("/")
async def root(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Workspace))
    workspace_list = result.scalars().all()
    return templates.TemplateResponse(
        request, "index.html", {"workspaces": workspace_list}
    )
