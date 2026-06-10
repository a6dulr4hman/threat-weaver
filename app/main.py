from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db, init_db
from app.models import Workspace
from app.routers import jobs, workspaces
from app.services.auth import (
    CLERK_PUBLISHABLE_KEY,
    _AUTH_ENABLED,
    get_current_user,
)
from app.templating import templates

BASE_DIR = Path(__file__).resolve().parent

# HTML paths that are accessible without authentication (sign-in page itself).
_PUBLIC_PATHS = {"/sign-in", "/sign-up"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="ThreatWeaver", lifespan=lifespan)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

app.include_router(workspaces.router)
app.include_router(jobs.router)


# ---------------------------------------------------------------------------
# Auth-wall middleware for HTML pages
# ---------------------------------------------------------------------------
@app.middleware("http")
async def auth_wall(request: Request, call_next):
    """Redirect unauthenticated browser requests to /sign-in.

    Only fires when:
    - Clerk auth is enabled (CLERK_SECRET_KEY is set)
    - The request is for an HTML page (not an API endpoint or static asset)
    - The path is not already a public page
    """
    path = request.url.path

    # Skip middleware for API, static files, verification endpoint, and
    # the Clerk-hosted pages themselves.
    if (
        not _AUTH_ENABLED
        or path.startswith("/api/")
        or path.startswith("/static/")
        or path in _PUBLIC_PATHS
        # Let Clerk's JS and webhook paths through unconditionally.
        or path.startswith("/clerk")
    ):
        return await call_next(request)

    # Check if the user has a valid Clerk session cookie.
    session_token = request.cookies.get("__session")
    auth_header = request.headers.get("authorization")
    has_token = bool(session_token or (auth_header and "Bearer " in auth_header))

    if not has_token:
        # Browser HTML request with no session → redirect to sign-in.
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return RedirectResponse(url="/sign-in", status_code=302)

    return await call_next(request)


# ---------------------------------------------------------------------------
# Sign-in / sign-up pages (rendered server-side, Clerk JS takes over)
# ---------------------------------------------------------------------------
@app.get("/sign-in")
async def sign_in_page(request: Request):
    return templates.TemplateResponse(
        request, "sign_in.html", {"clerk_pk": CLERK_PUBLISHABLE_KEY}
    )


@app.get("/sign-up")
async def sign_up_page(request: Request):
    return templates.TemplateResponse(
        request, "sign_in.html", {"clerk_pk": CLERK_PUBLISHABLE_KEY, "mode": "sign_up"}
    )


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.get("/")
async def root(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user),
):
    stmt = select(Workspace)
    if user_id and user_id != "test-user" and _AUTH_ENABLED:
        stmt = stmt.where(
            (Workspace.owner_id == user_id) | (Workspace.owner_id.is_(None))
        )
    result = await db.execute(stmt)
    workspace_list = result.scalars().all()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "workspaces": workspace_list,
            "clerk_pk": CLERK_PUBLISHABLE_KEY,
            "auth_enabled": _AUTH_ENABLED,
        },
    )
