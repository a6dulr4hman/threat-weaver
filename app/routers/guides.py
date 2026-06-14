"""Per-account onboarding-guide tracking.

The frontend shows the guided tour on each page (dashboard, workspace, job)
until the account marks that page's guide as finished. Completion is stored
per Clerk account in the ``user_guides`` table so a brand-new account sees the
guide on every page, and the state follows the user across devices/browsers.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import UserGuide
from app.services.auth import require_user

router = APIRouter(prefix="/api/guides", tags=["guides"])

# The set of guides the UI knows how to render (matches data-tour pages).
VALID_GUIDES = {"dashboard", "workspace", "job"}


async def _get_row(db: AsyncSession, user_id: str) -> UserGuide | None:
    result = await db.execute(select(UserGuide).where(UserGuide.user_id == user_id))
    return result.scalar_one_or_none()


@router.get("")
async def list_completed_guides(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(require_user),
):
    """Return the list of guide keys this account has finished."""
    row = await _get_row(db, user_id)
    completed = list(row.completed) if row and row.completed else []
    return {"completed": completed}


@router.post("/{name}/complete")
async def complete_guide(
    name: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(require_user),
):
    """Mark a guide as finished for the current account (idempotent)."""
    if name not in VALID_GUIDES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown guide '{name}'.",
        )

    row = await _get_row(db, user_id)
    if row is None:
        row = UserGuide(user_id=user_id, completed=[name])
        db.add(row)
    else:
        done = list(row.completed or [])
        if name not in done:
            done.append(name)
            # Reassign so SQLAlchemy detects the JSON column change.
            row.completed = done
    await db.commit()
    return {"completed": list(row.completed or [])}
