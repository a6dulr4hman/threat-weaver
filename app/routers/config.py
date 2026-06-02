from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import RoutingConfig
from app.schemas import RoutingConfigCreate, RoutingConfigResponse
from app.templating import templates

api_router = APIRouter(prefix="/api/config", tags=["config"])
html_router = APIRouter(prefix="/config", tags=["config-html"])


@api_router.get("/routing", response_model=list[RoutingConfigResponse])
async def list_routing_configs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RoutingConfig))
    configs = result.scalars().all()
    return configs


@api_router.put("/routing/{role}", response_model=RoutingConfigResponse)
async def upsert_routing_config(
    role: str, config_in: RoutingConfigCreate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(RoutingConfig).where(RoutingConfig.role == role)
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.email_address = config_in.email_address
    else:
        existing = RoutingConfig(role=role, email_address=config_in.email_address)
        db.add(existing)

    await db.commit()
    await db.refresh(existing)
    return existing


@api_router.delete("/routing/{role}", status_code=204)
async def delete_routing_config(role: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(RoutingConfig).where(RoutingConfig.role == role)
    )
    existing = result.scalar_one_or_none()
    if existing is None:
        raise HTTPException(status_code=404, detail="Routing config not found")

    await db.delete(existing)
    await db.commit()
    return Response(status_code=204)


@html_router.get("/")
async def config_page(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RoutingConfig))
    configs = result.scalars().all()
    return templates.TemplateResponse(
        request,
        "config.html",
        {"configs": configs},
    )


# Combined router for backwards compatibility with main.py include
router = APIRouter()
router.include_router(api_router)
router.include_router(html_router)
