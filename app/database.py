import os
from collections.abc import AsyncGenerator

from dotenv import load_dotenv
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./threatweaver.db")

engine = create_async_engine(DATABASE_URL, echo=False)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


@event.listens_for(engine.sync_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Lightweight, idempotent migrations for columns added after a table
        # was first created. create_all() only creates MISSING tables — it never
        # ALTERs an existing one — so a deployment with an older schema would be
        # missing newly-added columns. We add them via ALTER TABLE if absent.
        await conn.run_sync(_apply_column_migrations)


def _apply_column_migrations(sync_conn) -> None:
    """Add columns introduced after initial release to pre-existing tables."""
    from sqlalchemy import inspect, text

    inspector = inspect(sync_conn)
    existing_tables = set(inspector.get_table_names())

    # New columns keyed by table. Each value is (column_name, column_ddl_type).
    pending = {
        "analysis_jobs": [("structured_thoughts", "JSON")],
    }

    for table, columns in pending.items():
        if table not in existing_tables:
            continue  # create_all already made it with all current columns
        present = {col["name"] for col in inspector.get_columns(table)}
        for name, ddl_type in columns:
            if name not in present:
                sync_conn.execute(
                    text(f'ALTER TABLE {table} ADD COLUMN {name} {ddl_type}')
                )
