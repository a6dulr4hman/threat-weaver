"""Tests for the orchestrator FSM service."""
import uuid

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base
from app.models import AnalysisJob, Workspace
from app.services.orchestrator import FSMState, OrchestratorFSM, TRANSITIONS

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestAsyncSession = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest_asyncio.fixture
async def db_session():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestAsyncSession() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def test_fsm_valid_transitions():
    """Test that READY->RECON->DAST_TESTING etc. all work."""
    # Verify that the transition map supports the full chain
    assert FSMState.RECON in TRANSITIONS[FSMState.READY]
    assert FSMState.DAST_TESTING in TRANSITIONS[FSMState.RECON]
    assert FSMState.POC_VERIFICATION in TRANSITIONS[FSMState.DAST_TESTING]
    assert FSMState.BLUE_TEAM_REMEDIATION in TRANSITIONS[FSMState.POC_VERIFICATION]
    assert FSMState.COMPLETE in TRANSITIONS[FSMState.BLUE_TEAM_REMEDIATION]


def test_fsm_invalid_transition():
    """Test that READY->COMPLETE fails."""
    assert FSMState.COMPLETE not in TRANSITIONS[FSMState.READY]
    assert FSMState.READY not in TRANSITIONS[FSMState.COMPLETE]
    assert FSMState.DAST_TESTING not in TRANSITIONS[FSMState.READY]


async def test_fsm_transition_method(db_session):
    """Test the transition() method on OrchestratorFSM."""
    job_id = str(uuid.uuid4())
    fsm = OrchestratorFSM(db=db_session, job_id=job_id)

    # Valid transition
    assert fsm.state == FSMState.READY
    assert fsm.transition(FSMState.RECON) is True
    assert fsm.state == FSMState.RECON

    # Invalid transition (skip a step)
    assert fsm.transition(FSMState.COMPLETE) is False
    assert fsm.state == FSMState.RECON  # State unchanged


async def test_hydrate_state(db_session):
    """Create a job in DB with status='recon', hydrate, verify state is RECON."""
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    # Create workspace first (FK constraint)
    workspace = Workspace(
        id=workspace_id,
        target_url="https://example.com",
        verification_nonce="abc123",
        verification_status=True,
    )
    db_session.add(workspace)
    await db_session.commit()

    # Create a job with status "recon"
    job = AnalysisJob(
        id=job_id,
        workspace_id=workspace_id,
        status="recon",
        attack_graph_data={"nodes": ["vuln1"]},
    )
    db_session.add(job)
    await db_session.commit()

    # Hydrate the FSM
    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    await fsm.hydrate_state()

    assert fsm.state == FSMState.RECON
    assert fsm.attack_graph == {"nodes": ["vuln1"]}


async def test_save_state(db_session):
    """Test that save_state persists FSM state to DB."""
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    workspace = Workspace(
        id=workspace_id,
        target_url="https://example.com",
        verification_nonce="abc123",
        verification_status=True,
    )
    db_session.add(workspace)
    await db_session.commit()

    job = AnalysisJob(
        id=job_id,
        workspace_id=workspace_id,
        status="ready",
        attack_graph_data={},
    )
    db_session.add(job)
    await db_session.commit()

    # Create FSM, change state, save
    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.state = FSMState.DAST_TESTING
    fsm.attack_graph = {"test": "data"}
    await fsm.save_state()

    # Verify in DB
    from sqlalchemy import select

    stmt = select(AnalysisJob).where(AnalysisJob.id == job_id)
    result = await db_session.execute(stmt)
    updated_job = result.scalar_one()
    assert updated_job.status == "dast_testing"
    assert updated_job.attack_graph_data == {"test": "data"}


def test_deduplication():
    """Test that is_duplicate returns False first time, True second time."""
    from unittest.mock import MagicMock

    fsm = OrchestratorFSM(db=MagicMock(), job_id="test-job-123")

    # First occurrence - not a duplicate
    assert fsm.is_duplicate("file.py", "sql_injection", 10) is False
    # Second occurrence - is a duplicate
    assert fsm.is_duplicate("file.py", "sql_injection", 10) is True
    # Different vulnerability - not a duplicate
    assert fsm.is_duplicate("file.py", "xss", 10) is False
    # Different line - not a duplicate
    assert fsm.is_duplicate("file.py", "sql_injection", 20) is False
