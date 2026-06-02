"""Tests for the orchestrator FSM service and K2 agentic loop."""
import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

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
    fsm = OrchestratorFSM(db=MagicMock(), job_id="test-job-123")

    # First occurrence - not a duplicate
    assert fsm.is_duplicate("file.py", "sql_injection", 10) is False
    # Second occurrence - is a duplicate
    assert fsm.is_duplicate("file.py", "sql_injection", 10) is True
    # Different vulnerability - not a duplicate
    assert fsm.is_duplicate("file.py", "xss", 10) is False
    # Different line - not a duplicate
    assert fsm.is_duplicate("file.py", "sql_injection", 20) is False


# --- K2 Agent Tests ---


async def test_k2_agent_parse_tool_call():
    """K2Agent parses a valid tool_call JSON response correctly."""
    from app.services.k2_agent import K2Agent

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=json.dumps({
        "action": "tool_call",
        "tool": "run_nmap",
        "arguments": {"target": "example.com", "port_range": "1-1024"},
        "reasoning": "Starting reconnaissance",
    }))

    agent = K2Agent(llm_client=mock_llm)
    decision = await agent.decide({"phase": "ready", "target": "example.com"})

    assert decision["action"] == "tool_call"
    assert decision["tool"] == "run_nmap"
    assert decision["arguments"]["target"] == "example.com"
    assert decision["reasoning"] == "Starting reconnaissance"


async def test_k2_agent_parse_complete():
    """K2Agent parses a complete action response correctly."""
    from app.services.k2_agent import K2Agent

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=json.dumps({
        "action": "complete",
        "summary": "Found 2 XSS vulnerabilities and generated patches",
    }))

    agent = K2Agent(llm_client=mock_llm)
    decision = await agent.decide({"phase": "blue_team_remediation", "target": "test.com"})

    assert decision["action"] == "complete"
    assert "XSS" in decision["summary"]


async def test_k2_agent_parse_error():
    """K2Agent returns error fallback when LLM returns garbage."""
    from app.services.k2_agent import K2Agent

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value="This is not valid JSON at all!!!")

    agent = K2Agent(llm_client=mock_llm)
    decision = await agent.decide({"phase": "ready", "target": "test.com"})

    assert decision["action"] == "error"
    assert "Could not parse" in decision["detail"]


async def test_k2_agent_parse_markdown_json():
    """K2Agent handles JSON wrapped in markdown code blocks."""
    from app.services.k2_agent import K2Agent

    response_with_markdown = '```json\n{"action": "tool_call", "tool": "run_fuzzer", "arguments": {"url": "https://test.com"}, "reasoning": "testing"}\n```'
    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=response_with_markdown)

    agent = K2Agent(llm_client=mock_llm)
    decision = await agent.decide({"phase": "recon", "target": "test.com"})

    assert decision["action"] == "tool_call"
    assert decision["tool"] == "run_fuzzer"


async def test_k2_agent_parse_think_block_then_json():
    """K2Agent extracts JSON that follows a <think>...</think> reasoning block."""
    from app.services.k2_agent import K2Agent

    # This mirrors how K2-Think-v2 actually responds: reasoning prose, then JSON.
    response = (
        "<think>We have a given analysis state. The target is falak.me. "
        "Current phase = ready. No files scanned yet, so I should begin with "
        "reconnaissance to map the attack surface.</think>\n"
        '{"action": "tool_call", "tool": "run_nmap", '
        '"arguments": {"target": "falak.me", "port_range": "1-1024"}, '
        '"reasoning": "Begin recon"}'
    )
    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=response)

    agent = K2Agent(llm_client=mock_llm)
    decision = await agent.decide({"phase": "ready", "target": "falak.me"})

    assert decision["action"] == "tool_call"
    assert decision["tool"] == "run_nmap"
    assert decision["arguments"]["target"] == "falak.me"


async def test_k2_agent_parse_prose_then_json():
    """K2Agent extracts the trailing JSON even when preceded by plain prose."""
    from app.services.k2_agent import K2Agent

    response = (
        "Alright, let me think about this. The target is example.com and we "
        "haven't done recon yet. I'll start by scanning common ports.\n\n"
        "Here is my decision:\n"
        '{"action": "tool_call", "tool": "run_nmap", '
        '"arguments": {"target": "example.com", "port_range": "1-1024"}}'
    )
    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=response)

    agent = K2Agent(llm_client=mock_llm)
    decision = await agent.decide({"phase": "ready", "target": "example.com"})

    assert decision["action"] == "tool_call"
    assert decision["tool"] == "run_nmap"


async def test_k2_agent_prefers_final_json_object():
    """When reasoning contains an example JSON, the trailing answer wins."""
    from app.services.k2_agent import K2Agent

    response = (
        "<think>I could call something like "
        '{"action": "tool_call", "tool": "query_hackclub"} but recon comes '
        "first.</think>\n"
        '{"action": "tool_call", "tool": "run_nmap", "arguments": {"target": "x.com"}}'
    )
    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=response)

    agent = K2Agent(llm_client=mock_llm)
    decision = await agent.decide({"phase": "ready", "target": "x.com"})

    assert decision["action"] == "tool_call"
    assert decision["tool"] == "run_nmap"


async def test_k2_agent_retries_then_succeeds():
    """K2Agent re-prompts after an unparseable reply and accepts the retry."""
    from app.services.k2_agent import K2Agent

    responses = iter([
        "Hmm, I'm not sure yet, let me think more...",  # unparseable
        '{"action": "tool_call", "tool": "run_nmap", "arguments": {"target": "x.com"}}',
    ])

    async def mock_chat(messages, role="general"):
        return next(responses)

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(side_effect=mock_chat)

    agent = K2Agent(llm_client=mock_llm)
    decision = await agent.decide({"phase": "ready", "target": "x.com"})

    assert decision["action"] == "tool_call"
    assert decision["tool"] == "run_nmap"
    assert mock_llm.chat.call_count == 2


async def test_k2_agent_feed_result():
    """K2Agent.feed_result appends to conversation history."""
    from app.services.k2_agent import K2Agent

    agent = K2Agent(llm_client=MagicMock())
    agent.feed_result("run_nmap", {"results": [{"port": 80}]})

    assert len(agent.conversation_history) == 1
    assert "run_nmap" in agent.conversation_history[0]["content"]
    assert agent.conversation_history[0]["role"] == "user"


# --- Tool Executor Tests ---


async def test_tool_executor_run_nmap():
    """ToolExecutor routes run_nmap to MCPClient correctly."""
    from app.services.tool_executor import ToolExecutor

    mock_mcp = MagicMock()
    mock_mcp.run_nmap = AsyncMock(return_value={"error": None, "results": [{"port": 80}]})

    executor = ToolExecutor(job_id="test-job", mcp_client=mock_mcp)
    result = await executor.execute("run_nmap", {"target": "example.com", "port_range": "80-443"})

    mock_mcp.run_nmap.assert_called_once_with("example.com", "80-443")
    assert result["results"][0]["port"] == 80


async def test_tool_executor_run_fuzzer():
    """ToolExecutor routes run_fuzzer to MCPClient correctly."""
    from app.services.tool_executor import ToolExecutor

    mock_mcp = MagicMock()
    mock_mcp.run_fuzzer = AsyncMock(return_value={"results": [], "anomalies_found": 0})

    executor = ToolExecutor(job_id="test-job", mcp_client=mock_mcp)
    result = await executor.execute("run_fuzzer", {
        "url": "https://test.com",
        "payloads": [{"param": "q", "value": "test"}],
        "injection_type": "query",
    })

    mock_mcp.run_fuzzer.assert_called_once_with(
        "https://test.com", [{"param": "q", "value": "test"}], "query"
    )
    assert result["anomalies_found"] == 0


async def test_tool_executor_unknown_tool():
    """ToolExecutor returns error for unknown tool names."""
    from app.services.tool_executor import ToolExecutor

    executor = ToolExecutor(job_id="test-job", mcp_client=MagicMock())
    result = await executor.execute("nonexistent_tool", {})

    assert "error" in result
    assert "Unknown tool" in result["error"]
    assert "available_tools" in result


async def test_tool_executor_generate_patch():
    """ToolExecutor routes generate_patch to RemediationService."""
    from app.services.tool_executor import ToolExecutor

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value="fixed_code()")

    executor = ToolExecutor(job_id="test-job", mcp_client=MagicMock(), llm_client=mock_llm)
    result = await executor.execute("generate_patch", {
        "vuln_node": "sql_injection",
        "source_code": "query = f'SELECT * FROM users WHERE id={user_input}'",
    })

    assert result["vuln_node"] == "sql_injection"
    assert result["patch"] == "fixed_code()"


async def test_tool_executor_handles_exception():
    """ToolExecutor catches exceptions from tool execution."""
    from app.services.tool_executor import ToolExecutor

    mock_mcp = MagicMock()
    mock_mcp.run_nmap = AsyncMock(side_effect=RuntimeError("connection failed"))

    executor = ToolExecutor(job_id="test-job", mcp_client=mock_mcp)
    result = await executor.execute("run_nmap", {"target": "example.com"})

    assert "error" in result
    assert "connection failed" in result["error"]


# --- Orchestrator Agentic Loop Tests ---


async def test_orchestrator_agentic_loop(db_session):
    """Orchestrator loop: K2 calls a tool then signals complete."""
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    workspace = Workspace(
        id=workspace_id,
        target_url="https://target.com",
        verification_nonce="nonce",
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

    # Mock LLM to return tool_call first, then complete
    call_count = 0

    async def mock_chat(messages, role="general"):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return json.dumps({
                "action": "tool_call",
                "tool": "run_nmap",
                "arguments": {"target": "target.com", "port_range": "1-1024"},
                "reasoning": "Start with recon",
            })
        else:
            return json.dumps({
                "action": "complete",
                "summary": "Scan complete, no critical vulns found",
            })

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(side_effect=mock_chat)
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)

    mock_mcp = MagicMock()
    mock_mcp.run_nmap = AsyncMock(return_value={"error": None, "results": [{"port": 443}]})

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm
    fsm.mcp_client = mock_mcp

    final_state = await fsm.run_cycle()

    # Should have advanced to COMPLETE
    assert final_state == FSMState.COMPLETE
    # run_nmap should have been called
    mock_mcp.run_nmap.assert_called_once_with("target.com", "1-1024")
    # Attack graph should have results
    assert "tool_results" in fsm.attack_graph
    assert fsm.attack_graph["tool_results"][0]["tool"] == "run_nmap"
    assert "k2_summary" in fsm.attack_graph


async def test_orchestrator_agentic_loop_max_iterations(db_session):
    """Orchestrator loop terminates after MAX_ITERATIONS."""
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    workspace = Workspace(
        id=workspace_id,
        target_url="https://target.com",
        verification_nonce="nonce",
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

    # Mock LLM to always return tool_call (never complete)
    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=json.dumps({
        "action": "tool_call",
        "tool": "run_nmap",
        "arguments": {"target": "target.com", "port_range": "1-100"},
        "reasoning": "Keep scanning",
    }))
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)

    mock_mcp = MagicMock()
    mock_mcp.run_nmap = AsyncMock(return_value={"error": None, "results": []})

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm
    fsm.mcp_client = mock_mcp

    with patch("app.services.k2_agent.MAX_ITERATIONS", 3):
        final_state = await fsm.run_cycle()

    # Should NOT be COMPLETE since K2 never said complete
    assert final_state != FSMState.COMPLETE
    # But should have executed exactly 3 iterations
    assert mock_mcp.run_nmap.call_count == 3


async def test_orchestrator_error_breaks_loop(db_session):
    """Orchestrator loop stops on K2 parse error."""
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    workspace = Workspace(
        id=workspace_id,
        target_url="https://target.com",
        verification_nonce="nonce",
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

    # Mock LLM to return unparseable garbage
    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value="I don't know what to do, sorry!")
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm

    await fsm.run_cycle()

    # Should have stopped with an error recorded
    assert "k2_error" in fsm.attack_graph
    assert "Could not parse" in fsm.attack_graph["k2_error"]
    # The agent retries before giving up, so chat is called once per attempt
    # (initial + MAX_PARSE_RETRIES). The orchestrator loop still breaks once.
    from app.services.k2_agent import MAX_PARSE_RETRIES
    assert mock_llm.chat.call_count == MAX_PARSE_RETRIES + 1


async def test_orchestrator_complete_state_noop(db_session):
    """Orchestrator does nothing if state is already COMPLETE."""
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    workspace = Workspace(
        id=workspace_id,
        target_url="https://target.com",
        verification_nonce="nonce",
        verification_status=True,
    )
    db_session.add(workspace)
    await db_session.commit()

    job = AnalysisJob(
        id=job_id,
        workspace_id=workspace_id,
        status="complete",
        attack_graph_data={"done": True},
    )
    db_session.add(job)
    await db_session.commit()

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock()

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm

    final_state = await fsm.run_cycle()

    assert final_state == FSMState.COMPLETE
    # LLM should never have been called
    mock_llm.chat.assert_not_called()
