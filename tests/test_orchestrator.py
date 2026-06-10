"""Tests for the orchestrator FSM service and K2 agentic loop."""
import json
import os
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
    # Return a structured JSON that _parse_finding can handle.
    mock_llm.chat = AsyncMock(return_value='{"description":"test","risk_level":"High","cves":[],"recommendation":"fix it","code":"def fixed(): pass"}')

    executor = ToolExecutor(job_id="test-job", mcp_client=MagicMock(), llm_client=mock_llm)
    result = await executor.execute("generate_patch", {
        "vuln_node": "sql_injection",
        "source_code": "query = f'SELECT * FROM users WHERE id={user_input}'",
    })

    assert result["vuln_node"] == "sql_injection"
    assert "def fixed(): pass" in result["patch"]
    assert result["risk_level"] == "High"


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

    # Exactly 3 iterations executed (MAX_ITERATIONS cap).
    assert mock_mcp.run_nmap.call_count == 3
    # After the loop exhausts, the orchestrator ALWAYS finalizes: it forces the
    # FSM to COMPLETE and generates a report, so a stuck/looping run can never
    # silently hang without output.
    assert final_state == FSMState.COMPLETE
    assert "report" in fsm.attack_graph
    assert fsm.attack_graph.get("overall_severity") is not None


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



async def test_k2_agent_api_error_stops_retrying():
    """
    An 'Error: ...' API response (e.g. 403) is surfaced as an api_error and the
    agent does NOT waste its parse retries nudging K2.
    """
    from app.services.k2_agent import K2Agent

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value="Error: API returned status 403")

    agent = K2Agent(llm_client=mock_llm)
    decision = await agent.decide({"phase": "ready", "target": "x.com"})

    assert decision["action"] == "error"
    assert decision.get("api_error") is True
    assert "403" in decision["detail"]
    # Should have called the API exactly once (no retry storm).
    assert mock_llm.chat.call_count == 1



# --- Raw HTTP primitive routing ---


async def test_tool_executor_send_http_request():
    """ToolExecutor routes send_http_request to MCPClient with all fields."""
    from app.services.tool_executor import ToolExecutor

    mock_mcp = MagicMock()
    mock_mcp.send_http_request = AsyncMock(return_value={"status_code": 200, "body": "ok"})

    executor = ToolExecutor(job_id="test-job", mcp_client=mock_mcp)
    result = await executor.execute("send_http_request", {
        "method": "POST",
        "endpoint": "http://t.local/transfer",
        "headers": {"X-Test": "1"},
        "json_body": {"amount": -100},
        "params": {"debug": "1"},
    })

    mock_mcp.send_http_request.assert_called_once_with(
        method="POST",
        endpoint="http://t.local/transfer",
        headers={"X-Test": "1"},
        json_body={"amount": -100},
        form_data=None,
        params={"debug": "1"},
    )
    assert result["status_code"] == 200


async def test_tool_executor_send_http_request_url_alias():
    """_exec_send_http accepts 'url' as an alias for 'endpoint' and 'body' for json."""
    from app.services.tool_executor import ToolExecutor

    mock_mcp = MagicMock()
    mock_mcp.send_http_request = AsyncMock(return_value={"status_code": 200})

    executor = ToolExecutor(job_id="test-job", mcp_client=mock_mcp)
    await executor.execute("send_http_request", {
        "method": "GET",
        "url": "http://t.local/x",
        "body": {"k": "v"},
    })

    _, kwargs = mock_mcp.send_http_request.call_args
    assert kwargs["endpoint"] == "http://t.local/x"
    assert kwargs["json_body"] == {"k": "v"}


# --- Per-endpoint attack guardrails ---


def _make_fsm():
    fsm = OrchestratorFSM(db=MagicMock(), job_id="guardrail-job")
    fsm.attack_graph = {}
    return fsm


def test_endpoint_key_strips_query():
    """Same path with different query strings shares one budget."""
    fsm = _make_fsm()
    k1 = fsm._endpoint_key("send_http_request", {"endpoint": "http://t/transfer?a=1"})
    k2 = fsm._endpoint_key("send_http_request", {"endpoint": "http://t/transfer?a=2"})
    assert k1 == k2 == "http://t/transfer"


def test_endpoint_key_none_for_non_attack_tool():
    """Non-attack tools (e.g. run_nmap) are not endpoint-scoped."""
    fsm = _make_fsm()
    assert fsm._endpoint_key("run_nmap", {"target": "x.com"}) is None
    assert fsm._endpoint_key("generate_patch", {"vuln_node": "v"}) is None


def test_result_is_anomaly_signals():
    """Server error, stack trace, or fuzzer anomaly all count as anomalies."""
    fsm = _make_fsm()
    assert fsm._result_is_anomaly({"is_server_error": True}) is True
    assert fsm._result_is_anomaly({"stack_trace_detected": True}) is True
    assert fsm._result_is_anomaly({"anomalies_found": 2}) is True
    assert fsm._result_is_anomaly({"status_code": 200}) is False


def test_record_attempt_exhausts_after_three():
    """Three non-anomalous attempts mark the endpoint exhausted."""
    fsm = _make_fsm()
    ep = "http://t/login"

    assert fsm._record_attempt(ep, was_anomaly=False) is not None  # attempt 1
    assert not fsm._is_endpoint_exhausted(ep)
    fsm._record_attempt(ep, was_anomaly=False)  # attempt 2
    assert not fsm._is_endpoint_exhausted(ep)
    note = fsm._record_attempt(ep, was_anomaly=False)  # attempt 3 -> exhausted
    assert fsm._is_endpoint_exhausted(ep)
    assert "exhausted" in note.lower()


def test_record_attempt_anomaly_resets_counter():
    """An anomaly resets the budget so the agent can keep pursuing the lead."""
    fsm = _make_fsm()
    ep = "http://t/search"

    fsm._record_attempt(ep, was_anomaly=False)
    fsm._record_attempt(ep, was_anomaly=False)
    # Anomaly found -> reset
    note = fsm._record_attempt(ep, was_anomaly=True)
    assert note is None
    assert fsm.attack_graph["endpoint_attempts"][ep] == 0
    assert not fsm._is_endpoint_exhausted(ep)


async def test_orchestrator_blocks_exhausted_endpoint(db_session):
    """
    Once an endpoint is exhausted, further attacks on it are blocked (no real
    request) and the agent is nudged to move on. After 3 failed attempts the
    4th is blocked, so the executor runs exactly 3 times.
    """
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    workspace = Workspace(
        id=workspace_id, target_url="http://target.com",
        verification_nonce="n", verification_status=True,
    )
    db_session.add(workspace)
    await db_session.commit()
    job = AnalysisJob(
        id=job_id, workspace_id=workspace_id, status="ready", attack_graph_data={}
    )
    db_session.add(job)
    await db_session.commit()

    # K2 always attacks the same endpoint with a benign (non-anomaly) result.
    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=json.dumps({
        "action": "tool_call",
        "tool": "send_http_request",
        "arguments": {"method": "GET", "endpoint": "http://target.com/login"},
        "reasoning": "probe login",
    }))
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)

    mock_mcp = MagicMock()
    # Always a boring 200 -> never an anomaly -> budget gets consumed.
    mock_mcp.send_http_request = AsyncMock(return_value={
        "status_code": 200, "is_server_error": False,
        "stack_trace_detected": False, "body": "ok",
    })

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm
    fsm.mcp_client = mock_mcp

    with patch("app.services.k2_agent.MAX_ITERATIONS", 6):
        await fsm.run_cycle()

    # Executor should run only MAX_ATTACK_ATTEMPTS (3) times; later iterations
    # are blocked before reaching the network.
    assert mock_mcp.send_http_request.call_count == 3
    assert "http://target.com/login" in fsm.attack_graph.get("exhausted_endpoints", [])
    assert fsm.attack_graph.get("guardrail_notes")


async def test_orchestrator_anomaly_avoids_exhaustion(db_session):
    """If every attempt triggers an anomaly, the endpoint is never exhausted."""
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    workspace = Workspace(
        id=workspace_id, target_url="http://target.com",
        verification_nonce="n", verification_status=True,
    )
    db_session.add(workspace)
    await db_session.commit()
    job = AnalysisJob(
        id=job_id, workspace_id=workspace_id, status="ready", attack_graph_data={}
    )
    db_session.add(job)
    await db_session.commit()

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=json.dumps({
        "action": "tool_call",
        "tool": "send_http_request",
        "arguments": {"method": "POST", "endpoint": "http://target.com/transfer"},
        "reasoning": "logic flaw probe",
    }))
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)

    mock_mcp = MagicMock()
    # Every request triggers a 500 stack trace -> anomaly -> counter resets.
    mock_mcp.send_http_request = AsyncMock(return_value={
        "status_code": 500, "is_server_error": True,
        "stack_trace_detected": True, "body": "Traceback...",
    })

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm
    fsm.mcp_client = mock_mcp

    with patch("app.services.k2_agent.MAX_ITERATIONS", 5):
        await fsm.run_cycle()

    # Never exhausted; all 5 iterations reach the network.
    assert mock_mcp.send_http_request.call_count == 5
    assert "http://target.com/transfer" not in fsm.attack_graph.get(
        "exhausted_endpoints", []
    )


async def test_k2_agent_feed_note():
    """feed_note injects an [ORCHESTRATOR] message into history."""
    from app.services.k2_agent import K2Agent

    agent = K2Agent(llm_client=MagicMock())
    agent.feed_note("endpoint exhausted, move on")

    assert len(agent.conversation_history) == 1
    assert agent.conversation_history[0]["role"] == "user"
    assert "[ORCHESTRATOR]" in agent.conversation_history[0]["content"]
    assert "exhausted" in agent.conversation_history[0]["content"]


def test_run_fuzzer_not_advertised_to_agent():
    """Step 1: run_fuzzer is removed from the tool list K2 sees."""
    from app.services.k2_agent import SYSTEM_PROMPT, K2Agent

    agent = K2Agent(llm_client=MagicMock())
    msg = agent.build_state_message({"routes": [{"path": "/login"}]})

    assert "run_fuzzer" not in msg
    assert "send_http_request" in msg
    assert "/login" in msg
    # The system prompt no longer offers run_fuzzer as a tool option.
    assert "run_fuzzer" not in SYSTEM_PROMPT



# --- Phase 6: severity scoring + report ---


def test_score_severity_levels():
    """_score_severity maps anomaly/exploit counts onto severity tiers."""
    fsm = OrchestratorFSM(db=MagicMock(), job_id="sev-job")

    # No findings -> low
    fsm.attack_graph = {"tool_results": []}
    assert fsm._score_severity() == "low"

    # One anomaly -> medium
    fsm.attack_graph = {"tool_results": [
        {"tool": "send_http_request", "result": {"is_server_error": True}},
    ]}
    assert fsm._score_severity() == "medium"

    # Three anomalies -> high
    fsm.attack_graph = {"tool_results": [
        {"tool": "send_http_request", "result": {"is_server_error": True}},
        {"tool": "send_http_request", "result": {"stack_trace_detected": True}},
        {"tool": "run_fuzzer", "result": {"anomalies_found": 2}},
    ]}
    assert fsm._score_severity() == "high"

    # Confirmed exploit + several anomalies -> extreme
    fsm.attack_graph = {"tool_results": [
        {"tool": "execute_safe_poc", "result": {"exploit_confirmed": True}},
        {"tool": "send_http_request", "result": {"is_server_error": True}},
        {"tool": "send_http_request", "result": {"stack_trace_detected": True}},
        {"tool": "send_http_request", "result": {"server_crash_suspected": True}},
    ]}
    assert fsm._score_severity() == "extreme"


async def test_run_cycle_generates_report(db_session, tmp_path):
    """When K2 completes, the orchestrator scores severity and writes a PDF."""
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())

    workspace = Workspace(
        id=workspace_id, target_url="http://target.com",
        verification_nonce="n", verification_status=True,
    )
    db_session.add(workspace)
    await db_session.commit()
    job = AnalysisJob(
        id=job_id, workspace_id=workspace_id, status="ready", attack_graph_data={}
    )
    db_session.add(job)
    await db_session.commit()

    # K2 immediately completes the analysis.
    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=json.dumps({
        "action": "complete", "summary": "done",
    }))
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm

    # Write the PDF into a temp dir so the test doesn't touch /tmp/threatweaver.
    import app.services.report as report_mod

    with patch.object(report_mod, "REPORT_DIR", str(tmp_path)):
        final_state = await fsm.run_cycle()

    assert final_state == FSMState.COMPLETE
    report = fsm.attack_graph.get("report")
    assert report is not None
    assert report["status"] == "generated"
    assert fsm.attack_graph.get("overall_severity") in {
        "low", "medium", "high", "extreme"
    }
    # The PDF file actually exists and is a valid PDF.
    assert os.path.exists(report["path"])
    with open(report["path"], "rb") as f:
        assert f.read(5) == b"%PDF-"



# --- Regression: generate_patch loop guardrail + guaranteed finalize ---


async def _seed_ready_job(db_session):
    workspace_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    db_session.add(Workspace(
        id=workspace_id, target_url="http://target.com",
        verification_nonce="n", verification_status=True,
    ))
    await db_session.commit()
    db_session.add(AnalysisJob(
        id=job_id, workspace_id=workspace_id, status="ready", attack_graph_data={},
    ))
    await db_session.commit()
    return job_id


async def test_generate_patch_dedup_blocks_repeat(db_session):
    """Patching the same vuln_node twice is blocked (no second execution)."""
    job_id = await _seed_ready_job(db_session)

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=json.dumps({
        "action": "tool_call", "tool": "generate_patch",
        "arguments": {"vuln_node": "login_sqli", "source_code": "x = 1"},
        "reasoning": "patch it",
    }))
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm
    # Pre-seed a real observed anomaly in the DB so hydrate_state() restores it
    # and _has_observed_finding() returns True for the hallucination guardrail.
    observed_finding = [{
        "tool": "send_http_request",
        "result": {"is_server_error": True, "server_crash_suspected": True},
    }]
    from sqlalchemy import select
    from app.models import AnalysisJob as _AJ
    async with db_session.begin_nested():
        r = await db_session.execute(select(_AJ).where(_AJ.id == job_id))
        j = r.scalar_one()
        j.attack_graph_data = {"tool_results": observed_finding}
    await db_session.commit()

    patch_calls = 0

    from app.services import tool_executor as te_mod

    async def counting_execute(self, tool_name, arguments):
        nonlocal patch_calls
        if tool_name == "generate_patch":
            patch_calls += 1
        return {"patch": "def safe(): pass", "vuln_node": arguments.get("vuln_node")}

    with patch.object(te_mod.ToolExecutor, "execute", counting_execute), \
         patch("app.services.k2_agent.MAX_ITERATIONS", 6):
        await fsm.run_cycle()

    # Same vuln_node requested every iteration, but only patched ONCE.
    assert patch_calls == 1
    assert fsm.attack_graph.get("patched_nodes") == ["login_sqli"]


async def test_generate_patch_blocked_without_observed_finding(db_session):
    """generate_patch is blocked when no anomaly has been observed on the target."""
    job_id = await _seed_ready_job(db_session)

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=json.dumps({
        "action": "tool_call", "tool": "generate_patch",
        "arguments": {"vuln_node": "ssh_cve_2024_invented", "source_code": "x"},
        "reasoning": "saw SSH 9.6p1 in nmap, generating a CVE patch",
    }))
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm
    # No tool_results at all → _has_observed_finding() = False

    from app.services import tool_executor as te_mod

    patch_calls = 0

    async def counting_execute(self, tool_name, arguments):
        nonlocal patch_calls
        if tool_name == "generate_patch":
            patch_calls += 1
        return {"patch": ""}

    with patch.object(te_mod.ToolExecutor, "execute", counting_execute), \
         patch("app.services.k2_agent.MAX_ITERATIONS", 3):
        await fsm.run_cycle()

    # generate_patch was blocked — the hallucination guardrail fired.
    assert patch_calls == 0
    assert "ssh_cve_2024_invented" not in fsm.attack_graph.get("patched_nodes", [])
    """No more than MAX_PATCHES distinct patches are generated."""
    from app.services.orchestrator import MAX_PATCHES

    job_id = await _seed_ready_job(db_session)

    # Each iteration asks to patch a NEW vuln node.
    counter = {"i": 0}

    async def mock_chat(messages, role="general"):
        counter["i"] += 1
        return json.dumps({
            "action": "tool_call", "tool": "generate_patch",
            "arguments": {"vuln_node": f"vuln_{counter['i']}", "source_code": "x"},
        })

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(side_effect=mock_chat)
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)

    from app.services import tool_executor as te_mod

    async def fake_execute(self, tool_name, arguments):
        return {"patch": "def safe(): pass", "vuln_node": arguments.get("vuln_node")}

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm

    with patch.object(te_mod.ToolExecutor, "execute", fake_execute), \
         patch("app.services.k2_agent.MAX_ITERATIONS", 20):
        await fsm.run_cycle()

    assert len(fsm.attack_graph.get("patched_nodes", [])) <= MAX_PATCHES


async def test_time_budget_forces_finalize(db_session):
    """Exceeding the wall-clock budget stops the loop and still finalizes."""
    job_id = await _seed_ready_job(db_session)

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value=json.dumps({
        "action": "tool_call", "tool": "run_nmap",
        "arguments": {"target": "target.com"},
    }))
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)
    mock_mcp = MagicMock()
    mock_mcp.run_nmap = AsyncMock(return_value={"error": None, "results": []})

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm
    fsm.mcp_client = mock_mcp
    fsm.cycle_budget_seconds = 0.0  # already over budget on first check

    final_state = await fsm.run_cycle()

    assert final_state == FSMState.COMPLETE
    assert "time_budget_exceeded" in fsm.attack_graph.get("stopped_reason", "")
    assert "report" in fsm.attack_graph
    # The model was never actually called because we were over budget instantly.
    mock_mcp.run_nmap.assert_not_called()


async def test_error_exit_still_finalizes(db_session):
    """A K2 parse error still produces a finalize + report outcome."""
    job_id = await _seed_ready_job(db_session)

    mock_llm = MagicMock()
    mock_llm.chat = AsyncMock(return_value="totally not json")
    mock_llm.token_guard = MagicMock(side_effect=lambda msgs, max_t: msgs)

    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm.llm_client = mock_llm

    final_state = await fsm.run_cycle()

    assert final_state == FSMState.COMPLETE
    assert "k2_error" in fsm.attack_graph
    assert "report" in fsm.attack_graph


# --- Pipeline phase (high-water-mark) tests ---


def test_pipeline_phase_never_regresses():
    """
    pipeline_phase only moves forward. Simulates a multi-vulnerability scan
    where the agent loops back to earlier tools (run_nmap) after already
    reaching a later phase (BLUE_TEAM_REMEDIATION). The pipeline_phase must
    stay at the high-water-mark.
    """
    fsm = OrchestratorFSM(db=MagicMock(), job_id="phase-test-job")

    assert fsm.pipeline_phase == FSMState.READY

    # run_nmap -> pipeline_phase should advance to RECON
    fsm._maybe_advance_state("run_nmap")
    assert fsm.pipeline_phase == FSMState.RECON

    # send_http_request -> DAST_TESTING
    fsm._maybe_advance_state("send_http_request")
    assert fsm.pipeline_phase == FSMState.DAST_TESTING

    # generate_patch -> BLUE_TEAM_REMEDIATION
    fsm._maybe_advance_state("generate_patch")
    assert fsm.pipeline_phase == FSMState.BLUE_TEAM_REMEDIATION

    # Now simulate next iteration: run_nmap again (earlier phase tool).
    # pipeline_phase must NOT regress.
    fsm._maybe_advance_state("run_nmap")
    assert fsm.pipeline_phase == FSMState.BLUE_TEAM_REMEDIATION

    # send_http_request again - still no regression
    fsm._maybe_advance_state("send_http_request")
    assert fsm.pipeline_phase == FSMState.BLUE_TEAM_REMEDIATION

    # execute_safe_poc (POC_VERIFICATION) - still behind BLUE_TEAM_REMEDIATION
    fsm._maybe_advance_state("execute_safe_poc")
    assert fsm.pipeline_phase == FSMState.BLUE_TEAM_REMEDIATION


async def test_pipeline_phase_persisted(db_session):
    """pipeline_phase is persisted to the DB via save_state and reloaded via hydrate_state."""
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
        pipeline_phase="ready",
        attack_graph_data={},
    )
    db_session.add(job)
    await db_session.commit()

    # Create FSM, advance pipeline_phase, save
    fsm = OrchestratorFSM(db=db_session, job_id=job_id)
    fsm._maybe_advance_state("run_nmap")
    fsm._maybe_advance_state("send_http_request")
    fsm._maybe_advance_state("generate_patch")
    assert fsm.pipeline_phase == FSMState.BLUE_TEAM_REMEDIATION

    await fsm.save_state()

    # Verify in DB
    from sqlalchemy import select as sa_select

    stmt = sa_select(AnalysisJob).where(AnalysisJob.id == job_id)
    result = await db_session.execute(stmt)
    updated_job = result.scalar_one()
    assert updated_job.pipeline_phase == "blue_team_remediation"

    # Reload via hydrate_state on a fresh FSM instance
    fsm2 = OrchestratorFSM(db=db_session, job_id=job_id)
    await fsm2.hydrate_state()
    assert fsm2.pipeline_phase == FSMState.BLUE_TEAM_REMEDIATION


def test_advance_to_complete_sets_pipeline_phase():
    """_advance_to_complete advances the FSM state to COMPLETE but intentionally
    does NOT set pipeline_phase yet -- that only happens in _finalize_and_report
    so the UI stepper stays on 'Remediation' until the report is actually done."""
    fsm = OrchestratorFSM(db=MagicMock(), job_id="complete-test")
    assert fsm.pipeline_phase == FSMState.READY
    fsm._advance_to_complete()
    assert fsm.state == FSMState.COMPLETE
    # pipeline_phase should NOT be COMPLETE yet; it is stamped in _finalize_and_report.
    assert fsm.pipeline_phase != FSMState.COMPLETE
