"""FSM-based orchestrator with K2-Think-v2 agentic loop."""
import asyncio
import os
from enum import Enum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AnalysisJob, Workspace
from app.services.ast_parser import (
    analyze_codebase,
    extract_routes,
    filter_high_risk_files,
    generate_vuln_hash,
)
from app.services.llm_client import LLMClient
from app.services.mcp_client import MCPClient

# Where imported GitHub repos are cloned (see routers/workspaces.py import-repo).
REPO_BASE_DIR = "/tmp/threatweaver"

# Cognitive-fuzzing guardrail: how many non-anomalous payloads the agent may
# fire at a single endpoint before the orchestrator forces it to move on. This
# bounds the loop so a stubborn route can't burn the 60k token budget or the
# 120s gateway timeout. Stored alongside FSM state in SQLite (attack_graph).
MAX_ATTACK_ATTEMPTS = 3

# Tools that constitute an "attack attempt" against a specific endpoint and are
# therefore subject to the per-endpoint budget above.
ATTACK_TOOLS = {"send_http_request", "run_fuzzer"}


class FSMState(str, Enum):
    READY = "ready"
    RECON = "recon"
    DAST_TESTING = "dast_testing"
    POC_VERIFICATION = "poc_verification"
    BLUE_TEAM_REMEDIATION = "blue_team_remediation"
    COMPLETE = "complete"


# Valid state transitions
TRANSITIONS = {
    FSMState.READY: [FSMState.RECON],
    FSMState.RECON: [FSMState.DAST_TESTING],
    FSMState.DAST_TESTING: [FSMState.POC_VERIFICATION],
    FSMState.POC_VERIFICATION: [FSMState.BLUE_TEAM_REMEDIATION],
    FSMState.BLUE_TEAM_REMEDIATION: [FSMState.COMPLETE],
    FSMState.COMPLETE: [],
}


class OrchestratorFSM:
    """Finite State Machine orchestrator for security analysis workflow."""

    def __init__(self, db: AsyncSession, job_id: str):
        self.db = db
        self.job_id = job_id
        self.state: FSMState = FSMState.READY
        self.attack_graph: dict = {}
        self.llm_client = LLMClient()
        self.mcp_client = MCPClient()
        self._semaphore = asyncio.Semaphore(5)  # Token bucket: max 5 concurrent LLM calls
        self._seen_hashes: set[str] = set()

    async def hydrate_state(self) -> None:
        """Load current state from analysis_jobs table."""
        stmt = select(AnalysisJob).where(AnalysisJob.id == self.job_id)
        result = await self.db.execute(stmt)
        job = result.scalar_one_or_none()

        if job:
            try:
                self.state = FSMState(job.status)
            except ValueError:
                self.state = FSMState.READY
            self.attack_graph = job.attack_graph_data or {}

    async def save_state(self) -> None:
        """Persist current state back to analysis_jobs table."""
        stmt = select(AnalysisJob).where(AnalysisJob.id == self.job_id)
        result = await self.db.execute(stmt)
        job = result.scalar_one_or_none()

        if job:
            job.status = self.state.value
            job.attack_graph_data = self.attack_graph
            await self.db.commit()

    def transition(self, new_state: FSMState) -> bool:
        """Validate and execute state transition. Returns False if invalid."""
        if new_state in TRANSITIONS.get(self.state, []):
            self.state = new_state
            return True
        return False

    def is_duplicate(self, file_path: str, vuln_type: str, line_number: int) -> bool:
        """Check if vulnerability hash already exists (deduplication)."""
        h = generate_vuln_hash(file_path, vuln_type, line_number)
        if h in self._seen_hashes:
            return True
        self._seen_hashes.add(h)
        return False

    async def _get_workspace_target(self) -> str | None:
        """Retrieve the target_url for this job's workspace."""
        stmt = select(AnalysisJob).where(AnalysisJob.id == self.job_id)
        result = await self.db.execute(stmt)
        job = result.scalar_one_or_none()
        if not job:
            return None
        ws_stmt = select(Workspace).where(Workspace.id == job.workspace_id)
        ws_result = await self.db.execute(ws_stmt)
        workspace = ws_result.scalar_one_or_none()
        return workspace.target_url if workspace else None

    async def _ingest_code_context(self) -> dict | None:
        """
        Phase 1: SAST triage. Run the AST parser over the cloned repo
        (/tmp/threatweaver/<workspace_id>/repo) and return a compact,
        token-friendly summary of high-risk files for K2 to reason over.

        Returns None if no repo has been imported for this workspace.
        """
        stmt = select(AnalysisJob).where(AnalysisJob.id == self.job_id)
        result = await self.db.execute(stmt)
        job = result.scalar_one_or_none()
        if not job:
            return None

        repo_dir = os.path.join(REPO_BASE_DIR, job.workspace_id, "repo")
        if not os.path.isdir(repo_dir):
            return None

        # AST walking + filtering are CPU/IO bound; run off the event loop.
        analysis = await asyncio.to_thread(analyze_codebase, repo_dir)
        high_risk = await asyncio.to_thread(filter_high_risk_files, analysis)
        counts = await asyncio.to_thread(self._count_repo_files, repo_dir)
        routes = await asyncio.to_thread(extract_routes, repo_dir)

        summary = []
        for item in high_risk:
            try:
                rel_path = os.path.relpath(item["file_path"], repo_dir)
            except ValueError:
                rel_path = item["file_path"]
            summary.append(
                {"file": rel_path, "findings": item.get("findings", [])}
            )

        context = {
            "repo_dir": repo_dir,
            "total_files": counts["total"],
            "python_files": counts["python"],
            "high_risk_count": len(high_risk),
            "high_risk_files": summary,
            # Source-derived route map. The DAST phase attacks THESE endpoints
            # instead of guessing commodity paths.
            "routes": routes,
        }

        # Be honest about coverage: the AST/SAST layer is Python-only today.
        if counts["python"] == 0:
            context["note"] = (
                "No Python source files were found in this repository. Static "
                "code analysis (SAST) currently supports Python only, so no "
                "code-level findings are available. Rely on the live DAST tools "
                "(run_nmap, send_http_request) against the target."
            )
        return context

    @staticmethod
    def _count_repo_files(repo_dir: str) -> dict:
        """Count total files and Python files in the repo (excluding .git)."""
        total = 0
        python = 0
        for root, dirs, files in os.walk(repo_dir):
            if ".git" in dirs:
                dirs.remove(".git")
            for filename in files:
                total += 1
                if filename.endswith(".py"):
                    python += 1
        return {"total": total, "python": python}

    async def run_cycle(self) -> FSMState:
        """
        K2-driven agentic loop:
        1. Hydrate state from DB
        2. Build context for K2
        3. Loop: K2 decides -> execute -> feed back
        4. Update FSM state based on accomplished work
        5. Save to DB
        """
        from app.services.k2_agent import K2Agent, MAX_ITERATIONS
        from app.services.tool_executor import ToolExecutor

        await self.hydrate_state()

        # If already complete, nothing to do
        if self.state == FSMState.COMPLETE:
            return self.state

        target = await self._get_workspace_target()
        agent = K2Agent(llm_client=self.llm_client)
        executor = ToolExecutor(
            job_id=self.job_id, mcp_client=self.mcp_client, llm_client=self.llm_client
        )

        # Phase 1: ingest the cloned repo's source (once per job) so K2 can
        # reason about high-risk files rather than scanning blind.
        if "code_analysis" not in self.attack_graph:
            code_context = await self._ingest_code_context()
            if code_context is not None:
                self.attack_graph["code_analysis"] = code_context
                await self.save_state()

        for iteration in range(MAX_ITERATIONS):
            context = {
                "phase": self.state.value,
                "target": target,
                "attack_graph": self.attack_graph,
                "code_analysis": self.attack_graph.get("code_analysis"),
                "routes": (self.attack_graph.get("code_analysis") or {}).get("routes", []),
                "endpoint_attempts": self.attack_graph.get("endpoint_attempts", {}),
                "exhausted_endpoints": self.attack_graph.get("exhausted_endpoints", []),
                "iteration": iteration,
            }

            async with self._semaphore:
                decision = await agent.decide(context)

            action = decision.get("action")

            if action == "complete":
                # K2 says we're done - advance to COMPLETE
                self.attack_graph["k2_summary"] = decision.get("summary", "")
                self._advance_to_complete()
                break
            elif action == "tool_call":
                tool_name = decision.get("tool", "")
                arguments = decision.get("arguments", {})

                # Guardrail: refuse further attacks on an exhausted endpoint and
                # nudge the agent to pivot, without spending a real request.
                endpoint_key = self._endpoint_key(tool_name, arguments)
                if endpoint_key and self._is_endpoint_exhausted(endpoint_key):
                    note = (
                        f"Blocked: endpoint '{endpoint_key}' already hit the "
                        f"{MAX_ATTACK_ATTEMPTS}-attempt limit. Choose a different "
                        "endpoint or finish."
                    )
                    self.attack_graph.setdefault("guardrail_notes", []).append({
                        "iteration": iteration,
                        "endpoint": endpoint_key,
                        "note": note,
                    })
                    agent.feed_note(note)
                    await self.save_state()
                    continue

                result = await executor.execute(tool_name, arguments)
                # Store result in attack graph
                self.attack_graph.setdefault("tool_results", []).append({
                    "iteration": iteration,
                    "tool": tool_name,
                    "arguments": arguments,
                    "result": result,
                    "reasoning": decision.get("reasoning", ""),
                })
                # Feed result back to K2
                agent.feed_result(tool_name, result)

                # Per-endpoint attack budget: count the attempt, and if the
                # endpoint is now exhausted (or just short of it), tell the agent.
                if endpoint_key:
                    was_anomaly = self._result_is_anomaly(result)
                    note = self._record_attempt(endpoint_key, was_anomaly)
                    if note:
                        agent.feed_note(note)

                # Advance FSM state based on tool type
                self._maybe_advance_state(tool_name)
                # Checkpoint after each tool execution to prevent data loss
                await self.save_state()
            elif action == "error":
                # K2 response couldn't be parsed - break to avoid infinite loop
                self.attack_graph["k2_error"] = decision.get("detail", "Unknown error")
                break
            else:
                # Unknown action type
                break

        # Phase 6: if the analysis finished, score severity and send the alert.
        if self.state == FSMState.COMPLETE and not self.attack_graph.get(
            "notification"
        ):
            await self._finalize_and_notify()

        await self.save_state()
        return self.state

    def _advance_to_complete(self) -> None:
        """Advance FSM to COMPLETE through valid transitions."""
        state_chain = [
            FSMState.RECON, FSMState.DAST_TESTING,
            FSMState.POC_VERIFICATION, FSMState.BLUE_TEAM_REMEDIATION,
            FSMState.COMPLETE,
        ]
        for next_state in state_chain:
            if self.state == next_state:
                continue
            if not self.transition(next_state):
                break

    # --- Phase 6: severity scoring + alert routing ------------------------

    def _score_severity(self) -> str:
        """
        Grade the job's overall severity from the verified attack graph.

        Counts confirmed exploits (PoC), suspected server crashes / 5xx, and
        leaked stack traces across the recorded tool results, then maps the
        total onto Low / Medium / High / Extreme.
        """
        confirmed = 0
        anomalies = 0
        for entry in self.attack_graph.get("tool_results", []):
            result = entry.get("result") or {}
            if not isinstance(result, dict):
                continue
            if entry.get("tool") == "execute_safe_poc" and result.get(
                "exploit_confirmed"
            ):
                confirmed += 1
            if (
                result.get("is_server_error")
                or result.get("stack_trace_detected")
                or result.get("server_crash_suspected")
                or result.get("anomalies_found", 0)
            ):
                anomalies += 1

        if confirmed >= 1 and anomalies >= 3:
            return "extreme"
        if confirmed >= 1:
            return "high"
        if anomalies >= 3:
            return "high"
        if anomalies >= 1:
            return "medium"
        return "low"

    async def _finalize_and_notify(self) -> None:
        """
        Phase 6: score severity, persist it, and dispatch the email alert.

        The delivery outcome is recorded in attack_graph["notification"] so the
        result (sent / skipped / failed, with a reason) is always visible in the
        job data, even when no email goes out.
        """
        from app.services.notifier import NotifierService

        severity = self._score_severity()
        self.attack_graph["overall_severity"] = severity

        # Persist severity onto the job row too.
        stmt = select(AnalysisJob).where(AnalysisJob.id == self.job_id)
        result = await self.db.execute(stmt)
        job = result.scalar_one_or_none()
        if job:
            job.overall_severity = severity

        try:
            notifier = NotifierService(llm_client=self.llm_client)
            status = await notifier.send_alert(
                self.db, self.job_id, severity, self.attack_graph
            )
        except Exception as e:  # never let notification failure crash the job
            status = {"status": "failed", "reason": f"Notifier crashed: {e}"}

        self.attack_graph["notification"] = status

    def _maybe_advance_state(self, tool_name: str) -> None:
        """Advance FSM state by one step based on tool used."""
        tool_to_min_state = {
            "run_nmap": FSMState.RECON,
            "run_fuzzer": FSMState.DAST_TESTING,
            "send_http_request": FSMState.DAST_TESTING,
            "execute_safe_poc": FSMState.POC_VERIFICATION,
            "query_hackclub": FSMState.POC_VERIFICATION,
            "generate_patch": FSMState.BLUE_TEAM_REMEDIATION,
        }
        target_state = tool_to_min_state.get(tool_name)
        if not target_state:
            return
        # Only advance one step (the next valid state from current)
        valid_next = TRANSITIONS.get(self.state, [])
        if valid_next and self.state != target_state:
            self.transition(valid_next[0])

    # --- Per-endpoint attack guardrails -----------------------------------

    @staticmethod
    def _endpoint_key(tool_name: str, arguments: dict) -> str | None:
        """
        Derive a stable endpoint identifier for an attack tool call.

        Strips the query string so repeated attacks on the same path (with
        different payloads) count against one budget. Returns None for tools
        that aren't endpoint-scoped attacks.
        """
        if tool_name not in ATTACK_TOOLS:
            return None
        raw = arguments.get("endpoint") or arguments.get("url") or ""
        if not raw:
            return None
        # Normalise: drop query/fragment so ?a=1 and ?a=2 share a budget.
        return raw.split("?", 1)[0].split("#", 1)[0].rstrip("/") or raw

    @staticmethod
    def _result_is_anomaly(result: dict) -> bool:
        """
        Did an attack tool result trigger an anomaly worth pursuing?

        An anomaly resets the agent's "stuck" status for that endpoint - it has
        found something to dig into, so we don't penalise it under the budget.
        """
        if not isinstance(result, dict):
            return False
        # send_http_request signals.
        if result.get("is_server_error") or result.get("stack_trace_detected"):
            return True
        # run_fuzzer signal.
        if result.get("anomalies_found", 0):
            return True
        return False

    def _is_endpoint_exhausted(self, endpoint_key: str) -> bool:
        """True if this endpoint has already hit the attack-attempt budget."""
        exhausted = self.attack_graph.get("exhausted_endpoints", [])
        return endpoint_key in exhausted

    def _record_attempt(self, endpoint_key: str, was_anomaly: bool) -> str | None:
        """
        Update the per-endpoint attempt counter after an attack tool call.

        A non-anomalous attempt increments the counter; reaching
        MAX_ATTACK_ATTEMPTS marks the endpoint exhausted. An anomaly resets the
        counter (the agent has a lead to pursue). Returns a guardrail note to
        feed back to the agent, or None.
        """
        attempts = self.attack_graph.setdefault("endpoint_attempts", {})
        exhausted = self.attack_graph.setdefault("exhausted_endpoints", [])

        if was_anomaly:
            # Found something - reset the budget so the agent can keep probing
            # this lead without being cut off.
            attempts[endpoint_key] = 0
            return None

        attempts[endpoint_key] = attempts.get(endpoint_key, 0) + 1
        if attempts[endpoint_key] >= MAX_ATTACK_ATTEMPTS:
            if endpoint_key not in exhausted:
                exhausted.append(endpoint_key)
            return (
                f"Endpoint '{endpoint_key}' is exhausted: {MAX_ATTACK_ATTEMPTS} "
                "crafted payloads triggered no anomaly. Stop attacking this route "
                "and move on to a different endpoint or finish the analysis."
            )
        remaining = MAX_ATTACK_ATTEMPTS - attempts[endpoint_key]
        return (
            f"No anomaly on '{endpoint_key}' (attempt {attempts[endpoint_key]} of "
            f"{MAX_ATTACK_ATTEMPTS}, {remaining} left). Pivot your payload or move on."
        )
