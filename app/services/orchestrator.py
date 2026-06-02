"""FSM-based orchestrator with K2-Think-v2 agentic loop."""
import asyncio
import os
from enum import Enum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AnalysisJob, Workspace
from app.services.ast_parser import (
    analyze_codebase,
    filter_high_risk_files,
    generate_vuln_hash,
)
from app.services.llm_client import LLMClient
from app.services.mcp_client import MCPClient

# Where imported GitHub repos are cloned (see routers/workspaces.py import-repo).
REPO_BASE_DIR = "/tmp/threatweaver"


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
        }

        # Be honest about coverage: the AST/SAST layer is Python-only today.
        if counts["python"] == 0:
            context["note"] = (
                "No Python source files were found in this repository. Static "
                "code analysis (SAST) currently supports Python only, so no "
                "code-level findings are available. Rely on the live DAST tools "
                "(run_nmap, run_fuzzer, execute_safe_poc) against the target."
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

    def _maybe_advance_state(self, tool_name: str) -> None:
        """Advance FSM state by one step based on tool used."""
        tool_to_min_state = {
            "run_nmap": FSMState.RECON,
            "run_fuzzer": FSMState.DAST_TESTING,
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
