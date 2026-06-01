"""FSM-based orchestrator with DB state hydration and token bucket."""
import asyncio
from enum import Enum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AnalysisJob, Workspace
from app.services.ast_parser import generate_vuln_hash
from app.services.llm_client import LLMClient
from app.services.mcp_client import MCPClient


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

    async def _run_recon(self) -> None:
        """READY -> RECON: run nmap against the workspace target."""
        target = await self._get_workspace_target()
        if not target:
            return
        async with self._semaphore:
            scan_results = await self.mcp_client.run_nmap(target, "1-1024")
        self.attack_graph["recon"] = scan_results
        self.transition(FSMState.RECON)

    async def _run_dast(self) -> None:
        """RECON -> DAST_TESTING: run fuzzer against discovered services."""
        target = await self._get_workspace_target()
        if not target:
            self.transition(FSMState.DAST_TESTING)
            return
        # Build basic payload matrix from recon results
        recon_data = self.attack_graph.get("recon", {})
        services = recon_data.get("results", [])
        payloads = [{"param": "test", "value": f"<script>alert({i})</script>"} for i in range(min(len(services), 5))]
        if not payloads:
            payloads = [{"param": "test", "value": "<script>alert(1)</script>"}]
        async with self._semaphore:
            fuzz_results = await self.mcp_client.run_fuzzer(
                f"https://{target}", payloads, "query"
            )
        self.attack_graph["dast"] = fuzz_results
        self.transition(FSMState.DAST_TESTING)

    async def _run_poc_verification(self) -> None:
        """DAST_TESTING -> POC_VERIFICATION: execute safe PoC for each finding."""
        findings = self.attack_graph.get("dast", {}).get("results", [])
        verified = []
        for finding in findings:
            if finding.get("anomaly_detected"):
                async with self._semaphore:
                    poc_result = await self.mcp_client.execute_safe_poc(
                        sandbox_environment_id=self.job_id,
                        script_payload="print('poc_marker')",
                        expected_telemetry_signature={"marker": "poc_marker"},
                    )
                verified.append(poc_result)
        self.attack_graph["poc_results"] = verified
        self.transition(FSMState.POC_VERIFICATION)

    async def _run_remediation(self) -> None:
        """POC_VERIFICATION -> BLUE_TEAM_REMEDIATION: generate remediations."""
        from app.services.remediation import RemediationService

        remediation_svc = RemediationService(llm_client=self.llm_client)
        poc_results = self.attack_graph.get("poc_results", [])
        remediations = []
        for poc in poc_results:
            if poc.get("exploit_confirmed"):
                async with self._semaphore:
                    patch = await remediation_svc.generate_patch(
                        job_id=self.job_id,
                        vuln_node="verified_exploit",
                        source_code=poc.get("trace", ""),
                    )
                remediations.append(patch)
        self.attack_graph["remediations"] = remediations
        self.transition(FSMState.BLUE_TEAM_REMEDIATION)

    async def _finalize(self) -> None:
        """BLUE_TEAM_REMEDIATION -> COMPLETE: mark analysis complete."""
        self.transition(FSMState.COMPLETE)

    async def run_cycle(self) -> FSMState:
        """
        Execute one FSM cycle:
        1. Hydrate state from DB
        2. Based on current state, dispatch to appropriate phase handler
        3. Save state back to DB
        4. Return new state
        """
        await self.hydrate_state()

        if self.state == FSMState.READY:
            await self._run_recon()
        elif self.state == FSMState.RECON:
            await self._run_dast()
        elif self.state == FSMState.DAST_TESTING:
            await self._run_poc_verification()
        elif self.state == FSMState.POC_VERIFICATION:
            await self._run_remediation()
        elif self.state == FSMState.BLUE_TEAM_REMEDIATION:
            await self._finalize()

        await self.save_state()
        return self.state
