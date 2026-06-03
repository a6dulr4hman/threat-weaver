"""FSM-based orchestrator with K2-Think-v2 agentic loop."""
import asyncio
import json
import os
import re
import time
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
from app.services.llm_json import extract_json_object, is_api_error
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

# Source-derived routes that are never worth attacking: the root redirect,
# logout (which just clears the session), and the ThreatWeaver ownership-
# verification endpoint. They are excluded from the coverage checklist so the
# agent isn't nudged to waste its attack budget on them and so an "all routes
# probed" finish isn't blocked waiting on them.
SKIP_ROUTE_PATHS = {"/", "/logout", "/threatweaver.txt"}

# Cap on how many remediation patches a single job may generate.
# Set to 7 to match the number of vulnerabilities in the Nimbus CRM demo target.
MAX_PATCHES = 7

# Hard wall-clock budget for a single run_cycle, in seconds.
# With K2's 30 rpm cap and 120s per-call timeout, 20 iterations realistically
# takes 2-5 minutes. Setting this to 5 minutes gives headroom while preventing
# a single stuck job from blocking the server for 10+ minutes.
# Override with CYCLE_BUDGET_SECONDS env var if needed.
DEFAULT_CYCLE_BUDGET_SECONDS = float(
    os.getenv("CYCLE_BUDGET_SECONDS", "300")
)


# System prompt for the FINAL assessment pass. After the agentic loop ends, we
# hand K2-Think-v2 a compact digest of everything the scan observed and ask it
# to act as the lead assessor: count the vulnerabilities, rate each one, and
# write the executive verdict. It must reason ONLY from the supplied evidence.
FINAL_ASSESSMENT_PROMPT = """You are K2-Think-v2 acting as the lead security \
assessor writing the FINAL verdict for an automated penetration test. You are \
given a JSON digest of everything the autonomous scan actually did and observed \
against ONE target: recon services, every exploitation signal it triggered, \
confirmed sandbox PoCs, and any patches it generated.

Produce a concise, accurate vulnerability assessment. Base EVERY conclusion \
STRICTLY on the supplied evidence. Do NOT invent vulnerabilities the evidence \
does not support, and never rate a service/version as vulnerable without an \
observed exploitation signal. If the scan observed nothing exploitable, say so \
honestly with total_vulnerabilities = 0 and overall_risk "Informational".

Reply with EXACTLY ONE JSON object and nothing else (no prose, no markdown):
{
  "total_vulnerabilities": <integer>,
  "overall_risk": "Critical" | "High" | "Medium" | "Low" | "Informational",
  "executive_summary": "<2-4 sentence plain-English verdict for a CISO>",
  "vulnerabilities": [
    {
      "name": "<short title, e.g. 'SQLi authentication bypass on /login'>",
      "category": "<class, e.g. 'SQL Injection', 'Path Traversal', 'OS Command Injection', 'Broken Authentication'>",
      "endpoint": "<method + path it was observed on>",
      "severity": "Critical" | "High" | "Medium" | "Low",
      "cvss": <number 0.0-10.0>,
      "confidence": "Confirmed" | "Likely" | "Possible",
      "evidence": "<the concrete observation that proves it>",
      "impact": "<what an attacker gains>",
      "remediation": "<the fix in one sentence>"
    }
  ]
}
Order vulnerabilities from most to least severe. Be factual and specific."""


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
        self.cycle_budget_seconds = DEFAULT_CYCLE_BUDGET_SECONDS

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

        deadline = time.monotonic() + self.cycle_budget_seconds
        try:
            for iteration in range(MAX_ITERATIONS):
                # Wall-clock guardrail: a slow reasoning model (30 rpm, 120s per
                # call) can otherwise run far longer than any caller expects.
                # Stop cleanly and let the finally block finalize + notify.
                if time.monotonic() >= deadline:
                    self.attack_graph["stopped_reason"] = (
                        "time_budget_exceeded after "
                        f"{int(self.cycle_budget_seconds)}s"
                    )
                    break

                context = {
                    "phase": self.state.value,
                    "target": target,
                    "attack_graph": self._slim_attack_graph(),
                    "code_analysis": self.attack_graph.get("code_analysis"),
                    "routes": (self.attack_graph.get("code_analysis") or {}).get("routes", []),
                    # Source-derived coverage checklist: which routes still need
                    # probing. This is what DRIVES the loop — see build_state_message.
                    "route_progress": self._route_progress(),
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

                    # Guardrail: refuse further attacks on an exhausted endpoint
                    # and nudge the agent to pivot, without spending a request.
                    endpoint_key = self._endpoint_key(tool_name, arguments)
                    if endpoint_key and self._is_endpoint_exhausted(endpoint_key):
                        note = (
                            f"Blocked: endpoint '{endpoint_key}' already hit the "
                            f"{MAX_ATTACK_ATTEMPTS}-attempt limit. Choose a "
                            "different endpoint or finish."
                        )
                        self.attack_graph.setdefault("guardrail_notes", []).append({
                            "iteration": iteration,
                            "endpoint": endpoint_key,
                            "note": note,
                        })
                        agent.feed_note(note)
                        await self.save_state()
                        continue

                    # Guardrail: cap PoC verification to prevent the agent
                    # from looping on execute_safe_poc indefinitely.
                    # Each call runs a 30s subprocess; 10 calls = 5 minutes
                    # stuck at the PoC Verify step before any other check fires.
                    if tool_name == "execute_safe_poc":
                        poc_count = self.attack_graph.get("poc_attempts", 0)
                        sandbox_id = (arguments.get("sandbox_id") or "").strip()
                        completed_pocs = self.attack_graph.get("completed_pocs", [])
                        if sandbox_id and sandbox_id in completed_pocs:
                            agent.feed_note(
                                f"PoC '{sandbox_id}' already ran. Do not repeat it. "
                                "Move to generate_patch if confirmed, or finish."
                            )
                            await self.save_state()
                            continue
                        if poc_count >= 3:
                            agent.feed_note(
                                "PoC verification budget reached (3 attempts). "
                                "Accept the evidence you have and move to "
                                "generate_patch or finish."
                            )
                            await self.save_state()
                            continue

                    # Guardrail: bound remediation so the agent can't loop
                    # forever on generate_patch. Also enforce that patches are
                    # only generated for findings that were actually observed
                    # on this target — not invented from service banners.
                    if tool_name == "generate_patch":
                        patched = self.attack_graph.setdefault("patched_nodes", [])
                        vuln_node = (arguments.get("vuln_node") or "").strip()

                        # Reject hallucinated patches: require at least one
                        # tool_result entry that recorded a real anomaly.
                        if not self._has_observed_finding():
                            agent.feed_note(
                                "generate_patch BLOCKED: no confirmed finding on "
                                "this target. A patch is only justified after "
                                "send_http_request returned is_server_error=true / "
                                "server_crash_suspected=true, or execute_safe_poc "
                                "returned exploit_confirmed=true."
                            )
                            await self.save_state()
                            continue

                        if vuln_node and vuln_node in patched:
                            agent.feed_note(
                                f"'{vuln_node}' is already patched. "
                                'Finish now with {"action": "complete", "summary": "..."}.'
                            )
                            await self.save_state()
                            continue

                        # Hard cap: only 1 patch per run. After one patch K2
                        # almost always loops trying to patch more things.
                        # The 300s budget catches the rest, but forcing
                        # complete after the first patch is cleaner and faster.
                        if len(patched) >= MAX_PATCHES:
                            agent.feed_note(
                                f"Remediation budget reached ({MAX_PATCHES} patches). "
                                'Finish now with {"action": "complete", "summary": "..."}.'
                            )
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

                    # Record a successfully patched node (dedup + budget above)
                    # and persist the full structured finding to the mitigations
                    # table (description, risk, CVEs, recommendation + code).
                    if tool_name == "generate_patch" and not result.get("error"):
                        vuln_node = (arguments.get("vuln_node") or "").strip()
                        if vuln_node:
                            self.attack_graph.setdefault(
                                "patched_nodes", []
                            ).append(vuln_node)
                            await self._store_mitigation(vuln_node, result)

                        # Coverage driver: after a patch, push K2 toward the
                        # next UNPROBED source-derived route instead of looping
                        # on more patches. The route map (not HTML links) is the
                        # authoritative attack surface. endpoint_attempts keys
                        # are full URLs while route entries are paths, so
                        # _unprobed_routes() normalises before comparing.
                        all_routes = (
                            self.attack_graph.get("code_analysis") or {}
                        ).get("routes", [])
                        remaining = self._unprobed_routes()

                        # Only finish on coverage grounds when a route map EXISTS
                        # and is genuinely exhausted. With no route map there is
                        # nothing to exhaust — keep going and let the iteration /
                        # time / patch budgets bound the run, rather than quitting
                        # the instant an empty/missing list looks "done" (the bug
                        # that capped live scans at a single finding).
                        if all_routes and not remaining:
                            summary = (
                                self.attack_graph.get("k2_summary")
                                or "Analysis complete. All source-derived routes probed."
                            )
                            self.attack_graph["k2_summary"] = summary
                            self._advance_to_complete()
                            await self.save_state()
                            break

                        if remaining:
                            remaining_desc = ", ".join(
                                f"{r['path']} [{','.join(r.get('methods', []))}]"
                                + (" (AUTH)" if r.get("requires_auth") else "")
                                for r in remaining[:6]
                            )
                            agent.feed_note(
                                f"Patch stored for '{vuln_node}'. "
                                f"{len(remaining)} source-derived route(s) are still "
                                f"UNPROBED — probe them next: {remaining_desc}. "
                                "Authenticate first for routes marked (AUTH); the "
                                "session cookie persists across requests. Do NOT call "
                                "generate_patch again until a NEW anomaly is triggered."
                            )
                        else:
                            agent.feed_note(
                                f"Patch stored for '{vuln_node}'. No source-derived "
                                "route map is available — keep probing any endpoints "
                                "you still have evidence for, then finish when no "
                                "useful action remains."
                            )

                    # Track PoC attempts so the guardrail above can cap them.
                    if tool_name == "execute_safe_poc":
                        self.attack_graph["poc_attempts"] = (
                            self.attack_graph.get("poc_attempts", 0) + 1
                        )
                        sandbox_id = (arguments.get("sandbox_id") or "").strip()
                        if sandbox_id:
                            self.attack_graph.setdefault(
                                "completed_pocs", []
                            ).append(sandbox_id)

                    # Per-endpoint attack budget: count the attempt; if the
                    # endpoint is now exhausted (or close), tell the agent.
                    if endpoint_key:
                        finding = self._dast_finding(tool_name, arguments, result)
                        was_anomaly = finding is not None
                        # A success-based finding (auth bypass, file read, RCE)
                        # is itself confirmation: the live response already
                        # proves exploitation. Nudge K2 to record it NOW instead
                        # of hunting for a server error that will never come.
                        if finding and finding not in ("server_error", "fuzz_anomaly"):
                            agent.feed_note(
                                f"CONFIRMED FINDING ({finding}) on '{endpoint_key}': "
                                "the live response proves the exploit SUCCEEDED "
                                "(a 200 OK success, not a server error). That is "
                                "sufficient evidence — call generate_patch for this "
                                "flaw now. You do NOT need a separate execute_safe_poc "
                                "to confirm an already-successful exploit."
                            )
                        note = self._record_attempt(endpoint_key, was_anomaly)
                        if note:
                            agent.feed_note(note)

                    # Advance FSM state based on tool type
                    self._maybe_advance_state(tool_name)
                    # Checkpoint after each tool execution to prevent data loss
                    await self.save_state()
                elif action == "error":
                    # K2 response couldn't be parsed - break to avoid an
                    # infinite loop.
                    self.attack_graph["k2_error"] = decision.get(
                        "detail", "Unknown error"
                    )
                    break
                else:
                    # Unknown action type
                    break
        finally:
            # ALWAYS finalize: score severity and generate the PDF report,
            # regardless of HOW the loop ended (complete, error, time budget,
            # max iterations, or an unexpected exception). This guarantees a
            # report is produced for every run - the bug that left jobs silently
            # hung with no output.
            await self._ensure_finalized()

        await self.save_state()
        return self.state

    def _slim_attack_graph(self) -> dict:
        """
        Return a token-efficient view of the attack graph for K2's context.

        Full HTTP response bodies (2-4KB each) accumulate fast and fill the
        60k context window after ~10 iterations. K2 doesn't need the full body
        history — it just needs to know what was tried, what was anomalous, and
        whether the finding was confirmed. Strip bodies; keep signals.
        """
        slim_results = []
        for entry in self.attack_graph.get("tool_results", []):
            result = entry.get("result") or {}
            tool = entry.get("tool", "")
            slim_result = {}

            if tool in ("send_http_request",):
                # Keep signals, drop the body (can be 3KB of HTML).
                slim_result = {
                    k: v for k, v in result.items()
                    if k not in ("body", "response_headers")
                }
            elif tool == "execute_safe_poc":
                # Keep confirmation signal, drop full trace (can be huge).
                slim_result = {
                    "exploit_confirmed": result.get("exploit_confirmed"),
                    "match_detail": result.get("match_detail"),
                    "error": result.get("error"),
                }
            elif tool == "generate_patch":
                # Keep metadata, drop the full code (saved to DB already).
                slim_result = {
                    k: v for k, v in result.items() if k != "patch"
                }
            else:
                slim_result = result

            slim_results.append({
                "iteration": entry.get("iteration"),
                "tool": tool,
                "arguments": entry.get("arguments"),
                "result": slim_result,
                "reasoning": entry.get("reasoning"),
            })

        return {
            k: (slim_results if k == "tool_results" else v)
            for k, v in self.attack_graph.items()
            if k not in ("code_analysis",)  # code_analysis passed separately
        }

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
        Grade the job's overall severity.

        Priority order:
        1. Highest risk_level from generate_patch results (most accurate — K2
           assessed the actual vulnerability type and business impact).
        2. SAST high-risk file count from code analysis.
        3. Raw DAST anomaly/confirmed-exploit counts as a fallback.
        """
        risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        highest_patch_risk = 0
        confirmed = 0
        anomalies = 0

        for entry in self.attack_graph.get("tool_results", []):
            result = entry.get("result") or {}
            if not isinstance(result, dict):
                continue
            tool = entry.get("tool", "")

            if tool == "generate_patch":
                level = str(result.get("risk_level", "")).lower()
                highest_patch_risk = max(
                    highest_patch_risk, risk_order.get(level, 0)
                )
            elif tool == "execute_safe_poc" and result.get("exploit_confirmed"):
                confirmed += 1
            elif tool in ("send_http_request", "run_fuzzer") and self._dast_finding(
                tool, entry.get("arguments") or {}, result
            ):
                anomalies += 1

        # Patch-derived risk is most trustworthy — use it if available.
        if highest_patch_risk >= 4:
            return "extreme"
        if highest_patch_risk == 3:
            return "high"
        if highest_patch_risk == 2:
            return "medium"

        # SAST-derived: many high-risk files → at least high severity.
        sast_high = (self.attack_graph.get("code_analysis") or {}).get(
            "high_risk_count", 0
        )
        if sast_high >= 3:
            return "high"

        # DAST fallback.
        if confirmed >= 1 and anomalies >= 3:
            return "extreme"
        if confirmed >= 1:
            return "high"
        if anomalies >= 3:
            return "high"
        if anomalies >= 1:
            return "medium"
        return "low"

    async def _ensure_finalized(self) -> None:
        """
        Finalize the job on ANY loop exit (complete / error / timeout / max
        iterations / exception), exactly once.

        This is the safety net that guarantees a severity score and a report
        are always produced - the gap that previously left a stuck job with no
        output. It also forces the FSM to COMPLETE so the outer driver loop in
        the jobs router stops re-running a finished job.
        """
        if self.attack_graph.get("report"):
            return  # already finalized in this or a prior cycle
        # Drive the FSM to COMPLETE regardless of where it stalled.
        if self.state != FSMState.COMPLETE:
            self._advance_to_complete()
        await self._finalize_and_report()

    async def _store_mitigation(self, vuln_node: str, result: dict) -> None:
        """
        Persist a structured finding to the mitigations table (best-effort).

        `result` is the dict returned by ToolExecutor._exec_patch, which now
        contains: vuln_node, patch (code), description, risk_level, cves,
        recommendation.
        """
        from app.services.remediation import RemediationService

        code = RemediationService.clean_patch(result.get("patch", ""))
        metadata = {
            "description":    result.get("description", ""),
            "risk_level":     result.get("risk_level", "High"),
            "cves":           result.get("cves", []),
            "recommendation": result.get("recommendation", ""),
        }
        try:
            from app.models import Mitigation
            import uuid as _uuid
            mitigation = Mitigation(
                id=str(_uuid.uuid4()),
                job_id=self.job_id,
                vulnerability_node=vuln_node,
                remediation_code=code,
                finding_metadata=metadata,
            )
            self.db.add(mitigation)
            await self.db.commit()
        except Exception:
            # Storage failure must not crash the analysis loop.
            pass

    async def _finalize_and_report(self) -> None:
        """
        Phase 6: score severity, persist it, and generate the PDF report.

        The outcome is recorded in attack_graph["report"] (status + path) so the
        result is always visible in the job data and the UI can offer a download.
        """
        import logging
        _log = logging.getLogger(__name__)

        from app.services.report import ReportService

        severity = self._score_severity()
        self.attack_graph["overall_severity"] = severity

        # Final K2 verdict: enumerate + rate the vulnerabilities from the
        # evidence gathered this run. Best-effort — never blocks finalization
        # or the report if the model/network is unavailable (returns None).
        assessment = await self._generate_final_assessment()
        if assessment:
            self.attack_graph["final_assessment"] = assessment

        # Persist severity onto the job row too.
        stmt = select(AnalysisJob).where(AnalysisJob.id == self.job_id)
        result = await self.db.execute(stmt)
        job = result.scalar_one_or_none()
        if job:
            job.overall_severity = severity

        try:
            report_svc = ReportService()
            # Expire the session cache so _load_mitigations sees the rows that
            # _store_mitigation committed earlier in the same scan loop.
            self.db.expire_all()
            # Enforce a hard timeout on PDF generation so a reportlab crash or
            # hang can't block the background task indefinitely.
            path = await asyncio.wait_for(
                report_svc.generate(self.db, self.job_id, severity, self.attack_graph),
                timeout=60.0,
            )
            status = {"status": "generated", "path": path, "severity": severity}
        except asyncio.TimeoutError:
            status = {"status": "failed", "reason": "PDF generation timed out (60s)"}
            _log.error("PDF generation timed out for job %s", self.job_id)
        except Exception as e:
            status = {"status": "failed", "reason": f"Report generation failed: {e}"}
            _log.exception("PDF generation failed for job %s", self.job_id)

        self.attack_graph["report"] = status

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

    # --- Success-based exploitation detection -----------------------------
    # The error-based signals above (5xx / stack trace / connection drop) only
    # catch vulnerabilities that CRASH the app. Most real-world exploits SUCCEED
    # quietly with a 200 OK: an auth bypass returns a valid session, a path
    # traversal returns file contents, a command injection returns command
    # output. These detectors read that "exploitation succeeded" evidence
    # straight from the live response, so such findings get recorded and patched
    # instead of being missed while waiting for a server error that never comes.

    # Injection metacharacters that mark a submitted value as an injection
    # ATTEMPT (used to qualify an auth-bypass observation, so a normal login
    # with valid credentials is never mistaken for a bypass).
    _INJECTION_MARKERS = ("'", '"', "--", "/*", "#", ";", " or ", " union ", " and ")

    @staticmethod
    def _looks_like_file_disclosure(body: str) -> bool:
        """Response leaked the contents of a sensitive file (path traversal / LFI)."""
        if not body:
            return False
        low = body.lower()
        # /etc/passwd
        if "root:x:0:0:" in low or "root:!:0:0:" in low:
            return True
        if "daemon:x:" in low and "nologin" in low:
            return True
        # Private keys
        if "-----begin" in low and "private key-----" in low:
            return True
        return False

    @staticmethod
    def _looks_like_command_output(body: str) -> bool:
        """Response contains the output of an injected OS command (RCE)."""
        if not body:
            return False
        # `id` -> uid=0(root) gid=0(root) groups=...
        if re.search(r"uid=\d+\([\w.-]+\)\s+gid=\d+\(", body):
            return True
        # `ping`/`traceroute` output reflected from a host parameter.
        low = body.lower()
        if "bytes from" in low and ("icmp_seq=" in low or "ttl=" in low):
            return True
        return False

    @classmethod
    def _looks_like_auth_bypass(cls, arguments: dict, result: dict) -> bool:
        """
        A credential submission carrying injection metacharacters that yields an
        authenticated session — i.e. a SQLi/auth-bypass login succeeded.

        Deliberately narrow to avoid false positives: it requires an auth-style
        endpoint, injection characters in the submitted values, a non-error
        status, an authenticated landing page (or a redirect away from login),
        and the ABSENCE of a failed-login error in the body.
        """
        endpoint = (arguments.get("endpoint") or arguments.get("url") or "").lower()
        if not any(tok in endpoint for tok in ("login", "signin", "sign-in", "auth")):
            return False
        creds: dict = {}
        for src in (
            arguments.get("form_data"),
            arguments.get("json_body"),
            arguments.get("params"),
        ):
            if isinstance(src, dict):
                creds.update(src)
        blob = " ".join(str(v) for v in creds.values()).lower()
        if not blob or not any(m in blob for m in cls._INJECTION_MARKERS):
            return False
        if result.get("status_code", 0) not in (200, 301, 302, 303, 307, 308):
            return False
        body = (result.get("body") or "").lower()
        # A failed login re-renders the form with an error — never a bypass.
        if any(f in body for f in ("invalid", "incorrect", "failed", "try again")):
            return False
        # Authenticated landing-page markers.
        if any(s in body for s in ("logout", "sign out", "signout", "dashboard")):
            return True
        # A redirect away from the login page also implies a session was granted.
        loc = (result.get("response_headers") or {}).get("location", "").lower()
        if loc and "login" not in loc:
            return True
        return False

    def _dast_finding(self, tool: str, arguments: dict, result: dict) -> str | None:
        """
        Classify a DAST tool result as a concrete finding, or None.

        Covers BOTH error-based exploitation (server crash / stack trace) and
        success-based exploitation (auth bypass, file disclosure, command
        execution). This is the single source of truth used by the per-endpoint
        anomaly budget, the patch-gating guard (_has_observed_finding) and
        severity scoring, so all three agree on what counts as a real finding.
        """
        if tool not in ("send_http_request", "run_fuzzer") or not isinstance(result, dict):
            return None
        if self._result_is_anomaly(result) or result.get("server_crash_suspected"):
            return "fuzz_anomaly" if result.get("anomalies_found", 0) else "server_error"
        body = result.get("body") or ""
        if self._looks_like_file_disclosure(body):
            return "sensitive_file_disclosure"
        if self._looks_like_command_output(body):
            return "os_command_execution"
        if self._looks_like_auth_bypass(arguments or {}, result):
            return "auth_bypass"
        return None

    def _is_endpoint_exhausted(self, endpoint_key: str) -> bool:
        """True if this endpoint has already hit the attack-attempt budget."""
        exhausted = self.attack_graph.get("exhausted_endpoints", [])
        return endpoint_key in exhausted

    def _has_observed_finding(self) -> bool:
        """
        Return True only if the current scan has recorded at least one real,
        network-observed finding on this target via DAST tools.

        Used to gate generate_patch calls. Only DAST tool results count
        (send_http_request / run_fuzzer) — NOT execute_safe_poc, because PoC is
        a verification step for an already-observed anomaly, not a discovery
        tool. Without this distinction, K2 could run a fabricated PoC script
        (e.g. ssh_poc_1) that self-confirms via crash markers, then generate
        patches for invented CVEs.

        A "finding" is either error-based (5xx / stack trace / dropped
        connection) OR success-based (auth bypass, sensitive-file disclosure,
        OS-command output) — see _dast_finding. Recognising the success-based
        cases is essential: most real exploits return 200 OK, not a crash.
        """
        for entry in self.attack_graph.get("tool_results", []):
            result = entry.get("result") or {}
            if not isinstance(result, dict):
                continue
            tool = entry.get("tool", "")
            if self._dast_finding(tool, entry.get("arguments") or {}, result):
                return True
        return False

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

    # --- Source-derived route coverage ------------------------------------

    @staticmethod
    def _url_to_path(url: str) -> str:
        """
        Reduce a full URL (or bare path) to its path component, dropping the
        scheme, host, query string and fragment.

        endpoint_attempts is keyed by full URLs (e.g. "http://host/customer/5")
        while the route map is keyed by paths (e.g. "/customer/<cid>"), so both
        must be normalised to path form before they can be compared.
        """
        if not url:
            return "/"
        s = url.split("?", 1)[0].split("#", 1)[0]
        if "://" in s:
            s = s.split("://", 1)[1]
            slash = s.find("/")
            s = s[slash:] if slash != -1 else "/"
        if not s.startswith("/"):
            s = "/" + s
        return s

    @staticmethod
    def _route_path_matches(route_path: str, candidate_path: str) -> bool:
        """
        True if a concrete URL path matches a source-derived route template.

        Flask `<cid>` / `<int:cid>` and FastAPI `{item_id}` path parameters are
        treated as single-segment wildcards, so e.g. the probed path
        "/customer/5" matches the route template "/customer/<cid>".
        """
        rp = (route_path or "/").rstrip("/") or "/"
        cp = (candidate_path or "/").rstrip("/") or "/"
        placeholder = "WILDCARDSEG"
        templated = re.sub(r"<[^>]+>|\{[^}]+\}", placeholder, rp)
        pattern = "^" + re.escape(templated).replace(placeholder, r"[^/]+") + "$"
        return re.match(pattern, cp) is not None

    def _probed_url_paths(self) -> set[str]:
        """Path-normalised set of every endpoint that has seen an HTTP attempt."""
        return {
            self._url_to_path(key)
            for key in self.attack_graph.get("endpoint_attempts", {})
        }

    def _unprobed_routes(self) -> list[dict]:
        """
        Source-derived routes that have NOT yet been hit by a real HTTP attempt.

        Returns [] when no route map exists (there is nothing to drive coverage
        from). Skips the non-attackable routes in SKIP_ROUTE_PATHS.
        """
        all_routes = (self.attack_graph.get("code_analysis") or {}).get("routes", [])
        if not all_routes:
            return []
        probed = self._probed_url_paths()
        remaining = []
        for route in all_routes:
            path = route.get("path", "")
            if not path or path in SKIP_ROUTE_PATHS:
                continue
            if any(self._route_path_matches(path, p) for p in probed):
                continue
            remaining.append(route)
        return remaining

    def _route_progress(self) -> dict | None:
        """
        Build the per-iteration coverage checklist that makes the source-derived
        route map the EXPLICIT driver of the agent loop (instead of the agent
        following links it happens to see in HTML responses).

        Returns None when there is no route map to drive from, so the agent
        falls back to live DAST against the target.
        """
        all_routes = (self.attack_graph.get("code_analysis") or {}).get("routes", [])
        if not all_routes:
            return None
        attackable = [
            r for r in all_routes if r.get("path") not in SKIP_ROUTE_PATHS
        ]
        unprobed = self._unprobed_routes()
        return {
            "total_routes": len(all_routes),
            "attackable_routes": len(attackable),
            "probed": max(0, len(attackable) - len(unprobed)),
            "unprobed_count": len(unprobed),
            "unprobed_routes": [
                {
                    "path": r.get("path"),
                    "methods": r.get("methods", []),
                    "requires_auth": bool(r.get("requires_auth")),
                }
                for r in unprobed
            ],
        }

    # --- Final K2 vulnerability assessment --------------------------------

    async def _build_assessment_evidence(self) -> dict:
        """
        Assemble a compact, token-friendly digest of everything the scan
        observed, for the final K2 assessment pass. Includes only signals
        (not full HTML bodies): recon services, the exploitation findings our
        detectors recognised, confirmed PoCs, generated patches, the route map
        and which endpoints were probed.
        """
        observed: list[dict] = []
        recon_services: list[dict] = []
        confirmed_pocs: list[dict] = []

        for entry in self.attack_graph.get("tool_results", []):
            tool = entry.get("tool", "")
            result = entry.get("result") or {}
            args = entry.get("arguments") or {}
            if not isinstance(result, dict):
                continue

            if tool == "run_nmap":
                for svc in result.get("results", []) or []:
                    recon_services.append({
                        "port": svc.get("port"),
                        "service": svc.get("service"),
                        "version": svc.get("version"),
                    })
                continue

            label = self._dast_finding(tool, args, result)
            if label:
                observed.append({
                    "type": label,
                    "method": args.get("method"),
                    "endpoint": args.get("endpoint") or args.get("url"),
                    "payload": args.get("params")
                    or args.get("form_data")
                    or args.get("json_body"),
                    "status_code": result.get("status_code"),
                    "evidence": (result.get("telemetry") or "")[:300],
                })

            if tool == "execute_safe_poc" and result.get("exploit_confirmed"):
                confirmed_pocs.append({
                    "sandbox_id": args.get("sandbox_id"),
                    "detail": (result.get("match_detail") or "")[:300],
                })

        routes = (self.attack_graph.get("code_analysis") or {}).get("routes", [])
        return {
            "target": await self._get_workspace_target(),
            "heuristic_severity": self._score_severity(),
            "recon_services": recon_services,
            "observed_exploitation_signals": observed,
            "confirmed_pocs": confirmed_pocs,
            "patches_generated": self.attack_graph.get("patched_nodes", []),
            "endpoints_probed": list(
                self.attack_graph.get("endpoint_attempts", {}).keys()
            ),
            "route_map": [r.get("path") for r in routes],
            "agent_summary": self.attack_graph.get("k2_summary", ""),
        }

    async def _generate_final_assessment(self) -> dict | None:
        """
        Final pass: hand K2-Think-v2 a digest of everything the scan observed
        and ask it to enumerate and rate the vulnerabilities (count, severity,
        CVSS, impact, remediation).

        Best-effort and offline-safe:
        - Uses its OWN LLMClient so it never disturbs a mocked self.llm_client
          (and its call-count assertions) in unit tests.
        - Skipped entirely when no API key is configured (e.g. tests / local
          runs without K2 credentials).
        - Bounded by a timeout and never propagates an exception, so a slow or
          unavailable model can't block finalization or the PDF report.
        """
        client = LLMClient()
        if not client.api_key:
            return None
        try:
            evidence = await self._build_assessment_evidence()
            messages = [
                {"role": "system", "content": FINAL_ASSESSMENT_PROMPT},
                {"role": "user", "content": json.dumps(evidence, default=str)},
            ]
            raw = await asyncio.wait_for(
                client.chat(messages, role="agent"), timeout=120.0
            )
        except Exception:
            return None
        if not isinstance(raw, str) or is_api_error(raw):
            return None
        parsed = extract_json_object(raw)
        if not isinstance(parsed, dict) or "total_vulnerabilities" not in parsed:
            return None
        return parsed
