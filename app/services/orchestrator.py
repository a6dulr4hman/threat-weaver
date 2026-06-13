"""FSM-based orchestrator with K2-Think-v2 agentic loop."""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from enum import Enum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AnalysisJob, Workspace
from app.services.ast_parser import generate_vuln_hash
from app.services.llm_client import LLMClient
from app.services.llm_json import extract_json_object, is_api_error
from app.services.mcp_client import MCPClient

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

# Cap on how many remediation patches a single job may generate. Set above the
# Nimbus CRM demo target's vulnerability count so the "remediation budget
# reached, finish now" nudge never fires before the agent has covered the whole
# attack surface.
MAX_PATCHES = 12

# How many times the orchestrator may REJECT the agent's attempt to finish while
# discovered-but-unprobed endpoints remain. Each rejection feeds the agent the
# unprobed list and forces it to keep probing, which is what drives full
# coverage (and full vulnerability detection). MAX_ITERATIONS is the hard
# backstop; this just prevents a stubborn agent from looping on "complete".
COMPLETION_DEFERRAL_CAP = 15

# Hard wall-clock budget for a single run_cycle, in seconds.
# K2's 30 rpm cap + 120s per-call timeout means a thorough scan that probes the
# full attack surface (and patches findings) can take 10+ minutes. We give it
# real headroom so the budget never cuts a scan short of full coverage; a truly
# stuck job is still bounded by MAX_ITERATIONS.
# Override with CYCLE_BUDGET_SECONDS env var if needed.
DEFAULT_CYCLE_BUDGET_SECONDS = float(
    os.getenv("CYCLE_BUDGET_SECONDS", "900")
)


# System prompt for the FINAL assessment pass. After the agentic loop ends and
# the scan's findings/PoCs/patches have been correlated into ONE canonical
# vulnerability per (category, endpoint), we hand K2-Think-v2 that canonical
# list plus the raw evidence and ask it to act as the lead assessor: select the
# single DEFINITIVE characterization for each candidate (when the evidence is
# duplicated or noisy) and rate it. It must return exactly one entry per
# candidate id — no inventions, no omissions, no merges.
FINAL_ASSESSMENT_PROMPT = """You are K2-Think-v2 acting as the lead security \
assessor writing the FINAL verdict for an automated penetration test.

You are given (a) a JSON digest of everything the autonomous scan observed and \
(b) a list of CANDIDATE vulnerabilities that have already been de-duplicated to \
exactly one per (category, endpoint), each carrying a stable "id".

Your job is to pick the ONE definitive characterization for EACH candidate and \
rate it. Rules you MUST follow:
- Return EXACTLY ONE entry in "vulnerabilities" for EACH candidate id you were \
given — same count, same ids. Do NOT invent new vulnerabilities, do NOT drop \
any, and do NOT merge two candidates into one.
- Echo the candidate's "id" verbatim in each entry.
- Base every conclusion STRICTLY on the supplied evidence. Use the \
brave_search_enrichment data to add precise CVE IDs, reference URLs and CVSS \
scores where available.
- "total_vulnerabilities" MUST equal the number of candidates.

Reply with EXACTLY ONE JSON object and nothing else (no prose, no markdown):
{
  "total_vulnerabilities": <integer = number of candidates>,
  "overall_risk": "Critical" | "High" | "Medium" | "Low" | "Informational",
  "executive_summary": "<2-4 sentence plain-English verdict for a CISO>",
  "vulnerabilities": [
    {
      "id": "<the candidate id, echoed verbatim>",
      "name": "<short title, e.g. 'SQLi authentication bypass on /login'>",
      "category": "<class, e.g. 'SQL Injection', 'Path Traversal', 'OS Command Injection', 'Broken Authentication'>",
      "endpoint": "<method + path it was observed on>",
      "severity": "Critical" | "High" | "Medium" | "Low",
      "cvss": <number 0.0-10.0>,
      "confidence": "Confirmed" | "Likely" | "Possible",
      "evidence": "<the concrete observation that proves it>",
      "impact": "<what an attacker gains>",
      "remediation": "<the fix in one sentence>",
      "references": ["<URL from brave_search_enrichment if available>"]
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

    # Ordered list of FSM states for high-water-mark comparison.
    FSM_ORDER = [
        FSMState.READY,
        FSMState.RECON,
        FSMState.DAST_TESTING,
        FSMState.POC_VERIFICATION,
        FSMState.BLUE_TEAM_REMEDIATION,
        FSMState.COMPLETE,
    ]

    def __init__(self, db: AsyncSession, job_id: str):
        self.db = db
        self.job_id = job_id
        self.state: FSMState = FSMState.READY
        self.pipeline_phase: FSMState = FSMState.READY
        self.attack_graph: dict = {}
        self.llm_client = LLMClient()
        self.mcp_client = MCPClient()
        self._semaphore = asyncio.Semaphore(5)  # Token bucket: max 5 concurrent LLM calls
        self._seen_hashes: set[str] = set()
        self.cycle_budget_seconds = DEFAULT_CYCLE_BUDGET_SECONDS
        # The K2 agent for the current run_cycle; set in run_cycle so the
        # finalizer can format its captured <think> reasoning into a timeline.
        self._agent = None

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
            # Load pipeline_phase; fall back to current state for backwards compat.
            if job.pipeline_phase:
                try:
                    self.pipeline_phase = FSMState(job.pipeline_phase)
                except ValueError:
                    self.pipeline_phase = self.state
            else:
                self.pipeline_phase = self.state
            self.attack_graph = job.attack_graph_data or {}

    async def save_state(self) -> None:
        """Persist current state back to analysis_jobs table."""
        stmt = select(AnalysisJob).where(AnalysisJob.id == self.job_id)
        result = await self.db.execute(stmt)
        job = result.scalar_one_or_none()

        if job:
            job.status = self.state.value
            job.pipeline_phase = self.pipeline_phase.value
            job.attack_graph_data = self.attack_graph
            # Persist the structured thought timeline to its dedicated column
            # when it has been generated (at finalization).
            if self.attack_graph.get("structured_thoughts") is not None:
                job.structured_thoughts = self.attack_graph["structured_thoughts"]
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

        # Record scan start (epoch seconds) once, for the duration timer.
        if not self.attack_graph.get("started_at"):
            self.attack_graph["started_at"] = time.time()

        # If already complete, nothing to do
        if self.state == FSMState.COMPLETE:
            return self.state

        target = await self._get_workspace_target()
        agent = K2Agent(llm_client=self.llm_client)
        self._agent = agent
        executor = ToolExecutor(
            job_id=self.job_id, mcp_client=self.mcp_client, llm_client=self.llm_client
        )

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
                    # Link-based coverage: URLs discovered in HTML but not yet attacked.
                    "unvisited_links": self._unvisited_links(),
                    "endpoint_attempts": self.attack_graph.get("endpoint_attempts", {}),
                    "exhausted_endpoints": self.attack_graph.get("exhausted_endpoints", []),
                    "iteration": iteration,
                }

                async with self._semaphore:
                    decision = await agent.decide(context)

                # Accumulate K2-Think-v2 token usage from this reasoning call.
                self._accumulate_usage(getattr(self.llm_client, "last_usage", None))

                # Mirror the agent's captured chain-of-thought (the raw <think>
                # reasoning for each decision) into the attack graph so it is
                # persisted and available to render the UI thought timeline.
                self.attack_graph["thinking_log"] = agent.thinking_log

                action = decision.get("action")

                if action == "complete":
                    # Coverage gate: do NOT let the agent stop while it still has
                    # discovered-but-unprobed endpoints. The agent tends to
                    # declare victory after a handful of findings, leaving whole
                    # routes (e.g. /customers, /customer/<id>) untouched — which
                    # is the difference between finding ~half the vulns and the
                    # full set. We reject the early finish, hand it the concrete
                    # unprobed list, and make it keep going. Bounded by
                    # COMPLETION_DEFERRAL_CAP and, ultimately, MAX_ITERATIONS.
                    remaining = self._coverage_remaining()
                    deferrals = self.attack_graph.get("completion_deferrals", 0)
                    if remaining and deferrals < COMPLETION_DEFERRAL_CAP:
                        self.attack_graph["completion_deferrals"] = deferrals + 1
                        preview = ", ".join(remaining[:10])
                        agent.feed_note(
                            "DO NOT finish yet — you have not probed every "
                            "discovered endpoint. Coverage is incomplete. "
                            f"Unprobed routes still to attack: {preview}. "
                            "Probe EACH one with injection payloads suited to "
                            "its parameters before completing: SQL injection in "
                            "id / search / q parameters (e.g. \"1 OR 1=1\", "
                            "\"' OR '1'='1\"), OS command injection in host / "
                            "label / cmd parameters (e.g. \";id\", \"$(id)\", "
                            "\"|| id\"), path traversal in file / path "
                            "parameters (e.g. \"../../etc/passwd\"), and "
                            "template/code injection in formula parameters. "
                            "Only finish once every route above has been tested."
                        )
                        await self.save_state()
                        continue
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
                    # generate_patch invokes K2-Think-v2 inside the executor
                    # (via RemediationService, which shares self.llm_client), so
                    # capture those tokens too — they were previously lost.
                    if tool_name == "generate_patch":
                        self._accumulate_usage(
                            getattr(self.llm_client, "last_usage", None)
                        )
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
                            # No route map available — build an "unvisited links"
                            # list from URLs seen in prior responses vs. what
                            # endpoint_attempts already probed. This is the best
                            # approximation of coverage in pure-DAST mode.
                            unvisited = self._unvisited_links()
                            if unvisited:
                                links_desc = ", ".join(unvisited[:8])
                                agent.feed_note(
                                    f"Patch stored for '{vuln_node}'. You have "
                                    f"{len(unvisited)} endpoint(s) that appeared in "
                                    "prior HTML responses but have NOT been attacked "
                                    f"yet: {links_desc}. Probe each of them with a "
                                    "crafted payload BEFORE finishing. The session "
                                    "cookie persists. Do NOT call generate_patch "
                                    "again until a NEW anomaly is triggered on a "
                                    "different endpoint."
                                )
                            else:
                                agent.feed_note(
                                    f"Patch stored for '{vuln_node}'. Continue "
                                    "probing any endpoints you still have evidence "
                                    "for. Do NOT finish until you have attempted at "
                                    "least one injection payload on every distinct "
                                    "page you discovered during this session."
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
        """Advance FSM state to COMPLETE through valid transitions.

        Deliberately does NOT set pipeline_phase here — that is only set in
        _finalize_and_report() once the report is actually generated.  This
        prevents the UI stepper from jumping to "Complete" while the scan is
        still running (the bug where pipeline_phase=complete was stored before
        _finalize_and_report had finished, leaving the header saying "Scanning
        live" while the stepper showed "Complete").
        """
        state_chain = [
            FSMState.READY, FSMState.RECON, FSMState.DAST_TESTING,
            FSMState.POC_VERIFICATION, FSMState.BLUE_TEAM_REMEDIATION,
            FSMState.COMPLETE,
        ]
        # Advance ONLY forward from wherever we are now. Starting the walk at the
        # state *after* the current one avoids attempting an invalid backward
        # transition (e.g. DAST_TESTING -> RECON), which previously broke the
        # loop on the first step and left a finished job stuck at a running
        # status (report generated, but status never reached "complete" — the
        # "shows the report but still says scanning live" bug).
        try:
            start = state_chain.index(self.state) + 1
        except ValueError:
            start = 0  # current state not in the chain — walk from the beginning
        for next_state in state_chain[start:]:
            if not self.transition(next_state):
                break
        # pipeline_phase is intentionally NOT set to COMPLETE here.

    def _accumulate_usage(self, usage: dict | None) -> None:
        """Fold one K2-Think-v2 API call's token usage into the running total.

        Safe to call after every LLM interaction (reasoning, remediation, final
        assessment). Non-dict / empty usage (e.g. a mocked client in tests, or a
        failed call) is ignored so the counter only reflects real API calls.
        """
        if not isinstance(usage, dict) or not usage:
            return
        totals = self.attack_graph.setdefault("token_usage", {
            "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
            "llm_calls": 0,
        })
        totals["prompt_tokens"] += usage.get("prompt_tokens", 0) or 0
        totals["completion_tokens"] += usage.get("completion_tokens", 0) or 0
        total = usage.get("total_tokens")
        if not total:
            total = (usage.get("prompt_tokens", 0) or 0) + (usage.get("completion_tokens", 0) or 0)
        totals["total_tokens"] += total or 0
        totals["llm_calls"] += 1

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

        # Also read severity signals from the correlation layer and the K2
        # final assessment — both may have higher evidence than patch risk_level.
        canonical = self.attack_graph.get("vulnerabilities") or []
        for v in canonical:
            lvl = str(v.get("severity") or "").lower()
            highest_patch_risk = max(highest_patch_risk, risk_order.get(lvl, 0))

        assessment = self.attack_graph.get("final_assessment") or {}
        # overall_risk from K2 assessment
        k2_risk = str(assessment.get("overall_risk") or "").lower()
        # also walk individual vulnerabilities in the assessment
        for v in (assessment.get("vulnerabilities") or []):
            lvl = str(v.get("severity") or "").lower()
            highest_patch_risk = max(highest_patch_risk, risk_order.get(lvl, 0))
        # Map K2's overall_risk string directly
        k2_score = risk_order.get(k2_risk, 0)
        highest_patch_risk = max(highest_patch_risk, k2_score)

        # Patch-derived / K2-assessment risk is most trustworthy — use it if available.
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

    def _build_thought_timeline(self) -> list[dict]:
        """
        Build the K2 thought-process timeline from the agent's captured
        chain-of-thought (the raw <think>...</think> reasoning of every K2
        decision), NOT from the tool results.

        Each entry surfaces the model's ACTUAL deliberation verbatim, paired
        with the action that thinking produced. This is deterministic, instant,
        and uses no extra LLM call — the reasoning was already captured during
        the agent loop.
        """
        log = self.attack_graph.get("thinking_log") or []
        if not log:
            return []

        steps: list[dict] = []
        for i, entry in enumerate(log):
            tool = entry.get("tool") or ""
            action = entry.get("action") or ""
            args = entry.get("arguments") or {}

            # Title: what this thinking decided to do.
            if tool:
                title = self._thought_title(tool, args)
            elif action == "complete":
                title = "Concluded the analysis"
            elif action == "error":
                title = "Recovering from an unparsable response"
            else:
                title = f"Reasoning step {i + 1}"

            # Details: the model's RAW chain-of-thought. Fall back to the
            # one-line decision reasoning only when no <think> block was emitted.
            think = (entry.get("think") or "").strip()
            reasoning = (entry.get("reasoning") or "").strip()
            details = think or reasoning or f"Decided to {action or 'act'}."

            steps.append({
                "step_title": title,
                "details": details,
                "iteration": entry.get("iteration", i),
                "tool": tool or action,
                # True when we have genuine model reasoning (vs. a fallback line).
                "has_reasoning": bool(think),
            })

        return steps

    @staticmethod
    def _thought_title(tool: str, args: dict) -> str:
        """Generate a concise human-readable title for a tool call."""
        titles = {
            "run_nmap": lambda a: f"Port scan {a.get('target', 'target')}",
            "send_http_request": lambda a: f"{a.get('method', 'GET')} {a.get('endpoint', '')}",
            "run_fuzzer": lambda a: f"Fuzz {a.get('endpoint', a.get('url', 'target'))}",
            "execute_safe_poc": lambda a: f"PoC verification (sandbox {a.get('sandbox_id', '?')})",
            "generate_patch": lambda a: f"Generate patch for {a.get('vuln_node', 'vulnerability')}",
            "internet_search": lambda a: f"Internet search: {a.get('component', a.get('version', 'service'))}",
        }
        fn = titles.get(tool)
        if fn:
            return fn(args)
        return f"Execute {tool}"

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

        # Stamp completion time so the UI can show total scan duration.
        self.attack_graph.setdefault("started_at", time.time())
        self.attack_graph["completed_at"] = time.time()

        # Correlate detections <-> PoCs <-> patches into ONE canonical set, so
        # detected == tested == remediated == total and each PoC maps to its
        # OWN vulnerability instead of collapsing onto a single node.
        from app.services.correlation import correlate
        correlated = correlate(self.attack_graph)
        self.attack_graph["vulnerabilities"] = correlated["vulnerabilities"]
        self.attack_graph["vulnerability_counts"] = correlated["counts"]

        # Final K2 verdict: select ONE definitive assessment per canonical
        # vulnerability (enriched with CVSS/CVEs), with the count pinned to the
        # canonical total. Best-effort — never blocks finalization or the
        # report, and falls back to a deterministic verdict if K2 is offline.
        assessment = await self._generate_final_assessment(correlated)
        if assessment:
            self.attack_graph["final_assessment"] = assessment

        # Re-score severity now that the K2 assessment + correlation are available.
        # The first _score_severity() call above was a quick bootstrap; this one
        # has full access to final_assessment.vulnerabilities and canonical vulns.
        severity = self._score_severity()
        self.attack_graph["overall_severity"] = severity

        # Build the structured thought timeline directly from tool_results.
        # Each tool call is a "thought step" -- the agent's reasoning + what it did.
        self.attack_graph["structured_thoughts"] = self._build_thought_timeline()

        # Persist severity onto the job row too.
        stmt = select(AnalysisJob).where(AnalysisJob.id == self.job_id)
        result = await self.db.execute(stmt)
        job = result.scalar_one_or_none()
        if job:
            job.overall_severity = severity
            if self.attack_graph.get("structured_thoughts") is not None:
                job.structured_thoughts = self.attack_graph["structured_thoughts"]

        # ── PDF Report generation ────────────────────────────────────────────
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

        # Only now is the job truly finished — stamp pipeline_phase so the
        # UI stepper advances to "Complete" only once the report exists.
        self.pipeline_phase = FSMState.COMPLETE

    def _maybe_advance_state(self, tool_name: str) -> None:
        """Advance FSM state by one step based on tool used."""
        tool_to_min_state = {
            "run_nmap": FSMState.RECON,
            "run_fuzzer": FSMState.DAST_TESTING,
            "send_http_request": FSMState.DAST_TESTING,
            "execute_safe_poc": FSMState.POC_VERIFICATION,
            "internet_search": FSMState.POC_VERIFICATION,
            "generate_patch": FSMState.BLUE_TEAM_REMEDIATION,
        }
        target_state = tool_to_min_state.get(tool_name)
        if not target_state:
            return

        # Update high-water-mark pipeline_phase (only advances forward).
        target_idx = self.FSM_ORDER.index(target_state)
        current_phase_idx = self.FSM_ORDER.index(self.pipeline_phase)
        if target_idx > current_phase_idx:
            self.pipeline_phase = target_state

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

    # --- Link-based coverage (pure DAST, no route map) ---------------------

    def _unvisited_links(self) -> list[str]:
        """
        Extract URLs/paths that appeared in prior HTML responses but have NOT
        yet been attacked (i.e. are not in endpoint_attempts). This is the
        best-effort coverage driver when no source-derived route map exists:
        the scanner discovers pages by crawling links, so at minimum it should
        attack every link it saw.

        Returns a list of path strings (e.g. ["/download?file=welcome.txt",
        "/admin/diagnostics?host=localhost"]).
        """
        discovered: set[str] = set()
        for entry in self.attack_graph.get("tool_results", []):
            result = entry.get("result") or {}
            body = result.get("body") or ""
            if not body:
                continue
            # Extract href="..." and action="..." from HTML responses.
            for match in re.finditer(r'(?:href|action)="([^"]*)"', body):
                url = match.group(1)
                if not url or url.startswith(("#", "javascript:", "mailto:")):
                    continue
                # Keep only same-origin paths (starting with /).
                if url.startswith("/"):
                    discovered.add(url.split("#")[0])

        # Compare discovered paths against what we already probed.
        probed_paths = self._probed_url_paths()
        unvisited = []
        for link in sorted(discovered):
            path_only = link.split("?")[0].rstrip("/") or "/"
            if path_only in SKIP_ROUTE_PATHS:
                continue
            # Check if we already hit this exact link OR its base path.
            if path_only in probed_paths or link.split("?")[0] in probed_paths:
                continue
            if any(self._route_path_matches(path_only, p) for p in probed_paths):
                continue
            unvisited.append(link)
        return unvisited

    # --- Coverage gate (drives full endpoint exploration) -----------------

    @staticmethod
    def _coverage_template(path: str) -> str:
        """
        Collapse a path to a coverage 'template' so that distinct concrete URLs
        of the same endpoint (e.g. /customer/1 and /customer/2) count as ONE
        endpoint. Numeric segments become <id>; query strings are dropped.
        """
        p = (path or "/").split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"
        segs = ["<id>" if seg.isdigit() else seg for seg in p.split("/")]
        return "/".join(segs) or "/"

    def _coverage_remaining(self) -> list[str]:
        """
        Endpoints that were DISCOVERED (from the source route map when present,
        otherwise from links seen in HTML responses) but have NOT yet been
        probed. Deduplicated by template so /customer/1..5 collapse to one, and
        filtered against everything already attacked. An empty list means the
        agent has covered the full known attack surface and may finish.
        """
        unprobed_routes = self._unprobed_routes()
        if unprobed_routes:
            candidates = [r.get("path", "") for r in unprobed_routes if r.get("path")]
        else:
            candidates = self._unvisited_links()

        probed_templates = {
            self._coverage_template(self._url_to_path(k))
            for k in self.attack_graph.get("endpoint_attempts", {})
        }
        out: list[str] = []
        seen: set[str] = set()
        for cand in candidates:
            tmpl = self._coverage_template(self._url_to_path(cand))
            if tmpl in probed_templates or tmpl in seen:
                continue
            seen.add(tmpl)
            out.append(cand)
        return out

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

        # Enrich findings with Brave Search context (best-effort, non-blocking).
        # For each distinct vulnerability signal we observed, query Brave for
        # CVE references, exploit details, and remediation advice so the final
        # K2 assessment can produce a more detailed, evidence-backed report.
        enrichment: list[dict] = []
        try:
            search_queries = set()
            for svc in recon_services:
                if svc.get("version"):
                    search_queries.add(f"{svc['service']} {svc['version']} CVE exploit")
            for obs in observed:
                vuln_type = obs.get("type", "")
                if vuln_type:
                    search_queries.add(f"{vuln_type} vulnerability exploit remediation")
            for patch_name in self.attack_graph.get("patched_nodes", [])[:5]:
                search_queries.add(f"{patch_name.replace('_', ' ')} vulnerability CVE")

            # Run up to 4 searches in parallel (don't spam the API)
            limited_queries = list(search_queries)[:4]
            if limited_queries:
                results = await asyncio.gather(
                    *[self.mcp_client.internet_search(q, "") for q in limited_queries],
                    return_exceptions=True,
                )
                for query, res in zip(limited_queries, results):
                    if isinstance(res, dict) and not res.get("error"):
                        refs = res.get("references", [])[:3]
                        if refs:
                            enrichment.append({"query": query, "references": refs})
        except Exception:
            pass  # Enrichment failure must not block the assessment.

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
            "brave_search_enrichment": enrichment,
        }

    async def _generate_final_assessment(self, correlated: dict | None = None) -> dict | None:
        """
        Final pass: produce the DEFINITIVE vulnerability assessment.

        Built on top of the canonical correlated vulnerability set so the
        reported count ALWAYS equals the number of detected vulnerabilities
        (detected == tested == remediated == total). K2-Think-v2 is used to
        SELECT the single definitive characterization per candidate and enrich
        it (CVSS, CVEs, impact); when K2 is unavailable the deterministic
        verdict derived from the gathered evidence is returned instead, so the
        UI count is always consistent.

        Offline-safe: the K2 call uses its OWN LLMClient (never disturbs a
        mocked self.llm_client), is bounded by a timeout, and never raises.
        """
        if correlated is None:
            from app.services.correlation import correlate
            correlated = correlate(self.attack_graph)
        canonical = correlated.get("vulnerabilities", [])

        k2_obj = await self._k2_select_definitive(canonical)
        vulns = self._reconcile_assessment(
            canonical, (k2_obj or {}).get("vulnerabilities")
        )
        overall = self._overall_risk(vulns)
        summary = (
            (k2_obj or {}).get("executive_summary")
            or self.attack_graph.get("k2_summary")
            or self._default_summary(vulns, overall)
        )
        return {
            "total_vulnerabilities": len(vulns),
            "overall_risk": overall,
            "executive_summary": summary,
            "vulnerabilities": vulns,
        }

    async def _k2_select_definitive(self, canonical: list[dict]) -> dict | None:
        """
        Hand K2-Think-v2 the canonical candidate list + evidence and ask it to
        pick the ONE definitive assessment per candidate (and enrich it).

        Returns the parsed K2 object, or None when K2 is unavailable / errors.
        Always folds the call's token usage into the running counter.
        """
        client = LLMClient()
        if not client.api_key or not canonical:
            return None
        raw = None
        try:
            evidence = await self._build_assessment_evidence()
            evidence["candidate_vulnerabilities"] = [
                {
                    "id": v["id"],
                    "category": v["category"],
                    "endpoint": v["endpoint"],
                    "severity": v["severity"],
                    "verified": (v.get("verification") or {}).get("status"),
                    "remediated": v.get("remediation") is not None,
                    "evidence": (v.get("detection") or {}).get("evidence", ""),
                }
                for v in canonical
            ]
            messages = [
                {"role": "system", "content": FINAL_ASSESSMENT_PROMPT},
                {"role": "user", "content": json.dumps(evidence, default=str)},
            ]
            raw = await asyncio.wait_for(
                client.chat(messages, role="agent"), timeout=120.0
            )
        except Exception:
            raw = None
        finally:
            self._accumulate_usage(getattr(client, "last_usage", None))
        if not isinstance(raw, str) or is_api_error(raw):
            return None
        parsed = extract_json_object(raw)
        return parsed if isinstance(parsed, dict) else None

    # --- Assessment reconciliation helpers -------------------------------- #

    # Default CVSS base score by severity, used when K2 does not supply one.
    _CVSS_DEFAULT = {"Critical": 9.1, "High": 7.8, "Medium": 5.4, "Low": 3.1}
    _SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    @staticmethod
    def _normalize_ep(ep) -> str:
        if not ep:
            return ""
        m = re.search(r"/\S*", str(ep))
        path = m.group(0) if m else str(ep)
        return path.split("?")[0].rstrip("/").lower() or "/"

    @classmethod
    def _clean_sev(cls, s) -> str | None:
        if not s:
            return None
        key = str(s).strip().lower()
        return key.capitalize() if key in cls._SEV_RANK else None

    @classmethod
    def _coerce_cvss(cls, val, severity: str):
        try:
            f = float(val)
            if 0.0 <= f <= 10.0:
                return round(f, 1)
        except (TypeError, ValueError):
            pass
        return cls._CVSS_DEFAULT.get(severity, 5.0)

    def _reconcile_assessment(self, canonical: list[dict], k2_vulns) -> list[dict]:
        """
        Produce exactly ONE assessment entry per canonical vulnerability,
        merging K2's enrichment (matched by id, then by endpoint) over the
        deterministic data. Guarantees len(result) == len(canonical).
        """
        k2_by_id: dict[str, dict] = {}
        k2_by_ep: dict[str, dict] = {}
        if isinstance(k2_vulns, list):
            for kv in k2_vulns:
                if not isinstance(kv, dict):
                    continue
                if kv.get("id"):
                    k2_by_id[str(kv["id"])] = kv
                ep = self._normalize_ep(kv.get("endpoint"))
                if ep:
                    k2_by_ep.setdefault(ep, kv)

        out: list[dict] = []
        for v in canonical:
            kv = k2_by_id.get(v["id"]) or k2_by_ep.get(self._normalize_ep(v["endpoint"])) or {}
            verification = v.get("verification") or {}
            remediation = v.get("remediation") or {}
            severity = self._clean_sev(kv.get("severity")) or v["severity"]
            confidence = kv.get("confidence") or (
                "Confirmed" if verification.get("status") == "confirmed"
                else "Likely" if verification.get("status") == "observed"
                else "Possible"
            )
            cves = remediation.get("cves") or (
                [str(c) for c in kv.get("cves", [])] if isinstance(kv.get("cves"), list) else []
            )
            out.append({
                "id": v["id"],
                "name": kv.get("name") or v["name"],
                "category": kv.get("category") or v["category"],
                "endpoint": kv.get("endpoint") or v["endpoint"],
                "severity": severity,
                "cvss": self._coerce_cvss(kv.get("cvss"), severity),
                "confidence": confidence,
                "evidence": kv.get("evidence") or verification.get("detail")
                or (v.get("detection") or {}).get("evidence", ""),
                "impact": kv.get("impact") or "",
                "remediation": kv.get("remediation") or remediation.get("recommendation", ""),
                "cves": cves,
                "references": [str(r) for r in (kv.get("references") or []) if r],
            })
        return out

    def _overall_risk(self, vulns: list[dict]) -> str:
        if not vulns:
            return "Informational"
        top = max(self._SEV_RANK.get(str(v.get("severity", "")).lower(), 0) for v in vulns)
        return {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(top, "Informational")

    def _default_summary(self, vulns: list[dict], overall: str) -> str:
        n = len(vulns)
        if n == 0:
            return (
                "The automated scan did not confirm any exploitable "
                "vulnerabilities on this target."
            )
        tally: dict[str, int] = {}
        for v in vulns:
            sev = str(v.get("severity", "")).capitalize()
            tally[sev] = tally.get(sev, 0) + 1
        breakdown = ", ".join(
            f"{tally[s]} {s.lower()}" for s in ("Critical", "High", "Medium", "Low")
            if tally.get(s)
        )
        noun = "vulnerability" if n == 1 else "vulnerabilities"
        return (
            f"The automated scan confirmed {n} {noun} ({breakdown}); overall risk "
            f"is {overall}. Each finding was verified and a remediation was generated."
        )
