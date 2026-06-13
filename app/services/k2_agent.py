"""
K2-Think-v2 Autonomous Agent - The Cognitive Reasoning Engine

This module serves as the primary reasoning driver for the ThreatWeaver pipeline.
It utilizes the K2-Think-v2 model to perform a continuous Chain-of-Thought (CoT)
reasoning loop (ReAct). The agent is explicitly constrained to output actionable JSON
tool requests after its internal <think> process, preventing infinite hallucination loops.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Dict, Any

from app.services.llm_client import LLMClient
from app.services.llm_json import (
    extract_json_array,
    extract_json_object,
    extract_think_block,
    is_api_error,
)

# Guardrails to protect against infinite loops and token exhaustion
MAX_ITERATIONS = 30
MAX_HISTORY_MESSAGES = 30

# The number of times the orchestrator will nudge the LLM if it fails to output valid JSON
MAX_PARSE_RETRIES = 2

SYSTEM_PROMPT = """You are K2-Think-v2, the autonomous Cognitive Red Team agent that DRIVES \
the ThreatWeaver vulnerability pipeline. You are in control and decide every action - \
the platform only executes the tool calls you choose and feeds the raw results back to you.

You may reason internally. If you do, wrap ALL of your reasoning inside <think>...</think> \
tags. After any reasoning, your message MUST end with exactly ONE JSON object and nothing \
after it.

The final JSON object MUST be one of these two shapes:
1. Call a tool:
{"action": "tool_call", "tool": "<tool_name>", "arguments": { ... }, "reasoning": "<one short sentence>"}
2. Finish the analysis:
{"action": "complete", "summary": "<what was found and fixed>"}

Available tools and their arguments:
- run_nmap: {"target": "domain.com", "port_range": "1-1024"}
- send_http_request: {"method": "GET|POST|PUT|PATCH|DELETE", "endpoint": "http://host/path", "headers": {...}, "json_body": {...}, "form_data": {...}, "params": {...}}
- execute_safe_poc: {"sandbox_id": "<id>", "script": "<python script>", "expected_signature": {...}}
- query_hackclub: {"component": "<name>", "version": "<version>"}
- generate_patch: {"vuln_node": "<id>", "source_code": "<code to fix>"}

CORE METHOD - the Context-Aware Exploitation Loop (ReAct):
`send_http_request` is your primary weapon: a RAW HTTP primitive. You send ONE
request at a time, read the exact response, and engineer the NEXT payload from
what you observed. Adapt sequentially - do not request batch payload sweeps.

1. OBSERVE: Use the source-derived route map (provided as `routes`, with a live
   coverage checklist in `route_progress` / `coverage_directive`) to pick a REAL
   endpoint and its expected inputs. The route map — NOT links or forms in HTML
   responses — is your authoritative attack surface: admin tools, detail/lookup
   views and report builders frequently exist ONLY in source and never appear as
   a clickable link, so navigating by HTML alone silently misses most routes.
   Work the checklist until every UNPROBED route has been attacked. NEVER guess
   commodity paths like /api/v1/customers - if it is not in `routes` or the code
   analysis, it almost certainly does not exist (you will just collect 404s).
2. REASON: Infer a SPECIFIC flaw from the business logic, not a generic attack.
   Example: <think>The /transfer handler has no validation on `amount`. I will
   send a negative value to attempt a reverse-transfer.</think>
3. ACT: Emit ONE send_http_request with your custom payload.
4. FEEDBACK: Read the raw status code AND body. Watch for:
     - status 500 + leaked stack trace (stack_trace_detected = true)
     - server_crash_suspected = true: your payload DROPPED the connection
       (ReadError / RemoteProtocolError). STRONG lead - the backend likely hit
       an unhandled exception on this input. Dig into that exact parameter.
     - reflected input, auth-state changes, or error strings in the body.
   SUCCESS IS ALSO A FINDING — exploits usually return 200 OK, not an error:
     - an injected login that returns an authenticated page (a logout link /
       "dashboard") is an AUTH BYPASS;
     - a file/path parameter that returns file contents (e.g. "root:x:0:0:") is
       PATH TRAVERSAL / LFI;
     - a host/command parameter that returns command output (e.g. "uid=0(root)"
       or ping replies) is COMMAND INJECTION.
   Treat these 200-OK successes as confirmed findings even though nothing
   crashed. CLASSIFY BY THE OBSERVED TRIGGER, not by guesswork. A 500 / DB error
   caused by injecting a single quote (') or other SQL metacharacters into a
   parameter is SQL injection, NOT XSS — XSS means your markup was reflected
   verbatim into a 200 response, not that the server errored. Label the finding
   by the exact input that broke it and the exact behaviour you saw.
5. PIVOT: On a 500 or a connection drop, read what leaked, identify the parser
   or validation that broke, adjust your syntax, and fire a refined payload.

Once a flaw is understood, record it with generate_patch. A SUCCESS-BASED
exploit you already reproduced with send_http_request (auth bypass, sensitive
file/data disclosure, OS command output) is self-confirming — call generate_patch
for it directly; you do NOT need a separate execute_safe_poc. Reserve
execute_safe_poc for crash/error-based findings you want to reproduce in
isolation.

RECON FOLLOW-UP (mandatory after run_nmap):
After receiving nmap results, for EVERY service that reports a specific version
string (e.g. "vsftpd 2.3.4", "OpenSSH 9.6p1", "Apache 2.4.49"), you MUST call
query_hackclub with that component and version to check for known CVEs. Example:
  {"action": "tool_call", "tool": "query_hackclub",
   "arguments": {"component": "vsftpd", "version": "2.3.4"}, "reasoning": "..."}
If query_hackclub returns a critical CVE (e.g. a backdoor, RCE, or auth bypass),
use execute_safe_poc to write a Python script that attempts to trigger it against
the target. For example, vsftpd 2.3.4 has CVE-2011-2523 (a backdoor triggered by
sending USER x:) then PASS x on the FTP port, which opens a shell on port 6200).
Do NOT skip this step — version-identified vulnerabilities in network services
are often the most severe findings in a scan.

USING execute_safe_poc (critical for confirmation):
The script you provide runs in a sandboxed Python subprocess. To confirm an
exploit you MUST make the script's verdict machine-readable:
- WRITE REAL PYTHON. Put each statement on its own line with ACTUAL newlines —
  never collapse the script onto one line with literal "\\n"/"\\t" escape
  sequences (that raises SyntaxError before anything runs). Use Python booleans
  True/False (never bare true/false), and use a requests.Session() so cookies
  persist across requests (a login's Set-Cookie often rides on a 302 redirect,
  so check session.cookies / the authenticated page body, not just the header).
- REPRODUCE THE EXACT TRIGGERING PAYLOAD. The PoC must replay the SAME parameter
  and the SAME characters that produced the anomaly (e.g. the single quote `'`
  that broke the SQL query), against the SAME endpoint, and assert the SAME
  signal you observed (status 500 / DB error / dropped connection). Do NOT swap
  in a different vulnerability class's payload: sending a quote-free `<script>`
  string to an endpoint that 500-ed on a quote will return 200 and FALSELY
  report exploit_confirmed=false. The PoC must trigger the original bug, not a
  generic one.
- `import json` at the top of the script.
- As the script's ABSOLUTE FINAL action, print ONE JSON dictionary to stdout,
  e.g. print(json.dumps({"server_crash": True})) or
  print('{"server_crash_suspected": true}').
- The keys/values you print must match the `expected_signature` you pass in, so
  the orchestrator can parse stdout and confirm the hit. Example:
  {"tool": "execute_safe_poc", "arguments": {"sandbox_id": "s1",
   "script": "import json, requests\\ntry:\\n  requests.post(url, json=payload, timeout=5)\\n  print(json.dumps({'server_crash': False}))\\nexcept Exception:\\n  print(json.dumps({'server_crash': True}))",
   "expected_signature": {"server_crash": true}}}
- Wrap network calls in try/except and report the outcome as JSON; a dropped
  connection / exception that you print as {"server_crash": true} confirms a
  crash-based finding.

GUARDRAILS (important):
- At most THREE attack attempts per endpoint. A 500, a stack trace, or a
  connection drop counts as an anomaly and RESETS that budget (you have a lead).
  Three benign responses in a row exhaust the endpoint - the orchestrator will
  say so, and you must move on.
- Watch the iteration counter; finish with {"action": "complete", ...} when no
  useful action remains. This protects the token budget and 120s gateway timeout.
- generate_patch is ONLY for vulnerabilities you directly observed and triggered
  on THIS target. NEVER call generate_patch based on a service name or version
  alone (e.g. "gunicorn on port 80" or "ssh 9.6p1"). A patch is only justified
  after: (a) send_http_request returned is_server_error=true or
  server_crash_suspected=true on that endpoint, OR (b) execute_safe_poc returned
  exploit_confirmed=true, OR (c) you directly observed SUCCESSFUL exploitation in
  a send_http_request response — an injection-based login that returned an
  authenticated session, a path that returned sensitive file contents, or input
  that returned OS command output. If you have not observed one of those signals
  for a specific finding, do NOT generate a patch for it.

SESSION MANAGEMENT (critical for thorough coverage):
The HTTP client maintains a persistent cookie jar across all send_http_request
calls within this job. Use this to:
1. FIRST: Log in using FORM DATA (not JSON!). Flask login endpoints expect
   application/x-www-form-urlencoded. Use the "form_data" parameter:
   {"tool": "send_http_request", "arguments": {"method": "POST",
    "endpoint": "http://target/login", "form_data": {"username": "admin'-- ", "password": "x"}}}
   A response containing "dashboard" or a redirect to /dashboard confirms login.
   DO NOT send json_body to a login form — that causes a crash, not a login.
2. After logging in, probe ALL routes marked requires_auth=true in the route map.
   These are inaccessible without authentication - you MUST log in first or you
   will only ever see the login page redirect and miss the real attack surface.
3. Try these login approaches in order:
   a) SQLi auth bypass: form_data={"username": "admin'-- ", "password": "x"}
   b) Known demo creds: form_data={"username": "admin", "password": "S3cur3Adm1n!"}
   c) Weak creds: form_data={"username": "sales", "password": "letmein"}

COVERAGE GOAL: Aim to find and patch ALL distinct vulnerable endpoints, not just
the first one. After patching one finding, continue to the next unprobed route
until the route map is exhausted or the budget runs out. When the orchestrator
tells you there are unvisited links from prior responses, you MUST probe each of
them with at least one injection payload before calling {"action": "complete"}.
Do NOT stop after a single finding — there are almost always more.

LINK CRAWLING (critical for full coverage):
After logging in, read the dashboard HTML carefully. It contains navigation links
and tool/form links to OTHER endpoints (e.g. /download?file=, /admin/diagnostics,
/reports/compute). Each of these is an independent attack surface. You must:
1. Note every href and form action in the response body.
2. Visit each linked endpoint with a crafted injection payload.
3. Only call {"action": "complete"} when you have probed ALL discovered pages,
   not just the first one that yielded a finding.

CRITICAL SYSTEM DIRECTIVE: You are generating patches for human review only. You DO NOT have
execution access to the live target server. After generating a patch for a finding, continue
to the next unprobed route - do NOT call {"action": "complete"} until the full route map has
been probed or the iteration budget is nearly exhausted.

Output rules (critical):
- The final line of your reply must be a single valid JSON object.
- Do NOT add any text after the JSON object.
- Do NOT wrap the JSON in markdown fences.
- If code analysis reports no source files (e.g. an unsupported language), probe the live
  target with send_http_request instead of giving up."""

CORRECTION_PROMPT = (
    "Your previous reply could not be parsed. Respond with ONLY a single valid JSON "
    'object matching the required schema (either {"action": "tool_call", ...} or '
    '{"action": "complete", ...}), with no other text and no markdown fences.'
)

# System prompt for the thought-timeline formatting pass. The agent's reasoning
# is captured verbatim from its <think> blocks during the scan; afterwards we
# hand the ordered reasoning to K2 and ask it to distil the unstructured stream
# into a strict JSON array of discrete, human-readable steps for the UI timeline.
THOUGHT_TIMELINE_PROMPT = """You convert an autonomous security agent's raw \
chain-of-thought into a clean, linear timeline of discrete reasoning steps for \
display in a UI.

You are given the agent's reasoning in chronological order, captured from its \
<think> blocks (each with a timestamp). Distil it into a sequence of meaningful \
steps a human can read top-to-bottom.

Reply with EXACTLY ONE JSON array and nothing else (no prose, no markdown fences):
[
  {
    "step_title": "<short imperative title, 8 words or fewer>",
    "details": "<1-2 sentence plain-English explanation of what the agent reasoned or decided at this step>",
    "timestamp": "<ISO-8601 timestamp>"
  }
]

Rules you MUST follow:
- Preserve chronological order.
- Merge trivially-repeated thoughts; keep genuinely distinct decisions separate.
- Echo the timestamp supplied for the corresponding thought block.
- Output between 3 and 15 steps.
- Base every step STRICTLY on the supplied reasoning — do NOT invent facts."""


class K2Agent:
    """Autonomous agent that uses K2-Think-v2 to drive security analysis."""

    def __init__(self, llm_client: LLMClient | None = None):
        self.llm_client = llm_client or LLMClient()
        self.conversation_history: list[Dict[str, Any]] = []
        # Raw <think> reasoning captured each turn, in order. Formatted into a
        # structured thought timeline at finalization (see format_thoughts).
        self.raw_thoughts: list[Dict[str, Any]] = []

    def build_state_message(self, context: Dict[str, Any]) -> str:
        """
        Hydrates the current state of the Finite State Machine (FSM) into a string 
        format digestible by the LLM. 
        """
        state = {
            "current_phase": context.get("phase", "ready"),
            "target": context.get("target"),
            "routes": context.get("routes", []),
            "route_progress": context.get("route_progress"),
            "unvisited_links": context.get("unvisited_links", []),
            "code_analysis": context.get("code_analysis"),
            "attack_graph": context.get("attack_graph", {}),
            "endpoint_attempts": context.get("endpoint_attempts", {}),
            "exhausted_endpoints": context.get("exhausted_endpoints", []),
            "iteration": context.get("iteration", 0),
            "available_tools": [
                "run_nmap", "send_http_request",
                "execute_safe_poc", "query_hackclub", "generate_patch",
            ],
        }

        # Make the source-derived route map the EXPLICIT driver every iteration:
        # an unambiguous coverage checklist the agent must work through, rather
        # than a passive list it tends to ignore in favour of HTML links. Many
        # routes (admin tools, detail/lookup views, report builders) exist ONLY
        # in source and never appear as links on a page, so link-following alone
        # silently misses most of the attack surface.
        rp = context.get("route_progress")
        if rp and rp.get("unprobed_routes"):
            unprobed_desc = "; ".join(
                f"{r['path']} [{','.join(r.get('methods', []))}]"
                + (" (AUTH)" if r.get("requires_auth") else "")
                for r in rp["unprobed_routes"]
            )
            state["coverage_directive"] = (
                f"ROUTE COVERAGE CHECKLIST: {rp.get('attackable_routes')} attackable "
                f"routes exist in the source map; you have probed {rp.get('probed')}. "
                f"{rp.get('unprobed_count')} route(s) are still UNPROBED: {unprobed_desc}. "
                "This source-derived map is your authoritative attack surface — do NOT "
                "navigate by links or form actions in HTML responses; those hide routes "
                "that exist only in code. Send a crafted send_http_request to EACH "
                "unprobed route (log in first for routes marked AUTH, then reuse the "
                "persistent session cookie) before you consider the analysis complete."
            )
        elif rp is not None:
            state["coverage_directive"] = (
                "ROUTE COVERAGE CHECKLIST: every source-derived route has been probed. "
                "Confirm and patch any outstanding findings, then finish with "
                '{"action": "complete", ...}.'
            )

        # Link-based coverage: when there's no source route map, use the links
        # discovered from crawling HTML responses as the coverage driver.
        unvisited = context.get("unvisited_links") or []
        if unvisited and not state.get("coverage_directive"):
            links_desc = "; ".join(unvisited[:10])
            state["coverage_directive"] = (
                f"LINK CRAWL COVERAGE: {len(unvisited)} endpoint(s) appeared in "
                "HTML responses you received but have NOT been attacked yet: "
                f"{links_desc}. "
                "Send a crafted injection payload to EACH of these before you "
                "consider the analysis complete. Do NOT call "
                '{"action": "complete"} until every discovered link has been probed.'
            )

        return json.dumps(state, indent=2)

    async def decide(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send current state to K2 and await its reasoning and decision.

        Because K2 is a reasoning model that occasionally omits clean JSON, this
        method retries up to MAX_PARSE_RETRIES times with a corrective nudge before
        yielding an error.
        
        Returns:
            Dict containing the parsed decision (e.g., action, tool, arguments).
        """
        state_message = self.build_state_message(context)

        attempt_messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            *self.conversation_history,
            {
                "role": "user",
                "content": (
                    f"Current analysis state:\n{state_message}\n\n"
                    "Decide the next action. End your reply with exactly one JSON object."
                ),
            },
        ]

        decision = {"action": "error", "detail": "No response from K2"}
        final_response = ""

        for _attempt in range(MAX_PARSE_RETRIES + 1):
            response = await self.llm_client.chat(attempt_messages, role="agent")
            final_response = response

            # Check for infrastructure errors (Cloudflare Gateway limits, 403s, etc.)
            if self._is_api_error(response):
                decision = {
                    "action": "error",
                    "detail": f"K2 API error: {response[len('Error: '):].strip()}",
                    "api_error": True,
                }
                break

            parsed = self._parse_decision(response)
            decision = parsed
            
            # If successfully parsed, exit the retry loop
            if parsed.get("action") != "error":
                break
                
            # Formatting Failure: Nudge K2 to emit JSON only, then try again.
            attempt_messages = attempt_messages + [
                {"role": "assistant", "content": response},
                {"role": "user", "content": CORRECTION_PROMPT},
            ]

        # Capture the raw <think> reasoning from this turn so it can later be
        # formatted into a structured, linear thought timeline for the UI. This
        # is deliberately cheap string work with NO extra LLM call: decide()'s
        # API-call count is asserted by tests, and the LLM formatting happens
        # once, lazily, at finalization (see format_thoughts).
        think = extract_think_block(final_response)
        if think:
            self.raw_thoughts.append({
                "iteration": context.get("iteration"),
                "phase": context.get("phase"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "text": think,
            })

        # Record this exchange in the rolling history to maintain context
        self.conversation_history.append(
            {"role": "user", "content": f"State: {state_message}"}
        )
        self.conversation_history.append(
            {"role": "assistant", "content": final_response}
        )

        # Truncate the sliding window to prevent exceeding the 60k token limit
        if len(self.conversation_history) > MAX_HISTORY_MESSAGES:
            self.conversation_history = self.conversation_history[-MAX_HISTORY_MESSAGES:]

        return decision

    def feed_result(self, tool_name: str, result: Dict[str, Any]) -> None:
        """Injects the raw output of the MCP tool execution back into the LLM's memory."""
        self.conversation_history.append({
            "role": "user",
            "content": f"Tool '{tool_name}' returned:\n{json.dumps(result, indent=2, default=str)}",
        })

    def feed_note(self, note: str) -> None:
        """
        Injects a hard system directive into the conversation history.
        Used primarily for FSM guardrails (e.g. "endpoint exhausted, forcing pivot").
        """
        self.conversation_history.append({
            "role": "user",
            "content": f"[ORCHESTRATOR] {note}",
        })

    def feed_system(self, content: str) -> None:
        """
        Inject a system-role directive into the conversation history.

        Used for agentic self-correction: when a tool execution fails, the raw
        Python exception is formatted into a corrective system prompt and fed
        back so the model can analyse the failure and propose alternative
        parameters. The main SYSTEM_PROMPT is re-prepended fresh on every
        decide() call, so adding system messages here is safe even after the
        rolling-window truncation.
        """
        self.conversation_history.append({
            "role": "system",
            "content": content,
        })

    @staticmethod
    def _is_api_error(response: str) -> bool:
        """True if the LLM client returned an infrastructure error string."""
        return is_api_error(response)

    def _parse_decision(self, response: str) -> Dict[str, Any]:
        """Extracts and parses the final JSON payload, ignoring <think> reasoning blocks."""
        decision = extract_json_object(response, required_key="action")
        if decision is not None:
            return decision
        
        # If parsing fails entirely, grab a snippet for the error log
        snippet = response.strip()[:200]
        return {"action": "error", "detail": f"Could not parse K2 response: {snippet}"}

    # ------------------------------------------------------------------ #
    # Structured thought timeline                                         #
    # ------------------------------------------------------------------ #

    async def format_thoughts(self, llm_client: LLMClient | None = None) -> list[Dict[str, Any]]:
        """
        Convert the captured raw <think> reasoning into a strict JSON array
        describing a linear thought timeline:

            [{"step_title": str, "details": str, "timestamp": ISO}, ...]

        An LLM does the structuring (its output parsed via
        llm_json.extract_json_array), but this is fully offline-safe: with no
        captured reasoning, no API key, or any error, it falls back to a
        deterministic conversion of the raw thoughts so the timeline ALWAYS
        renders. Token usage from the formatting call is left on the supplied
        client's ``last_usage`` so the caller can fold it into a global counter.
        """
        if not self.raw_thoughts:
            return []

        client = llm_client or self.llm_client or LLMClient()
        structured: list | None = None

        # Only spend an API call when a key is configured; otherwise the
        # deterministic fallback below keeps the feature working offline.
        if getattr(client, "api_key", ""):
            try:
                payload = [
                    {
                        "index": i,
                        "timestamp": t.get("timestamp"),
                        "phase": t.get("phase"),
                        "reasoning": t.get("text", ""),
                    }
                    for i, t in enumerate(self.raw_thoughts)
                ]
                messages = [
                    {"role": "system", "content": THOUGHT_TIMELINE_PROMPT},
                    {"role": "user", "content": json.dumps(payload, default=str)},
                ]
                raw = await client.chat(messages, role="general")
                if isinstance(raw, str) and not is_api_error(raw):
                    parsed = extract_json_array(raw)
                    if isinstance(parsed, list):
                        structured = parsed
            except Exception:
                structured = None

        if structured is None:
            structured = self._fallback_timeline()

        return self._normalize_timeline(structured)

    def _fallback_timeline(self) -> list[Dict[str, Any]]:
        """Deterministically turn raw <think> blocks into timeline steps."""
        steps: list[Dict[str, Any]] = []
        for t in self.raw_thoughts:
            text = (t.get("text") or "").strip()
            if not text:
                continue
            # Use the first sentence as the step title, the rest as details.
            first = re.split(r"(?<=[.!?])\s+", text, maxsplit=1)[0].strip()
            title = first[:80] + ("..." if len(first) > 80 else "")
            steps.append({
                "step_title": title or "Reasoning step",
                "details": text[:600],
                "timestamp": t.get("timestamp"),
            })
        return steps

    def _normalize_timeline(self, steps: list) -> list[Dict[str, Any]]:
        """Validate/clean a timeline so every entry matches the strict schema."""
        fallback_ts = [t.get("timestamp") for t in self.raw_thoughts]
        normalized: list[Dict[str, Any]] = []
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            title = str(step.get("step_title") or step.get("title") or "").strip()
            details = str(step.get("details") or step.get("detail") or "").strip()
            if not title and not details:
                continue
            ts = step.get("timestamp")
            if not ts and i < len(fallback_ts):
                ts = fallback_ts[i]
            if not ts:
                ts = datetime.now(timezone.utc).isoformat()
            normalized.append({
                "step_title": title or "Reasoning step",
                "details": details,
                "timestamp": str(ts),
            })
        return normalized