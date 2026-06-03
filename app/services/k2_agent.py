"""
K2-Think-v2 Autonomous Agent - The Cognitive Reasoning Engine

This module serves as the primary reasoning driver for the ThreatWeaver pipeline.
It utilizes the K2-Think-v2 model to perform a continuous Chain-of-Thought (CoT)
reasoning loop (ReAct). The agent is explicitly constrained to output actionable JSON
tool requests after its internal <think> process, preventing infinite hallucination loops.
"""

import json
from typing import Dict, Any

from app.services.llm_client import LLMClient
from app.services.llm_json import extract_json_object, is_api_error

# Guardrails to protect against infinite loops and token exhaustion
MAX_ITERATIONS = 20
MAX_HISTORY_MESSAGES = 20

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
   CLASSIFY BY THE OBSERVED TRIGGER, not by guesswork. A 500 / DB error caused
   by injecting a single quote (') or other SQL metacharacters into a parameter
   is SQL injection, NOT XSS — XSS means your markup was reflected verbatim into
   a 200 response, not that the server errored. Label the finding by the exact
   input that broke it and the exact behaviour you saw.
5. PIVOT: On a 500 or a connection drop, read what leaked, identify the parser
   or validation that broke, adjust your syntax, and fire a refined payload.

Once an anomaly is understood, confirm it with execute_safe_poc, then
generate_patch. Map run_nmap service banners to CVEs with query_hackclub.

USING execute_safe_poc (critical for confirmation):
The script you provide runs in a sandboxed Python subprocess. To confirm an
exploit you MUST make the script's verdict machine-readable:
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
  exploit_confirmed=true. If you have not observed one of those signals for a
  specific finding, do NOT generate a patch for it.

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
until the route map is exhausted or the budget runs out.

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


class K2Agent:
    """Autonomous agent that uses K2-Think-v2 to drive security analysis."""

    def __init__(self, llm_client: LLMClient | None = None):
        self.llm_client = llm_client or LLMClient()
        self.conversation_history: list[Dict[str, Any]] = []

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