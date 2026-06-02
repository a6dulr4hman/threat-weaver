"""K2-Think-v2 autonomous agent - the main reasoning driver.

K2-Think-v2 is a long chain-of-thought reasoning model: it "thinks out loud"
(often inside <think>...</think> tags) before producing a final answer. This
module is built around that reality - it extracts the actionable JSON decision
from a response that may be wrapped in reasoning prose, and retries with a
corrective nudge when the model forgets to emit parseable JSON.
"""
import json

from app.services.llm_client import LLMClient
from app.services.llm_json import extract_json_object, is_api_error

MAX_ITERATIONS = 20
MAX_HISTORY_MESSAGES = 20
# How many times to re-prompt K2 when its reply can't be parsed into a decision.
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
- send_http_request: {"method": "GET|POST|PUT|PATCH|DELETE", "endpoint": "http://host/path", "headers": {...}, "json_body": {...}, "params": {...}}
- execute_safe_poc: {"sandbox_id": "<id>", "script": "<python script>", "expected_signature": {...}}
- query_hackclub: {"component": "<name>", "version": "<version>"}
- generate_patch: {"vuln_node": "<id>", "source_code": "<code to fix>"}

CORE METHOD - the Context-Aware Exploitation Loop (ReAct):
`send_http_request` is your primary weapon: a RAW HTTP primitive. You send ONE
request at a time, read the exact response, and engineer the NEXT payload from
what you observed. Adapt sequentially - do not request batch payload sweeps.

1. OBSERVE: Use the source-derived route map (provided as `routes`) to pick a
   REAL endpoint and its expected inputs. NEVER guess commodity paths like
   /api/v1/customers - if it is not in `routes` or the code analysis, it almost
   certainly does not exist (you will just collect 404s).
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
5. PIVOT: On a 500 or a connection drop, read what leaked, identify the parser
   or validation that broke, adjust your syntax, and fire a refined payload.

Once an anomaly is understood, confirm it with execute_safe_poc, then
generate_patch. Map run_nmap service banners to CVEs with query_hackclub.

GUARDRAILS (important):
- At most THREE attack attempts per endpoint. A 500, a stack trace, or a
  connection drop counts as an anomaly and RESETS that budget (you have a lead).
  Three benign responses in a row exhaust the endpoint - the orchestrator will
  say so, and you must move on.
- Watch the iteration counter; finish with {"action": "complete", ...} when no
  useful action remains. This protects the token budget and 120s gateway timeout.

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
        self.conversation_history: list[dict] = []

    def build_state_message(self, context: dict) -> str:
        """Format current analysis state for K2."""
        return json.dumps({
            "current_phase": context.get("phase", "ready"),
            "target": context.get("target"),
            "routes": context.get("routes", []),
            "code_analysis": context.get("code_analysis"),
            "attack_graph": context.get("attack_graph", {}),
            "endpoint_attempts": context.get("endpoint_attempts", {}),
            "exhausted_endpoints": context.get("exhausted_endpoints", []),
            "iteration": context.get("iteration", 0),
            "available_tools": [
                "run_nmap", "send_http_request",
                "execute_safe_poc", "query_hackclub", "generate_patch",
            ],
        }, indent=2)

    async def decide(self, context: dict) -> dict:
        """
        Send current state to K2 and get its decision.

        Because K2 is a reasoning model that occasionally omits clean JSON, this
        retries up to MAX_PARSE_RETRIES times with a corrective nudge before
        giving up. Returns a parsed decision dict with an 'action' key, or
        {"action": "error", ...} if parsing fails on every attempt.
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

            # Infrastructure errors (403, timeouts, rate limits) come back as
            # "Error: ..." strings from the LLM client. Re-prompting with a
            # formatting nudge won't help and just burns the rate-limit budget,
            # so surface a clear API error and stop retrying.
            if self._is_api_error(response):
                decision = {
                    "action": "error",
                    "detail": f"K2 API error: {response[len('Error: '):].strip()}",
                    "api_error": True,
                }
                break

            parsed = self._parse_decision(response)
            decision = parsed
            if parsed.get("action") != "error":
                break
            # Couldn't parse - nudge K2 to emit JSON only, then try again.
            attempt_messages = attempt_messages + [
                {"role": "assistant", "content": response},
                {"role": "user", "content": CORRECTION_PROMPT},
            ]

        # Record this exchange in the rolling history (state + final response).
        self.conversation_history.append(
            {"role": "user", "content": f"State: {state_message}"}
        )
        self.conversation_history.append(
            {"role": "assistant", "content": final_response}
        )

        # Sliding window: keep only the last MAX_HISTORY_MESSAGES messages
        if len(self.conversation_history) > MAX_HISTORY_MESSAGES:
            self.conversation_history = self.conversation_history[-MAX_HISTORY_MESSAGES:]

        return decision

    def feed_result(self, tool_name: str, result: dict) -> None:
        """Feed tool execution results back into conversation history."""
        self.conversation_history.append({
            "role": "user",
            "content": f"Tool '{tool_name}' returned:\n{json.dumps(result, indent=2, default=str)}",
        })

    def feed_note(self, note: str) -> None:
        """
        Inject an orchestrator-authored note into the conversation history.

        Used for guardrail messages (e.g. "endpoint X exhausted after 3
        attempts, move on") so the agent's next decision is grounded in the
        orchestrator's enforcement, not just its own reasoning.
        """
        self.conversation_history.append({
            "role": "user",
            "content": f"[ORCHESTRATOR] {note}",
        })

    # --- Response parsing -------------------------------------------------

    @staticmethod
    def _is_api_error(response: str) -> bool:
        """True if the LLM client returned an infrastructure error string."""
        return is_api_error(response)

    def _parse_decision(self, response: str) -> dict:
        """Parse K2's (possibly reasoning-wrapped) response into a decision dict."""
        decision = extract_json_object(response, required_key="action")
        if decision is not None:
            return decision
        snippet = response.strip()[:200]
        return {"action": "error", "detail": f"Could not parse K2 response: {snippet}"}
