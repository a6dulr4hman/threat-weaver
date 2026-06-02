"""K2-Think-v2 autonomous agent - the main reasoning driver.

K2-Think-v2 is a long chain-of-thought reasoning model: it "thinks out loud"
(often inside <think>...</think> tags) before producing a final answer. This
module is built around that reality - it extracts the actionable JSON decision
from a response that may be wrapped in reasoning prose, and retries with a
corrective nudge when the model forgets to emit parseable JSON.
"""
import json
import re

from app.services.llm_client import LLMClient

MAX_ITERATIONS = 20
MAX_HISTORY_MESSAGES = 20
# How many times to re-prompt K2 when its reply can't be parsed into a decision.
MAX_PARSE_RETRIES = 2

SYSTEM_PROMPT = """You are K2-Think-v2, the autonomous security analysis engine that DRIVES \
the ThreatWeaver vulnerability pipeline. You are in control and decide every action - \
the platform only executes the tool calls you choose.

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
- run_fuzzer: {"url": "https://domain.com/path", "payloads": [{"param": "q", "value": "..."}], "injection_type": "query|body"}
- execute_safe_poc: {"sandbox_id": "<id>", "script": "<python script>", "expected_signature": {...}}
- query_hackclub: {"component": "<name>", "version": "<version>"}
- generate_patch: {"vuln_node": "<id>", "source_code": "<code to fix>"}

Recommended workflow: start with reconnaissance (run_nmap), probe endpoints (run_fuzzer), \
verify findings in the sandbox (execute_safe_poc), look up known CVEs (query_hackclub), \
then generate_patch for each confirmed vulnerability. When no further useful action \
remains, return {"action": "complete", ...}.

Output rules (critical):
- The final line of your reply must be a single valid JSON object.
- Do NOT add any text after the JSON object.
- Do NOT wrap the JSON in markdown fences.
- If code analysis reports no source files (e.g. an unsupported language), rely on the \
live DAST tools against the target instead of giving up."""

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
            "code_analysis": context.get("code_analysis"),
            "attack_graph": context.get("attack_graph", {}),
            "iteration": context.get("iteration", 0),
            "available_tools": [
                "run_nmap", "run_fuzzer", "execute_safe_poc",
                "query_hackclub", "generate_patch",
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

    # --- Response parsing -------------------------------------------------

    def _parse_decision(self, response: str) -> dict:
        """Parse K2's (possibly reasoning-wrapped) response into a decision dict."""
        text = self._strip_reasoning(response)
        decision = self._extract_action_json(text)
        if decision is not None:
            return decision
        snippet = response.strip()[:200]
        return {"action": "error", "detail": f"Could not parse K2 response: {snippet}"}

    @staticmethod
    def _strip_reasoning(response: str) -> str:
        """Remove <think>...</think> reasoning blocks so only the answer remains."""
        text = response.strip()
        # Drop fully-formed reasoning blocks.
        text = re.sub(r"<think>.*?</think>", " ", text, flags=re.DOTALL | re.IGNORECASE)
        # If a closing tag remains (unbalanced), keep only what follows the last one.
        lower = text.lower()
        if "</think>" in lower:
            idx = lower.rfind("</think>")
            text = text[idx + len("</think>"):]
        # Drop any dangling opening tag.
        text = re.sub(r"<think>", " ", text, flags=re.IGNORECASE)
        return text.strip()

    @classmethod
    def _extract_action_json(cls, text: str) -> dict | None:
        """Find a JSON object containing an 'action' key within free-form text."""
        # 1) Markdown-fenced blocks (```json ... ``` or ``` ... ```).
        for block in re.findall(
            r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE
        ):
            obj = cls._load_action(block)
            if obj is not None:
                return obj

        # 2) Balanced-brace scan. Prefer the LAST valid object, since a reasoning
        #    model emits its final answer after the prose.
        valid = [
            obj
            for obj in (cls._load_action(c) for c in cls._iter_brace_objects(text))
            if obj is not None
        ]
        if valid:
            return valid[-1]

        # 3) Whole response as a single JSON document.
        return cls._load_action(text)

    @staticmethod
    def _load_action(candidate: str) -> dict | None:
        """json.loads a candidate string, returning it only if it has an 'action'."""
        candidate = candidate.strip()
        if not candidate:
            return None
        try:
            obj = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            return None
        if isinstance(obj, dict) and "action" in obj:
            return obj
        return None

    @staticmethod
    def _iter_brace_objects(text: str):
        """Yield top-level {...} substrings, ignoring braces inside JSON strings."""
        depth = 0
        start = None
        in_str = False
        escape = False
        quote = ""
        for i, ch in enumerate(text):
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote:
                    in_str = False
                continue
            if ch in ('"', "'"):
                in_str = True
                quote = ch
            elif ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start is not None:
                        yield text[start:i + 1]
                        start = None
