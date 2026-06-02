"""K2-Think-v2 autonomous agent - the main reasoning driver."""
import json

from app.services.llm_client import LLMClient

MAX_ITERATIONS = 20

SYSTEM_PROMPT = """You are K2-Think-v2, the autonomous security analysis engine for ThreatWeaver.
You drive the entire vulnerability analysis pipeline. Given the current analysis state, 
you decide what action to take next.

Available tools:
- run_nmap: Scan target for open ports. Args: {"target": "domain.com", "port_range": "1-1024"}
- run_fuzzer: Fuzz endpoints for vulnerabilities. Args: {"url": "https://...", "payloads": [...], "injection_type": "query|body"}
- execute_safe_poc: Execute proof-of-concept in sandbox. Args: {"sandbox_id": "...", "script": "...", "expected_signature": {...}}
- query_hackclub: Search for known CVEs. Args: {"component": "...", "version": "..."}
- generate_patch: Generate remediation code. Args: {"vuln_node": "...", "source_code": "..."}

Respond with EXACTLY one JSON object (no markdown, no extra text):
- To call a tool: {"action": "tool_call", "tool": "<tool_name>", "arguments": {...}, "reasoning": "why this action"}
- When analysis is complete: {"action": "complete", "summary": "what was found and fixed"}

Always think step by step. Start with reconnaissance, then test for vulnerabilities, 
verify exploits, and finally generate patches."""


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
        Returns parsed decision dict with 'action' key.
        Falls back to {"action": "error", ...} on parse errors.
        """
        state_message = self.build_state_message(context)

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            *self.conversation_history,
            {"role": "user", "content": f"Current analysis state:\n{state_message}\n\nWhat should we do next?"},
        ]

        response = await self.llm_client.chat(messages, role="agent")

        # Track conversation
        self.conversation_history.append({"role": "user", "content": f"State: {state_message}"})
        self.conversation_history.append({"role": "assistant", "content": response})

        # Parse K2's response
        return self._parse_decision(response)

    def feed_result(self, tool_name: str, result: dict) -> None:
        """Feed tool execution results back into conversation history."""
        self.conversation_history.append({
            "role": "user",
            "content": f"Tool '{tool_name}' returned:\n{json.dumps(result, indent=2, default=str)}",
        })

    def _parse_decision(self, response: str) -> dict:
        """Parse K2's JSON response into a decision dict."""
        # Try to extract JSON from the response
        response = response.strip()

        # Handle markdown code blocks
        if "```json" in response:
            start = response.index("```json") + 7
            end = response.index("```", start)
            response = response[start:end].strip()
        elif "```" in response:
            start = response.index("```") + 3
            end = response.index("```", start)
            response = response[start:end].strip()

        try:
            decision = json.loads(response)
            if "action" in decision:
                return decision
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback: if we can't parse, signal error to avoid infinite loop
        return {"action": "error", "detail": f"Could not parse K2 response: {response[:200]}"}
