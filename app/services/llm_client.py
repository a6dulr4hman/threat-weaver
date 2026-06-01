"""K2-Think-v2 API client via Cloudflare AI Gateway."""
import os

import httpx
from dotenv import load_dotenv

load_dotenv()


class LLMClient:
    """LLM client with 120s timeout and 60k token guard."""

    def __init__(self):
        self.account_id = os.getenv("CF_ACCOUNT_ID", "")
        self.api_token = os.getenv("CF_API_TOKEN", "")
        self.base_url = (
            f"https://gateway.ai.cloudflare.com/v1/{self.account_id}"
            f"/threatweaver/workers-ai/@cf/qwen/qwen2.5-coder-32b-instruct"
        )
        self.timeout = 120.0
        self.max_tokens = 60000

    def token_guard(self, messages: list[dict], max_tokens: int = 60000) -> list[dict]:
        """
        Estimate token count (~4 chars per token) across all messages.
        If total exceeds max_tokens, truncate user message content from the end
        while preserving system messages intact and maintaining message structure.
        Returns the (possibly truncated) message list.
        """
        total_chars = sum(len(msg.get("content", "")) for msg in messages)
        estimated_tokens = total_chars // 4

        if estimated_tokens <= max_tokens:
            return messages

        # Calculate how many characters we need to cut
        max_chars = max_tokens * 4
        excess = total_chars - max_chars

        # Preserve system messages, truncate user/assistant messages from the end
        result = []
        chars_to_trim = excess

        # Process messages in reverse to trim from latest user messages first
        reversed_messages = list(reversed(messages))
        trimmed_reversed = []

        for msg in reversed_messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if role == "system":
                # Never truncate system messages
                trimmed_reversed.append(msg)
            elif chars_to_trim > 0:
                content_len = len(content)
                if chars_to_trim >= content_len:
                    # Remove all content from this message but keep the message
                    chars_to_trim -= content_len
                    trimmed_reversed.append({"role": role, "content": ""})
                else:
                    # Truncate from the end of this message
                    trimmed_content = content[: content_len - chars_to_trim]
                    chars_to_trim = 0
                    trimmed_reversed.append({"role": role, "content": trimmed_content})
            else:
                trimmed_reversed.append(msg)

        # Reverse back to original order, filter out empty non-system messages
        result = [
            msg
            for msg in reversed(trimmed_reversed)
            if msg.get("content") or msg.get("role") == "system"
        ]

        return result

    async def chat(self, messages: list[dict], role: str = "general") -> str:
        """
        Send chat completion request to Cloudflare AI Gateway.
        """
        # Apply token guard preserving message structure
        messages = self.token_guard(messages, self.max_tokens)

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }
        payload = {"messages": messages}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self.base_url,
                    headers=headers,
                    json=payload,
                )
                if resp.status_code != 200:
                    return f"Error: API returned status {resp.status_code}"
                data = resp.json()
                # Cloudflare Workers AI response format
                result = data.get("result", {})
                if isinstance(result, dict):
                    return result.get("response", str(data))
                return str(result)
        except httpx.TimeoutException:
            return "Error: Request timed out (120s limit)"
        except Exception as e:
            return f"Error: {str(e)}"
