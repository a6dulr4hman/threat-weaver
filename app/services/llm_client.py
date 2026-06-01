"""K2-Think-v2 API client.

Talks to the K2-Think chat completions endpoint
(https://api.k2think.ai/v1/chat/completions) using the
``MBZUAI-IFM/K2-Think-v2`` model. The endpoint is fronted by Cloudflare, so the
same gateway constraints apply:

* hard request timeout of 120 seconds (2 minutes)
* a 60,000 token context budget
* a strict ceiling of 30 requests per minute
"""
import asyncio
import os
import time

import httpx
from dotenv import load_dotenv

load_dotenv()

# K2-Think endpoint + model identifiers.
K2_BASE_URL = "https://api.k2think.ai/v1/chat/completions"
K2_MODEL = "MBZUAI-IFM/K2-Think-v2"

# Gateway constraints.
REQUEST_TIMEOUT = 120.0  # seconds (Cloudflare 2-minute hard cap)
MAX_TOKENS = 60000  # context window ceiling
RATE_LIMIT_REQUESTS = 30  # requests ...
RATE_LIMIT_PERIOD = 60.0  # ... per this many seconds


class _AsyncRateLimiter:
    """Async token-bucket rate limiter.

    Refills ``rate`` tokens over every ``period`` seconds. ``acquire`` blocks
    until a token is available, smoothing bursts so we never exceed the
    configured requests-per-minute ceiling.
    """

    def __init__(self, rate: int, period: float):
        self.rate = rate
        self.period = period
        self.tokens = float(rate)
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.updated
                # Refill proportionally to elapsed time, capped at capacity.
                self.tokens = min(
                    float(self.rate),
                    self.tokens + elapsed * (self.rate / self.period),
                )
                self.updated = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return

                # Not enough budget yet: sleep until one token has refilled.
                deficit = 1 - self.tokens
                wait_time = deficit * (self.period / self.rate)
                await asyncio.sleep(wait_time)


# Module-level limiter shared across all LLMClient instances so the
# 30 requests/minute ceiling is enforced globally, not per-job.
_RATE_LIMITER = _AsyncRateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_PERIOD)


class LLMClient:
    """K2-Think-v2 client with 120s timeout, 60k token guard, and 30 rpm cap."""

    def __init__(self):
        self.api_key = os.getenv("K2_API_KEY", "")
        self.base_url = K2_BASE_URL
        self.model = K2_MODEL
        self.timeout = REQUEST_TIMEOUT
        self.max_tokens = MAX_TOKENS

    def token_guard(self, messages: list[dict], max_tokens: int = MAX_TOKENS) -> list[dict]:
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
        Send a chat completion request to the K2-Think-v2 API.

        Enforces the global 30 requests/minute rate limit, applies the 60k
        token guard, and uses a 120s request timeout.
        """
        # Apply token guard preserving message structure.
        messages = self.token_guard(messages, self.max_tokens)

        # Block until the rate limiter grants a slot (<= 30 req/min).
        await _RATE_LIMITER.acquire()

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }

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
                return self._extract_content(data)
        except httpx.TimeoutException:
            return "Error: Request timed out (120s limit)"
        except Exception as e:
            return f"Error: {str(e)}"

    @staticmethod
    def _extract_content(data: dict) -> str:
        """Extract the assistant message from an OpenAI-compatible response."""
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            message = choices[0].get("message", {})
            content = message.get("content")
            if content is not None:
                return content
        return str(data)
