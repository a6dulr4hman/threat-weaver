"""Blue team patch synthesis and syntax validation."""
import ast
import re
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Mitigation
from app.services.llm_client import LLMClient
from app.services.llm_json import extract_json_object


class RemediationService:
    """Generates security patches and validates them syntactically."""

    def __init__(self, llm_client: LLMClient | None = None):
        self.llm_client = llm_client or LLMClient()

    @staticmethod
    def clean_patch(raw: str) -> str:
        """
        Extract the actual patched code from a K2-Think-v2 response.

        K2 is a reasoning model: it emits a long <think>...</think> monologue
        ("We need to respond with only the fixed code...") followed by the real
        answer, often inside a ```python fenced block. The raw text was being
        stored/returned verbatim, which is why patches looked like rambling
        prose. This strips the reasoning and prefers the LAST fenced code block
        (the final answer), falling back to the de-thought text.
        """
        if not raw:
            return ""
        text = raw.strip()

        # Drop chain-of-thought reasoning blocks.
        text = re.sub(
            r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE
        )
        lower = text.lower()
        if "</think>" in lower:  # unbalanced/truncated reasoning tag
            text = text[lower.rfind("</think>") + len("</think>"):]
        text = re.sub(r"<think>", "", text, flags=re.IGNORECASE).strip()

        # Prefer the last fenced code block - reasoning models put the final
        # answer at the end.
        blocks = re.findall(
            r"```(?:python|py)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE
        )
        if blocks:
            return blocks[-1].strip()
        return text.strip()

    async def generate_patch(
        self, job_id: str, vuln_node: str, source_code: str
    ) -> dict:
        """
        Ask the LLM for a full structured security finding, not just code.

        Returns a dict with:
          description   – plain-English explanation of what the vulnerability is
          risk_level    – Critical / High / Medium / Low
          cves          – list of relevant CVE IDs (empty list if none)
          recommendation – concise one-paragraph fix strategy
          code          – the actual patched code (cleaned, no reasoning monologue)

        The LLM is instructed to reply with a JSON object so all fields come
        back in one call (same token budget, richer output).
        """
        system_prompt = (
            "You are a senior application security engineer writing a formal "
            "vulnerability report for a development team.\n\n"
            "Respond with EXACTLY ONE JSON object and no other text. "
            "Keep any chain-of-thought reasoning inside <think></think> tags "
            "BEFORE the JSON.\n\n"
            "Required JSON schema:\n"
            "{\n"
            '  "description": "<2-3 sentence plain-English explanation of what '
            'the vulnerability is and how it can be exploited>",\n'
            '  "risk_level": "<Critical|High|Medium|Low>",\n'
            '  "cves": ["CVE-YYYY-NNNNN", ...],\n'
            '  "recommendation": "<1-paragraph concise fix strategy without '
            'code - what the developer should do and why>",\n'
            '  "code": "<the complete patched code block that fixes the '
            'vulnerability>"\n'
            "}\n\n"
            "Rules:\n"
            "- cves must be an array (empty [] if no known CVE applies).\n"
            "- code must contain only the fixed code, no markdown fences, "
            "no explanatory prose.\n"
            "- risk_level must be exactly one of: Critical, High, Medium, Low."
        )
        user_prompt = (
            f"Vulnerability: {vuln_node}\n\n"
            f"Affected source code:\n```\n{source_code}\n```\n\n"
            "Produce the structured security finding JSON."
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ]
        raw = await self.llm_client.chat(messages, role="remediation")
        return self._parse_finding(raw, vuln_node)

    def _parse_finding(self, raw: str, vuln_node: str) -> dict:
        """
        Parse the LLM response into a structured finding dict.

        Tries structured JSON first; falls back gracefully so the pipeline
        never crashes on a malformed response.
        """
        fallback = {
            "description": f"Security vulnerability detected in {vuln_node}.",
            "risk_level": "High",
            "cves": [],
            "recommendation": "Review and remediate the identified vulnerability.",
            "code": self.clean_patch(raw),
        }

        obj = extract_json_object(raw, required_key="description")
        if obj is None:
            # Maybe the whole cleaned text is the code (old-style response).
            fallback["code"] = self.clean_patch(raw)
            return fallback

        return {
            "description":    str(obj.get("description", fallback["description"])),
            "risk_level":     str(obj.get("risk_level", "High")).capitalize(),
            "cves":           [str(c) for c in obj.get("cves", [])]
                              if isinstance(obj.get("cves"), list) else [],
            "recommendation": str(obj.get("recommendation",
                                          fallback["recommendation"])),
            "code":           self.clean_patch(str(obj.get("code", ""))),
        }

    def validate_syntax(self, code: str) -> bool:
        """
        Validate Python code syntax using ast.parse().
        For non-Python code, do a basic brace-matching heuristic.
        Returns True if code is syntactically valid.
        """
        # Try Python syntax validation first
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            pass

        # Fall back to basic brace-matching heuristic for non-Python code
        open_braces = 0
        open_brackets = 0
        open_parens = 0
        for char in code:
            if char == "{":
                open_braces += 1
            elif char == "}":
                open_braces -= 1
            elif char == "[":
                open_brackets += 1
            elif char == "]":
                open_brackets -= 1
            elif char == "(":
                open_parens += 1
            elif char == ")":
                open_parens -= 1

            if open_braces < 0 or open_brackets < 0 or open_parens < 0:
                return False

        return open_braces == 0 and open_brackets == 0 and open_parens == 0

    async def store_mitigation(
        self, db: AsyncSession, job_id: str, vuln_node: str, remediation_code: str
    ) -> Mitigation:
        """
        Create a Mitigation record in the database.
        """
        mitigation = Mitigation(
            id=str(uuid.uuid4()),
            job_id=job_id,
            vulnerability_node=vuln_node,
            remediation_code=remediation_code,
        )
        db.add(mitigation)
        await db.commit()
        await db.refresh(mitigation)
        return mitigation
