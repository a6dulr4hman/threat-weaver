"""Blue team patch synthesis and syntax validation."""
import ast
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Mitigation
from app.services.llm_client import LLMClient


class RemediationService:
    """Generates security patches and validates them syntactically."""

    def __init__(self, llm_client: LLMClient | None = None):
        self.llm_client = llm_client or LLMClient()

    async def generate_patch(
        self, job_id: str, vuln_node: str, source_code: str
    ) -> str:
        """
        Ask the LLM to generate a security fix for the vulnerability.
        Returns the remediation code string.
        """
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a security engineer. Generate a minimal code patch "
                    "that fixes the described vulnerability. Return only the fixed code."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Vulnerability: {vuln_node}\n\n"
                    f"Source code:\n```\n{source_code}\n```\n\n"
                    "Provide the patched code that fixes this vulnerability."
                ),
            },
        ]
        return await self.llm_client.chat(messages, role="remediation")

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
