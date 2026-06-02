"""Resend SDK integration with K2-driven, severity-based recipient routing."""
import asyncio
import json
import os
from pathlib import Path

import resend
from jinja2 import Environment, FileSystemLoader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RoutingConfig
from app.services.llm_client import LLMClient
from app.services.llm_json import extract_json_object, is_api_error

# Fallback severity routing matrix. Used only when K2 is unavailable or returns
# an unusable response. K2 is the primary decision-maker for recipients.
SEVERITY_ROUTING = {
    "extreme": {"to_roles": ["ciso", "head_of_security"], "cc_roles": []},
    "high": {"to_roles": ["head_of_security"], "cc_roles": ["head_engineer"]},
    "medium": {"to_roles": ["head_engineer"], "cc_roles": ["head_of_security"]},
    "low": {"to_roles": ["head_engineer"], "cc_roles": []},
}

ROUTING_SYSTEM_PROMPT = """You are K2-Think-v2 acting as the alert-routing dispatcher for \
ThreatWeaver, a security scanner. Given a finding's severity and the list of available \
recipient roles (each with a saved email address), decide who should receive the alert.

Routing principles:
- More severe findings escalate to senior/executive roles (e.g. CISO, Head of Security).
- Less severe findings go to engineering/operational roles.
- "to" recipients are the primary owners; "cc" recipients are kept informed.
- Only choose from the roles provided. Never invent roles or email addresses.
- Pick at least one "to" recipient if any role is available.

Respond with EXACTLY one JSON object and nothing else:
{"to_roles": ["role1", ...], "cc_roles": ["role2", ...], "reasoning": "<one short sentence>"}"""


class NotifierService:
    """Sends severity-graded email alerts via Resend, with K2-chosen recipients."""

    def __init__(self, llm_client: LLMClient | None = None):
        self.api_key = os.getenv("RESEND_API_KEY", "")
        resend.api_key = self.api_key
        template_dir = Path(__file__).parent.parent / "templates" / "email"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        self.llm_client = llm_client or LLMClient()

    async def _load_routing_configs(self, db: AsyncSession) -> dict[str, str]:
        """Return all saved {role: email_address} entries from routing_config."""
        result = await db.execute(select(RoutingConfig))
        return {c.role: c.email_address for c in result.scalars().all()}

    async def _choose_roles_with_k2(
        self, severity: str, available: dict[str, str]
    ) -> tuple[list[str], list[str]] | None:
        """
        Ask K2 to choose which saved roles should be emailed for this severity.

        Returns (to_roles, cc_roles) limited to roles that actually exist in
        ``available``, or None if K2 was unavailable / returned nothing usable
        (caller then falls back to the static matrix).
        """
        if not available:
            return None

        roles_payload = [
            {"role": role, "email": email} for role, email in available.items()
        ]
        user_msg = (
            f"Finding severity: {severity}\n"
            f"Available recipient roles:\n{json.dumps(roles_payload, indent=2)}\n\n"
            "Choose the recipients. Respond with one JSON object only."
        )
        messages = [
            {"role": "system", "content": ROUTING_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ]

        response = await self.llm_client.chat(messages, role="routing")
        if is_api_error(response):
            return None

        decision = extract_json_object(response, required_key="to_roles")
        if decision is None:
            return None

        # Keep only roles that genuinely exist; ignore any hallucinated ones.
        to_roles = [r for r in decision.get("to_roles", []) if r in available]
        cc_roles = [
            r for r in decision.get("cc_roles", []) if r in available and r not in to_roles
        ]
        if not to_roles:
            return None
        return to_roles, cc_roles

    def _fallback_roles(
        self, severity: str, available: dict[str, str]
    ) -> tuple[list[str], list[str]]:
        """Static severity-matrix routing, filtered to roles that exist."""
        routing = SEVERITY_ROUTING.get(severity, {"to_roles": [], "cc_roles": []})
        to_roles = [r for r in routing["to_roles"] if r in available]
        cc_roles = [r for r in routing["cc_roles"] if r in available]
        # If the configured roles aren't present, fall back to emailing everyone
        # saved so an alert is never silently dropped.
        if not to_roles and available:
            to_roles = list(available.keys())
        return to_roles, cc_roles

    async def get_recipients(
        self, db: AsyncSession, severity: str
    ) -> tuple[list[str], list[str]]:
        """
        Resolve the (to, cc) email lists for a given severity.

        K2 is asked to choose recipients from the saved roles; if it is
        unavailable or returns nothing usable, the static SEVERITY_ROUTING
        matrix is used instead. Role names are resolved to email addresses.
        """
        available = await self._load_routing_configs(db)
        if not available:
            return [], []

        chosen = await self._choose_roles_with_k2(severity, available)
        if chosen is None:
            to_roles, cc_roles = self._fallback_roles(severity, available)
        else:
            to_roles, cc_roles = chosen

        to_list = [available[r] for r in to_roles if r in available]
        cc_list = [available[r] for r in cc_roles if r in available]
        return to_list, cc_list

    def render_email(self, severity: str, attack_graph: dict, job_id: str) -> str:
        """Render the appropriate email template for the severity level."""
        try:
            template = self.env.get_template(f"{severity}.html")
            return template.render(attack_graph=attack_graph, job_id=job_id)
        except Exception:
            # Fallback to plain text if template not found
            return (
                f"ThreatWeaver Alert - Severity: {severity.upper()}\n\n"
                f"Job ID: {job_id}\n"
                f"Attack Graph: {attack_graph}"
            )

    async def send_alert(
        self, db: AsyncSession, job_id: str, severity: str, attack_graph: dict
    ) -> dict:
        """
        Send a severity-routed email alert.

        Returns a structured status dict so the caller (and the user) can SEE
        exactly what happened instead of a silent bool. Possible "status"
        values: "sent", "skipped" (with a reason), or "failed" (with an error).
        """
        if not self.api_key:
            return {
                "status": "skipped",
                "reason": "RESEND_API_KEY is not set; cannot send email.",
                "to": [],
                "cc": [],
                "severity": severity,
            }

        to_list, cc_list = await self.get_recipients(db, severity)

        if not to_list:
            return {
                "status": "skipped",
                "reason": (
                    "No recipients resolved. Add routing rules at /config "
                    "(e.g. roles 'ciso', 'head_of_security', 'head_engineer')."
                ),
                "to": [],
                "cc": [],
                "severity": severity,
            }

        from_addr = os.getenv(
            "RESEND_FROM", "ThreatWeaver <alerts@threatweaver.dev>"
        )
        html_content = self.render_email(severity, attack_graph, job_id)

        try:
            params = {
                "from": from_addr,
                "to": to_list,
                "subject": f"[{severity.upper()}] ThreatWeaver Security Alert - Job {job_id[:8]}",
                "html": html_content,
            }
            if cc_list:
                params["cc"] = cc_list

            send_result = await asyncio.to_thread(resend.Emails.send, params)
            message_id = None
            if isinstance(send_result, dict):
                message_id = send_result.get("id")
            return {
                "status": "sent",
                "to": to_list,
                "cc": cc_list,
                "severity": severity,
                "message_id": message_id,
            }
        except Exception as e:
            return {
                "status": "failed",
                "reason": f"Resend API error: {e}",
                "to": to_list,
                "cc": cc_list,
                "severity": severity,
            }
