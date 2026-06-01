"""Resend SDK integration with severity-based routing matrix."""
import asyncio
import os
from pathlib import Path

import resend
from jinja2 import Environment, FileSystemLoader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RoutingConfig

# Severity routing matrix
SEVERITY_ROUTING = {
    "extreme": {"to_roles": ["ciso", "head_of_security"], "cc_roles": []},
    "high": {"to_roles": ["head_of_security"], "cc_roles": ["head_engineer"]},
    "medium": {"to_roles": ["head_engineer"], "cc_roles": ["head_of_security"]},
    "low": {"to_roles": ["head_engineer"], "cc_roles": []},
}


class NotifierService:
    """Sends severity-graded email alerts via Resend API."""

    def __init__(self):
        self.api_key = os.getenv("RESEND_API_KEY", "")
        resend.api_key = self.api_key
        template_dir = Path(__file__).parent.parent / "templates" / "email"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))

    async def get_recipients(
        self, db: AsyncSession, severity: str
    ) -> tuple[list[str], list[str]]:
        """
        Look up email addresses from routing_config table based on severity routing matrix.
        Returns (to_list, cc_list) of email addresses.
        """
        routing = SEVERITY_ROUTING.get(severity, {"to_roles": [], "cc_roles": []})

        to_list = []
        cc_list = []

        # Get TO recipients
        for role in routing["to_roles"]:
            stmt = select(RoutingConfig).where(RoutingConfig.role == role)
            result = await db.execute(stmt)
            config = result.scalar_one_or_none()
            if config:
                to_list.append(config.email_address)

        # Get CC recipients
        for role in routing["cc_roles"]:
            stmt = select(RoutingConfig).where(RoutingConfig.role == role)
            result = await db.execute(stmt)
            config = result.scalar_one_or_none()
            if config:
                cc_list.append(config.email_address)

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
    ) -> bool:
        """
        Send severity-routed email alert.
        Returns True on success, False on failure.
        """
        if not self.api_key:
            return False

        to_list, cc_list = await self.get_recipients(db, severity)

        if not to_list:
            return False

        html_content = self.render_email(severity, attack_graph, job_id)

        try:
            params = {
                "from": "ThreatWeaver <alerts@threatweaver.dev>",
                "to": to_list,
                "subject": f"[{severity.upper()}] ThreatWeaver Security Alert - Job {job_id[:8]}",
                "html": html_content,
            }
            if cc_list:
                params["cc"] = cc_list

            await asyncio.to_thread(resend.Emails.send, params)
            return True
        except Exception:
            return False
