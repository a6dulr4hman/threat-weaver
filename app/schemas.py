from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional

from pydantic import BaseModel, field_validator


class WorkspaceCreate(BaseModel):
    target_url: str

    @field_validator("target_url")
    @classmethod
    def reject_private_targets(cls, v: str) -> str:
        """Reject IP addresses, localhost, and private/reserved ranges."""
        # Strip protocol if present for validation
        host = v
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        # Strip path and port
        host = host.split("/")[0].split(":")[0]

        # Reject localhost
        if host.lower() in ("localhost", "localhost.localdomain"):
            raise ValueError("Private/reserved targets are not allowed")

        # Try to parse as IP address
        try:
            ip = ipaddress.ip_address(host)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                raise ValueError("Private/reserved targets are not allowed")
            # Also reject any IP address (we only allow domain names)
            raise ValueError("IP addresses are not allowed as targets")
        except ValueError as e:
            if "not allowed" in str(e):
                raise
            # Not a valid IP, continue checking as domain

        # Reject metadata endpoint patterns (169.254.x.x already caught above)
        # Additional check for encoded/alternate representations
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            raise ValueError("IP addresses are not allowed as targets")

        return v


class WorkspaceResponse(BaseModel):
    id: str
    target_url: str
    verification_nonce: str
    verification_status: bool

    model_config = {"from_attributes": True}


class JobCreate(BaseModel):
    workspace_id: str


class JobResponse(BaseModel):
    id: str
    workspace_id: str
    status: str
    overall_severity: Optional[str] = None
    attack_graph_data: Any = None

    model_config = {"from_attributes": True}


class MitigationResponse(BaseModel):
    id: str
    job_id: str
    vulnerability_node: str
    remediation_code: Optional[str] = None

    model_config = {"from_attributes": True}


class RoutingConfigCreate(BaseModel):
    role: str
    email_address: str


class RoutingConfigResponse(BaseModel):
    role: str
    email_address: str

    model_config = {"from_attributes": True}
