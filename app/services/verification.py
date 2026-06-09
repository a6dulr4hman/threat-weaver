from __future__ import annotations

import asyncio
import logging
import os

import dns.exception
import dns.resolver
import httpx

logger = logging.getLogger(__name__)

# TEMPORARY: when MOCK_VERIFICATION is enabled, verify_domain auto-accepts every
# domain without performing the real DNS/HTTP checks. This is a stopgap while the
# DNS TXT verification flow is being debugged. Remove once that is fixed.
_TRUTHY = {"1", "true", "yes", "on"}


def _mock_verification_enabled() -> bool:
    """Read the bypass flag at call time so it can be toggled per-environment."""
    return os.getenv("MOCK_VERIFICATION", "").strip().lower() in _TRUTHY


async def _check_dns_txt(target_url: str, expected_nonce: str) -> bool:
    """Check DNS TXT record at _threatweaver.<domain> for the expected nonce."""
    try:
        qname = f"_threatweaver.{target_url}"
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(None, dns.resolver.resolve, qname, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode().strip() == expected_nonce:
                    return True
    except Exception as e:
        logger.warning("DNS TXT check for %s failed: %s: %s",
                       target_url, type(e).__name__, e)
    return False


async def lookup_txt_values(target_url: str) -> tuple[list[str], str | None]:
    """
    Read-only diagnostic: return the TXT values currently at
    _threatweaver.<domain>, plus a human-readable error if the lookup failed.

    Used only to explain WHY verification failed -- never affects the verdict.
    """
    qname = f"_threatweaver.{target_url}"
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(None, dns.resolver.resolve, qname, "TXT")
        values = [t.decode().strip() for rdata in answers for t in rdata.strings]
        return values, None
    except dns.resolver.NXDOMAIN:
        return [], f"No DNS record exists at {qname} (NXDOMAIN). Add a TXT record there."
    except dns.resolver.NoAnswer:
        return [], f"{qname} resolves but has no TXT record."
    except dns.exception.Timeout:
        return [], ("DNS query timed out -- the ThreatWeaver server may not have "
                    "outbound DNS access.")
    except Exception as e:
        return [], f"DNS lookup error for {qname}: {type(e).__name__}: {e}"


async def _check_http(target_url: str, expected_nonce: str) -> bool:
    """Fallback: check HTTP endpoint for nonce at target_url/threatweaver.txt."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"https://{target_url}/threatweaver.txt")
            if response.status_code == 200 and response.text.strip() == expected_nonce:
                return True
    except Exception as e:
        logger.warning("HTTP verification check for %s failed: %s: %s",
                       target_url, type(e).__name__, e)
    return False


async def verify_domain(target_url: str, expected_nonce: str) -> bool:
    """Verify domain ownership by checking DNS TXT record first, then HTTP fallback."""
    # TEMPORARY bypass: auto-accept when MOCK_VERIFICATION is enabled.
    if _mock_verification_enabled():
        logger.warning(
            "MOCK_VERIFICATION enabled - auto-accepting domain '%s' without a real "
            "ownership check. Disable this before production.",
            target_url,
        )
        return True

    # Try DNS TXT record at _threatweaver.<domain>
    if await _check_dns_txt(target_url, expected_nonce):
        return True

    # Fallback to HTTP verification
    if await _check_http(target_url, expected_nonce):
        return True

    return False
