from __future__ import annotations

import asyncio
import logging
import os

import dns.exception
import dns.resolver
import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cloudflare DNS-over-HTTPS (DoH) helper
# ---------------------------------------------------------------------------
# Uses Cloudflare's 1.1.1.1 DoH endpoint — free, fastest public resolver,
# works over HTTPS so no blocked-UDP-port issues on cloud hosts. Falls back
# to the system DNS resolver (dnspython) if the DoH request fails.

_CF_DOH = "https://cloudflare-dns.com/dns-query"


async def _doh_txt(name: str) -> list[str]:
    """
    Query Cloudflare DoH for TXT records on *name*.
    Returns a list of decoded TXT string values (may be empty).
    Raises on network / HTTP errors so callers can fall back to system DNS.
    """
    async with httpx.AsyncClient(timeout=8.0) as client:
        resp = await client.get(
            _CF_DOH,
            params={"name": name, "type": "TXT"},
            headers={"Accept": "application/dns-json"},
        )
        resp.raise_for_status()
        data = resp.json()
    values: list[str] = []
    for answer in data.get("Answer") or []:
        if answer.get("type") == 16:          # 16 = TXT
            raw = answer.get("data", "")
            # Cloudflare wraps TXT data in double-quotes; strip them.
            values.append(raw.strip().strip('"'))
    return values


async def _resolve_txt(name: str) -> list[str]:
    """
    Resolve TXT records for *name* — Cloudflare DoH first, system DNS fallback.
    Returns a (possibly empty) list of string values.
    """
    try:
        return await _doh_txt(name)
    except Exception as e:
        logger.debug("Cloudflare DoH failed for %s (%s), falling back to system DNS", name, e)

    # System-DNS fallback (dnspython, synchronous — run in executor).
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None, dns.resolver.resolve, name, "TXT"
        )
        return [
            t.decode().strip()
            for rdata in answers
            for t in rdata.strings
        ]
    except Exception as e:
        logger.warning("System DNS TXT lookup for %s failed: %s: %s",
                       name, type(e).__name__, e)
        return []

# TEMPORARY: when MOCK_VERIFICATION is enabled, verify_domain auto-accepts every
# domain without performing the real DNS/HTTP checks. This is a stopgap while the
# DNS TXT verification flow is being debugged. Remove once that is fixed.
_TRUTHY = {"1", "true", "yes", "on"}


def _mock_verification_enabled() -> bool:
    """Read the bypass flag at call time so it can be toggled per-environment."""
    return os.getenv("MOCK_VERIFICATION", "").strip().lower() in _TRUTHY


async def _check_dns_txt(target_url: str, expected_nonce: str) -> bool:
    """Check DNS TXT record at _threatweaver.<domain> for the expected nonce.

    Uses Cloudflare DoH (fastest free resolver) with a system-DNS fallback.
    """
    qname = f"_threatweaver.{target_url}"
    values = await _resolve_txt(qname)
    matched = any(v == expected_nonce for v in values)
    if not matched and values:
        logger.info(
            "DNS nonce mismatch for %s: expected %r, got %r",
            qname, expected_nonce, values,
        )
    return matched


async def lookup_txt_values(target_url: str) -> tuple[list[str], str | None]:
    """
    Read-only diagnostic: return the TXT values currently at
    _threatweaver.<domain>, plus a human-readable error if the lookup failed.

    Used only to explain WHY verification failed -- never affects the verdict.
    """
    qname = f"_threatweaver.{target_url}"
    try:
        values = await _doh_txt(qname)
        if values:
            return values, None
        # DoH returned no answers — try system DNS for more specific error.
    except Exception as doh_err:
        logger.debug("DoH diagnostic lookup failed for %s: %s", qname, doh_err)

    # System-DNS fallback with specific error classification.
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None, dns.resolver.resolve, qname, "TXT"
        )
        values = [t.decode().strip() for rdata in answers for t in rdata.strings]
        return values, None
    except dns.resolver.NXDOMAIN:
        return [], (
            f"No DNS record exists at {qname} (NXDOMAIN). "
            "Add a TXT record with the nonce shown above."
        )
    except dns.resolver.NoAnswer:
        return [], f"{qname} resolves but has no TXT record."
    except dns.exception.Timeout:
        return [], (
            "DNS query timed out. The ThreatWeaver server may not have "
            "outbound DNS access. Try adding the record and waiting for propagation."
        )
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
