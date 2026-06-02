import asyncio

import dns.resolver
import httpx


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
    except Exception:
        pass
    return False


async def _check_http(target_url: str, expected_nonce: str) -> bool:
    """Fallback: check HTTP endpoint for nonce at target_url/threatweaver.txt."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"https://{target_url}/threatweaver.txt")
            if response.status_code == 200 and response.text.strip() == expected_nonce:
                return True
    except Exception:
        pass
    return False


async def verify_domain(target_url: str, expected_nonce: str) -> bool:
    """Verify domain ownership by checking DNS TXT record first, then HTTP fallback."""
    # Try DNS TXT record at _threatweaver.<domain>
    if await _check_dns_txt(target_url, expected_nonce):
        return True

    # Fallback to HTTP verification
    if await _check_http(target_url, expected_nonce):
        return True

    return False
