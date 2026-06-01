import httpx


async def verify_domain(target_url: str, expected_nonce: str) -> bool:
    """Verify domain ownership by checking for nonce at target_url/threatweaver.txt."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"https://{target_url}/threatweaver.txt")
            if response.status_code == 200 and response.text.strip() == expected_nonce:
                return True
            return False
    except Exception:
        return False
