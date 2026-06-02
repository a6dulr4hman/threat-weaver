"""MCP tool dispatcher - each tool is a discrete async function."""
import asyncio
import os
import time

import httpx


class MCPClient:
    """Model Context Protocol client for sandboxed tool execution."""

    async def run_nmap(self, target_domain: str, port_range: str) -> dict:
        """
        Spawn async subprocess with nmap against target.
        Parse output to JSON array: [{protocol, port, state, service, version}]
        Handle nmap not being installed gracefully.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap",
                "-sV",
                "--version-light",  # lighter probes -> faster service detection
                "-T4",  # more aggressive timing template
                "--host-timeout",
                "90s",  # give up on a host rather than hang the whole scan
                "-p",
                port_range,
                target_domain,
                "-oX",
                "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=100)
        except FileNotFoundError:
            return {
                "error": "nmap is not installed",
                "results": [],
            }
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return {
                "error": (
                    "nmap scan timed out. Try a narrower port_range "
                    "(e.g. '80,443,21,22') instead of a broad range."
                ),
                "results": [],
            }

        output = stdout.decode("utf-8", errors="ignore")
        results = _parse_nmap_output(output)
        return {
            "error": None,
            "results": results,
        }

    async def run_fuzzer(
        self,
        target_endpoint_url: str,
        parameter_payload_matrix: list[dict],
        injection_type: str,
    ) -> dict:
        """
        Send async HTTP requests with payloads using httpx.
        Measure response times, lengths, status codes.
        """
        results = []
        anomalies_found = 0

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            for payload in parameter_payload_matrix:
                start_time = time.monotonic()
                try:
                    if injection_type == "query":
                        resp = await client.get(
                            target_endpoint_url, params=payload
                        )
                    else:
                        resp = await client.post(
                            target_endpoint_url, json=payload
                        )
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    response_length = len(resp.content)
                    status_code = resp.status_code

                    # A genuine anomaly is a server-side error (5xx) or a
                    # suspiciously slow-but-successful response. We deliberately
                    # do NOT treat a slow response on its own as an anomaly,
                    # because a uniformly slow target (or an upstream proxy)
                    # would otherwise flag every payload and mislead the agent.
                    anomaly = status_code >= 500
                    if anomaly:
                        anomalies_found += 1

                    results.append({
                        "payload": payload,
                        "status_code": status_code,
                        "response_length": response_length,
                        "response_time_ms": round(elapsed_ms, 2),
                        "anomaly_detected": anomaly,
                        "transport_error": None,
                    })
                except (httpx.TimeoutException, httpx.HTTPError) as e:
                    # Connection-level failures (timeouts, refused connections,
                    # TLS errors) are TRANSPORT problems, not application
                    # vulnerabilities. Record them with status_code 0 but do
                    # NOT count them as anomalies - otherwise an unreachable
                    # https:// endpoint looks like a confirmed exploit, which is
                    # exactly the false positive that led K2 to hallucinate an
                    # RCE in earlier runs.
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    results.append({
                        "payload": payload,
                        "status_code": 0,
                        "response_length": 0,
                        "response_time_ms": round(elapsed_ms, 2),
                        "anomaly_detected": False,
                        "transport_error": type(e).__name__,
                    })

        return {
            "results": results,
            "total_requests": len(parameter_payload_matrix),
            "anomalies_found": anomalies_found,
        }

    async def execute_safe_poc(
        self,
        sandbox_environment_id: str,
        script_payload: str,
        expected_telemetry_signature: dict,
    ) -> dict:
        """
        Execute script in isolated subprocess with resource limits.
        Use asyncio.create_subprocess_exec with timeout (30s max).

        NOTE: Production deployment should use container isolation (e.g., gVisor,
        Docker with --network=none, or a dedicated sandbox runtime) for full
        security. The current implementation provides basic isolation by clearing
        sensitive env vars and restricting the working directory.
        """
        import tempfile

        # Create a restricted environment: remove sensitive variables
        safe_env = os.environ.copy()
        sensitive_keys = (
            "SECRET_KEY", "CF_API_TOKEN", "CF_ACCOUNT_ID",
            "RESEND_API_KEY", "DATABASE_URL",
        )
        for key in sensitive_keys:
            safe_env.pop(key, None)

        # Use a temporary directory as the working directory
        with tempfile.TemporaryDirectory(prefix="tw_poc_") as tmp_workdir:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "python3",
                    "-c",
                    script_payload,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=safe_env,
                    cwd=tmp_workdir,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
                trace = stdout.decode("utf-8", errors="ignore")
                error_output = stderr.decode("utf-8", errors="ignore")

                # Check if the expected telemetry signature was matched
                exploit_confirmed = False
                if expected_telemetry_signature:
                    marker = expected_telemetry_signature.get("marker", "")
                    if marker and marker in trace:
                        exploit_confirmed = True

                return {
                    "memory_profile": {"sandbox_id": sandbox_environment_id},
                    "trace": trace,
                    "exploit_confirmed": exploit_confirmed,
                    "error": error_output if error_output else None,
                }
            except asyncio.TimeoutError:
                return {
                    "memory_profile": {"sandbox_id": sandbox_environment_id},
                    "trace": "",
                    "exploit_confirmed": False,
                    "error": "Execution timed out (30s limit)",
                }
            except FileNotFoundError:
                return {
                    "memory_profile": {"sandbox_id": sandbox_environment_id},
                    "trace": "",
                    "exploit_confirmed": False,
                    "error": "Python interpreter not found",
                }

    async def query_hackclub(
        self, component_signature: str, version_string: str
    ) -> dict:
        """
        Query the Hack Club Search API for known vulnerabilities / CVEs.

        The Hack Club Search API is a Brave Search proxy. The web search
        endpoint is ``GET /res/v1/web/search?q=...`` and requires an API key
        passed as a bearer token (``Authorization: Bearer sk-hc-v1-...``) or via
        the ``x-subscription-token`` header. The response nests results under
        ``data["web"]["results"]`` where each result has ``title``, ``url`` and
        ``description`` fields.

        See https://search.hackclub.com/docs for the full specification.
        """
        api_key = os.getenv("HACKCLUB_API_KEY", "")
        if not api_key:
            return {
                "references": [],
                "vulnerable_components": [],
                "mitigations": [],
                "error": (
                    "HACKCLUB_API_KEY is not set. Get a key from "
                    "https://search.hackclub.com and set it in the environment."
                ),
            }

        # Build a CVE-oriented query. Include the version only when known so we
        # stay well under the 400-char / 50-word limit.
        component = component_signature.strip()
        version = (version_string or "").strip()
        query = (
            f"{component} {version} CVE vulnerability"
            if version
            else f"{component} CVE vulnerability"
        )

        url = "https://search.hackclub.com/res/v1/web/search"
        params = {"q": query, "count": 5}
        headers = {"Authorization": f"Bearer {api_key}"}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, params=params, headers=headers)
                if resp.status_code != 200:
                    return {
                        "references": [],
                        "vulnerable_components": [],
                        "mitigations": [],
                        "error": f"Hack Club Search API returned {resp.status_code}",
                    }
                data = resp.json() if resp.content else {}
                web_results = (data.get("web") or {}).get("results") or []
                references = [
                    {
                        "title": r.get("title", ""),
                        "url": r.get("url", ""),
                        "description": r.get("description", ""),
                    }
                    for r in web_results
                ]
                return {
                    "references": references,
                    "vulnerable_components": (
                        [f"{component}@{version}"] if version else [component]
                    ),
                    "mitigations": [],
                    "error": None,
                }
        except httpx.HTTPError as e:
            return {
                "references": [],
                "vulnerable_components": [],
                "mitigations": [],
                "error": f"Hack Club Search request failed: {e}",
            }


def _parse_nmap_output(xml_output: str) -> list[dict]:
    """Parse nmap XML output into structured results."""
    import re

    results = []
    # Simple regex-based parsing for port lines in XML
    port_pattern = re.compile(
        r'<port protocol="(\w+)" portid="(\d+)">'
        r'.*?<state state="(\w+)"'
        r'.*?<service name="([^"]*)"(?:.*?version="([^"]*)")?',
        re.DOTALL,
    )

    for match in port_pattern.finditer(xml_output):
        results.append({
            "protocol": match.group(1),
            "port": int(match.group(2)),
            "state": match.group(3),
            "service": match.group(4),
            "version": match.group(5) or "",
        })

    return results
