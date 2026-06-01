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
                "-p",
                port_range,
                target_domain,
                "-oX",
                "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        except FileNotFoundError:
            return {
                "error": "nmap is not installed",
                "results": [],
            }
        except asyncio.TimeoutError:
            return {
                "error": "nmap scan timed out",
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

        async with httpx.AsyncClient(timeout=30.0) as client:
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

                    # Detect anomalies: unusual status codes or very slow responses
                    anomaly = status_code >= 500 or elapsed_ms > 5000
                    if anomaly:
                        anomalies_found += 1

                    results.append({
                        "payload": payload,
                        "status_code": status_code,
                        "response_length": response_length,
                        "response_time_ms": round(elapsed_ms, 2),
                        "anomaly_detected": anomaly,
                    })
                except httpx.HTTPError:
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    anomalies_found += 1
                    results.append({
                        "payload": payload,
                        "status_code": 0,
                        "response_length": 0,
                        "response_time_ms": round(elapsed_ms, 2),
                        "anomaly_detected": True,
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
        Query HackClub Search API for CVE/vulnerability data.
        """
        url = "https://search.hackclub.com/api/search"
        params = {"query": f"{component_signature} {version_string} vulnerability"}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, params=params)
                if resp.status_code != 200:
                    return {
                        "references": [],
                        "vulnerable_components": [],
                        "mitigations": [],
                    }
                data = resp.json() if resp.content else {}
                return {
                    "references": data.get("results", []),
                    "vulnerable_components": [
                        f"{component_signature}@{version_string}"
                    ],
                    "mitigations": [],
                }
        except (httpx.HTTPError, Exception):
            return {
                "references": [],
                "vulnerable_components": [],
                "mitigations": [],
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
