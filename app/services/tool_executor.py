"""Executes tool calls decided by K2 agent."""
from app.services.llm_client import LLMClient
from app.services.mcp_client import MCPClient
from app.services.remediation import RemediationService


class ToolExecutor:
    """Maps K2's tool call decisions to actual MCP/service method calls."""

    def __init__(
        self,
        job_id: str,
        mcp_client: MCPClient | None = None,
        llm_client: LLMClient | None = None,
    ):
        self.job_id = job_id
        self.mcp_client = mcp_client or MCPClient()
        self.remediation_svc = RemediationService(llm_client=llm_client or LLMClient())

    async def execute(self, tool_name: str, arguments: dict) -> dict:
        """Execute a tool by name with given arguments. Returns result dict."""
        executors = {
            "run_nmap": self._exec_nmap,
            "run_fuzzer": self._exec_fuzzer,
            "send_http_request": self._exec_send_http,
            "execute_safe_poc": self._exec_poc,
            "query_hackclub": self._exec_hackclub,
            "generate_patch": self._exec_patch,
        }

        executor = executors.get(tool_name)
        if not executor:
            return {"error": f"Unknown tool: {tool_name}", "available_tools": list(executors.keys())}

        try:
            return await executor(arguments)
        except Exception as e:
            return {"error": f"Tool execution failed: {str(e)}"}

    async def _exec_nmap(self, args: dict) -> dict:
        target = args.get("target", "")
        port_range = args.get("port_range", "1-1024")
        return await self.mcp_client.run_nmap(target, port_range)

    async def _exec_fuzzer(self, args: dict) -> dict:
        url = args.get("url", "")
        payloads = args.get("payloads", [{"param": "test", "value": "<script>alert(1)</script>"}])
        injection_type = args.get("injection_type", "query")
        return await self.mcp_client.run_fuzzer(url, payloads, injection_type)

    async def _exec_send_http(self, args: dict) -> dict:
        method = args.get("method", "GET")
        endpoint = args.get("endpoint") or args.get("url", "")
        headers = args.get("headers")
        json_body = args.get("json_body")
        if json_body is None:
            json_body = args.get("body") or args.get("json")
        form_data = args.get("form_data") or args.get("data")
        params = args.get("params")
        return await self.mcp_client.send_http_request(
            method=method,
            endpoint=endpoint,
            headers=headers,
            json_body=json_body,
            form_data=form_data,
            params=params,
        )

    async def _exec_poc(self, args: dict) -> dict:
        sandbox_id = args.get("sandbox_id", self.job_id)
        script = args.get("script", "")
        signature = args.get("expected_signature", {})
        return await self.mcp_client.execute_safe_poc(sandbox_id, script, signature)

    async def _exec_hackclub(self, args: dict) -> dict:
        component = args.get("component", "")
        version = args.get("version", "")
        return await self.mcp_client.query_hackclub(component, version)

    async def _exec_patch(self, args: dict) -> dict:
        vuln_node = args.get("vuln_node", "")
        source_code = args.get("source_code", "")
        # generate_patch now returns a structured finding dict:
        # {description, risk_level, cves, recommendation, code}
        finding = await self.remediation_svc.generate_patch(
            job_id=self.job_id, vuln_node=vuln_node, source_code=source_code
        )
        return {
            "vuln_node":      vuln_node,
            "patch":          finding.get("code", ""),   # backward-compat key
            "description":    finding.get("description", ""),
            "risk_level":     finding.get("risk_level", "High"),
            "cves":           finding.get("cves", []),
            "recommendation": finding.get("recommendation", ""),
        }
