import json
import subprocess
import time
import uuid
from typing import Any, Dict

from agentatk.adapters.base import ExecutionAdapter, ExecutionTelemetry


class McpAdapter(ExecutionAdapter):
    """
    Speaks the Model Context Protocol (MCP) over stdio or JSON-RPC.
    """

    def execute(
        self,
        launch_spec: Dict[str, Any],
        injection_vector: Dict[str, Any],
        stated_intent: str,
        sandbox: Any,
    ) -> ExecutionTelemetry:
        execution_id = f"EXEC-{uuid.uuid4().hex[:8]}"
        command = launch_spec.get("command")
        if not command:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="UNSUPPORTED_RUNTIME",
                error_message="No stdio command provided for MCP server",
            )

        tool_to_call = injection_vector.get("tool_name")
        args_payload = injection_vector.get("args") or {"input": injection_vector.get("content", "")}

        start_time = time.time()
        try:
            # Send JSON-RPC init and tools/call over stdio
            init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "agentatk-auditor", "version": "2.0"}}}) + "\n"
            call_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool_to_call or "default_tool", "arguments": args_payload}}) + "\n"

            proc = subprocess.run(
                command,
                input=(init_req + call_req).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True if isinstance(command, str) else False,
                timeout=launch_spec.get("timeout_seconds", 20),
            )
            duration_ms = int((time.time() - start_time) * 1000)
            stdout_str = proc.stdout.decode("utf-8", errors="replace")
            stderr_str = proc.stderr.decode("utf-8", errors="replace")

            tool_trace = list(sandbox.executed_calls)
            if tool_to_call:
                tool_trace.append({"tool": tool_to_call, "args": args_payload, "result": stdout_str})

            return ExecutionTelemetry(
                execution_id=execution_id,
                status="EXECUTION_SUCCESS" if proc.returncode == 0 else "TARGET_CRASH",
                exit_code=proc.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                tool_trace=tool_trace,
                network_trace=list(sandbox.net.requests),
                duration_ms=duration_ms,
            )
        except subprocess.TimeoutExpired:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="EXECUTION_TIMEOUT",
                error_message="MCP server timed out",
                duration_ms=int((time.time() - start_time) * 1000),
            )
        except Exception as e:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="TARGET_CRASH",
                error_message=f"MCP adapter error: {e}",
            )
