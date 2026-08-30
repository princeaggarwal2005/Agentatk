import os
import subprocess
import time
import uuid
from typing import Any, Dict
from pathlib import Path

from agentatk.adapters.base import ExecutionAdapter, ExecutionTelemetry


class ProcessAdapter(ExecutionAdapter):
    """
    Executes local CLI / script-based agent targets inside the sandbox overlay.
    """

    def execute(
        self,
        launch_spec: Dict[str, Any],
        injection_vector: Dict[str, Any],
        stated_intent: str,
        sandbox: Any,
    ) -> ExecutionTelemetry:
        execution_id = f"EXEC-{uuid.uuid4().hex[:8]}"
        command = launch_spec.get("command") or launch_spec.get("entrypoint")
        if not command:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="UNSUPPORTED_RUNTIME",
                error_message="No command or entrypoint specified in launch_spec",
            )

        timeout = launch_spec.get("timeout_seconds", 30)
        overlay_root = str(sandbox.fs.root)

        # 1. Apply Injection Vector
        channel = injection_vector.get("channel", "seeded_file")
        content = injection_vector.get("content", "")
        location = injection_vector.get("location")

        stdin_data = None
        if channel == "seeded_file" and location:
            sandbox.fs.seed(location, content)
        elif channel == "stdin":
            stdin_data = content
        elif channel == "argv" and isinstance(command, str) and "{payload}" in command:
            command = command.replace("{payload}", content)

        # 2. Build Environment
        env = os.environ.copy()
        env["SANDBOX_CANARY"] = sandbox.canary
        env["PYTHONUNBUFFERED"] = "1"
        if "env_overrides" in launch_spec:
            env.update(launch_spec["env_overrides"])

        start_time = time.time()
        try:
            # Run command inside overlay directory
            if isinstance(command, str):
                shell_cmd = True
            else:
                shell_cmd = False

            proc = subprocess.run(
                command,
                cwd=overlay_root,
                input=stdin_data.encode("utf-8") if stdin_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                shell=shell_cmd,
                timeout=timeout,
            )
            duration_ms = int((time.time() - start_time) * 1000)
            stdout_str = proc.stdout.decode("utf-8", errors="replace")
            stderr_str = proc.stderr.decode("utf-8", errors="replace")

            # Check if guardrail blocked output
            lowered_out = stdout_str.lower() + stderr_str.lower()
            if any(term in lowered_out for term in ("guardrail blocked", "content blocked", "policy violation", "refused by safety")):
                status = "GUARDRAIL_INTERCEPT"
            elif proc.returncode != 0 and not stdout_str:
                status = "TARGET_CRASH"
            else:
                status = "EXECUTION_SUCCESS"

            # Parse tool calls recorded in sandbox or output
            tool_trace = list(sandbox.executed_calls)
            network_trace = list(sandbox.net.requests)

            return ExecutionTelemetry(
                execution_id=execution_id,
                status=status,
                exit_code=proc.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                tool_trace=tool_trace,
                network_trace=network_trace,
                duration_ms=duration_ms,
            )

        except subprocess.TimeoutExpired:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="EXECUTION_TIMEOUT",
                exit_code=-1,
                stderr=f"Process timed out after {timeout} seconds.",
                duration_ms=int((time.time() - start_time) * 1000),
            )
        except FileNotFoundError as e:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="UNSUPPORTED_RUNTIME",
                exit_code=-1,
                error_message=f"Executable not found: {e}",
            )
        except Exception as e:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="TARGET_CRASH",
                exit_code=-1,
                error_message=f"Execution failed with exception: {e}",
            )
