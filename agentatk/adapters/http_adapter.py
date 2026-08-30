import time
import uuid
from typing import Any, Dict
import httpx

from agentatk.adapters.base import ExecutionAdapter, ExecutionTelemetry


class HttpAdapter(ExecutionAdapter):
    """
    Sends test requests to a running HTTP/REST agent service and monitors responses.
    """

    def execute(
        self,
        launch_spec: Dict[str, Any],
        injection_vector: Dict[str, Any],
        stated_intent: str,
        sandbox: Any,
    ) -> ExecutionTelemetry:
        execution_id = f"EXEC-{uuid.uuid4().hex[:8]}"
        base_url = launch_spec.get("url") or launch_spec.get("endpoint")
        if not base_url:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="UNSUPPORTED_RUNTIME",
                error_message="No URL or endpoint provided in launch_spec",
            )

        method = launch_spec.get("method", "POST").upper()
        headers = launch_spec.get("headers", {})
        timeout = launch_spec.get("timeout_seconds", 30)

        # Inject payload
        payload = injection_vector.get("content", "")
        payload_key = injection_vector.get("key", "message")
        json_body = launch_spec.get("body", {})
        if isinstance(json_body, dict):
            json_body[payload_key] = payload

        start_time = time.time()
        try:
            with httpx.Client(timeout=timeout) as client:
                if method == "POST":
                    resp = client.post(base_url, json=json_body, headers=headers)
                elif method == "GET":
                    resp = client.get(base_url, params={payload_key: payload}, headers=headers)
                else:
                    resp = client.request(method, base_url, json=json_body, headers=headers)

            duration_ms = int((time.time() - start_time) * 1000)
            raw_text = resp.text

            # Check if safety guard blocked request
            if resp.status_code in (400, 403, 422) and any(
                term in raw_text.lower() for term in ("guardrail", "blocked", "safety", "forbidden", "policy")
            ):
                status = "GUARDRAIL_INTERCEPT"
            elif resp.status_code >= 500:
                status = "TARGET_CRASH"
            else:
                status = "EXECUTION_SUCCESS"

            return ExecutionTelemetry(
                execution_id=execution_id,
                status=status,
                exit_code=0 if resp.is_success else resp.status_code,
                stdout=raw_text,
                duration_ms=duration_ms,
                raw_response=raw_text,
                tool_trace=list(sandbox.executed_calls),
                network_trace=list(sandbox.net.requests),
            )

        except httpx.TimeoutException:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="EXECUTION_TIMEOUT",
                exit_code=-1,
                error_message="HTTP request timed out",
                duration_ms=int((time.time() - start_time) * 1000),
            )
        except httpx.ConnectError as e:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="ENVIRONMENT_DEPENDENCY_MISSING",
                exit_code=-1,
                error_message=f"Could not connect to target HTTP service at {base_url}: {e}",
            )
        except Exception as e:
            return ExecutionTelemetry(
                execution_id=execution_id,
                status="TARGET_CRASH",
                exit_code=-1,
                error_message=f"HTTP adapter error: {e}",
            )
