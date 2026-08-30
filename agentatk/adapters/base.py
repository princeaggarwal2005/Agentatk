from abc import ABC, abstractmethod
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field
import time


class ExecutionTelemetry(BaseModel):
    execution_id: str
    status: Literal[
        "EXECUTION_SUCCESS",
        "GUARDRAIL_INTERCEPT",
        "TARGET_CRASH",
        "EXECUTION_TIMEOUT",
        "UNSUPPORTED_RUNTIME",
        "ENVIRONMENT_DEPENDENCY_MISSING",
    ] = "EXECUTION_SUCCESS"
    exit_code: Optional[int] = 0
    stdout: str = ""
    stderr: str = ""
    tool_trace: List[Dict[str, Any]] = Field(default_factory=list)
    network_trace: List[Dict[str, Any]] = Field(default_factory=list)
    duration_ms: int = 0
    raw_response: Optional[str] = None
    error_message: Optional[str] = None


class ExecutionAdapter(ABC):
    """
    Abstract interface for executing an agent target across different runtime interfaces.
    """

    @abstractmethod
    def execute(
        self,
        launch_spec: Dict[str, Any],
        injection_vector: Dict[str, Any],
        stated_intent: str,
        sandbox: Any,
    ) -> ExecutionTelemetry:
        """
        Executes a dynamic test against the target agent and collects telemetry.
        """
        pass
