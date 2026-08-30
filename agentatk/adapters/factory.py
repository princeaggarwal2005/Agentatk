import os
from typing import Any, Optional
from pathlib import Path

from agentatk.adapters.base import ExecutionAdapter
from agentatk.adapters.simulation_adapter import SimulationAdapter
from agentatk.adapters.process_adapter import ProcessAdapter
from agentatk.adapters.http_adapter import HttpAdapter
from agentatk.adapters.mcp_adapter import McpAdapter
from agentatk.state import TargetState


class AdapterFactory:
    """
    Dynamically resolves the appropriate ExecutionAdapter for a given target repository.
    """

    @staticmethod
    def resolve(target_state: TargetState, model_client: Any) -> ExecutionAdapter:
        target_root = Path(target_state.target_root).resolve()
        arch = target_state.architecture or {}

        # 1. MCP Configuration
        mcp_config = target_root / "mcp_config.json"
        if mcp_config.exists() or arch.get("type") == "mcp":
            return McpAdapter()

        # 2. Live HTTP Endpoint
        if arch.get("type") == "http" or "url" in arch:
            return HttpAdapter()

        # 3. CLI / Runnable Subprocess Entrypoint
        if arch.get("entrypoint_type") == "cli" or arch.get("command"):
            return ProcessAdapter()

        # 4. Default to SimulationAdapter (Prompt + Extracted Tools)
        return SimulationAdapter(model_client)
