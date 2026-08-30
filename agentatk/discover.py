"""
Target Discovery & Adapter Contract Resolver.

Routes targets across three authoritative paths:
1. Path 1: MCP Protocol Introspection (live tools/list over wire)
2. Path 2: Multi-Scenario Benchmark Suites (strictly 1-by-1 per sub-scenario)
3. Path 3: Framework Codebase Recon & Live Instantiation

Refuses to guess configurations or silently substitute fake prompts.
"""

import json
import os
import yaml
from agentatk.model_client import DEFAULT_MODEL
from agentatk.mcp_client import MCPClient
from agentatk.recon import AutonomousReconAgent


class NoTargetAdapterError(Exception):
    """Raised when no valid target entrypoint or configuration could be discovered."""
    pass


def auto_discover_target(target_path, model_client=None):
    """
    Resolves the target path against the Adapter Contract.
    Returns a target specification dict or raises NoTargetAdapterError.
    """
    target_path = os.path.abspath(target_path)
    if not os.path.exists(target_path):
        raise NoTargetAdapterError(f"Target path does not exist: {target_path}")

    # =========================================================================
    # Path 1: MCP Protocol Target (mcp_config.json or MCP endpoint)
    # =========================================================================
    mcp_config_path = os.path.join(target_path, "mcp_config.json") if os.path.isdir(target_path) else (target_path if target_path.endswith("mcp_config.json") else None)
    if mcp_config_path and os.path.exists(mcp_config_path):
        try:
            with open(mcp_config_path, "r", encoding="utf-8") as f:
                mcp_data = json.load(f)
            # Introspect MCP tools directly over the wire/command
            client = MCPClient(server_command=mcp_data.get("command"))
            tools = client.list_tools()
            if tools:
                return {
                    "name": mcp_data.get("name", os.path.basename(target_path)),
                    "type": "mcp",
                    "entrypoint": {"type": "mcp", "config": mcp_data},
                    "system_prompt": mcp_data.get("system_prompt", "MCP Agent"),
                    "tools": tools,
                    "policy": mcp_data.get("policy"),
                }
        except Exception:
            pass

    # =========================================================================
    # Path 2: Multi-Scenario Benchmark Suite (scenarios/ subfolder)
    # =========================================================================
    scenarios_dir = os.path.join(target_path, "scenarios") if os.path.basename(target_path) != "scenarios" else target_path
    if os.path.isdir(scenarios_dir) and os.path.exists(scenarios_dir):
        scenarios = []
        recon_agent = AutonomousReconAgent(model_client)
        for item in sorted(os.listdir(scenarios_dir)):
            subpath = os.path.join(scenarios_dir, item)
            if os.path.isdir(subpath) and not item.startswith("."):
                # Run individual discovery strictly per scenario
                sc_manifest = recon_agent.analyze_target(subpath)
                if sc_manifest and len(sc_manifest.get("tools", [])) > 0:
                    sc_manifest["scenario_id"] = item
                    sc_manifest["path"] = subpath
                    scenarios.append(sc_manifest)

        if scenarios:
            return {
                "name": os.path.basename(target_path),
                "type": "multi_scenario",
                "is_benchmark_suite": True,
                "scenarios_dir": scenarios_dir,
                "scenarios": scenarios,
            }

    # =========================================================================
    # Path 3: Single Agent / Framework Codebase Recon
    # =========================================================================
    recon_agent = AutonomousReconAgent(model_client)
    manifest = recon_agent.analyze_target(target_path)
    if manifest and len(manifest.get("tools", [])) > 0:
        manifest["type"] = manifest.get("entrypoint", {}).get("type", "in_process")
        return manifest

    # If no adapter, server, or manifest could be found, fail loudly
    raise NoTargetAdapterError(
        f"No valid agent entrypoint or adapter found in '{target_path}'.\n"
        f"Expected one of:\n"
        f"  - In-process factory function in agent.py: `load_target() -> Agent` or `get_agent() -> Agent`\n"
        f"  - Multi-scenario benchmark repository with a `scenarios/` directory\n"
        f"  - MCP server schema: `mcp_config.json`"
    )
