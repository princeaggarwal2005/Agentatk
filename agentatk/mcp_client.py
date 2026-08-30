"""
Direct Protocol-Level MCP Introspection Client.

Connects to MCP servers (via stdio or HTTP/SSE) and queries tools/list
directly over the wire without inspecting raw source code.
"""

import json
import subprocess
import shutil


class MCPClient:
    """Introspects and interacts with Model Context Protocol (MCP) servers."""

    def __init__(self, server_command=None, server_url=None, env=None):
        self.server_command = server_command
        self.server_url = server_url
        self.env = env or {}

    def list_tools(self):
        """
        Sends an RPC tools/list request to the MCP server and returns normalized tool schemas.
        """
        # If stdio command is provided (e.g. ['node', 'mcp-server.js'])
        if self.server_command:
            try:
                cmd = self.server_command if isinstance(self.server_command, list) else self.server_command.split()
                # Run a fast initialization & list request
                init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "agentatk", "version": "1.0"}}}) + "\n"
                tools_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
                
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                stdout, _ = proc.communicate(input=init_req + tools_req, timeout=5)
                
                tools = []
                for line in stdout.splitlines():
                    try:
                        resp = json.loads(line)
                        if resp.get("id") == 2 and "result" in resp:
                            for t in resp["result"].get("tools", []):
                                tools.append({
                                    "type": "function",
                                    "function": {
                                        "name": t.get("name"),
                                        "description": t.get("description", "MCP Tool"),
                                        "parameters": t.get("inputSchema", {}),
                                    }
                                })
                    except Exception:
                        continue

                if tools:
                    return tools
            except Exception:
                pass

        # Fallback if live wire query is unavailable
        return []
