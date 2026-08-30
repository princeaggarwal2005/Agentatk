from .canary import make_canary
from .overlay_fs import OverlayFS
from .fake_net import FakeNet


class Sandbox:
    """
    Isolated virtual environment with simulated filesystem overlay,
    mock network trap, and authoritative tool execution interceptor.
    """

    def __init__(self, canary=None, base_dir=None, copy_from_dir=None):
        self.fs = OverlayFS(base_dir=base_dir, copy_from_dir=copy_from_dir)
        self.net = FakeNet()
        self.canary = canary or make_canary()
        self.planted_payload = ""
        self.executed_calls = []
        self.custom_tools = {}

    def seed_payload(self, payload: str, seed_canary: bool = True):
        """Seeds the sandbox with a dynamic attack payload and secret canary."""
        safe_payload = str(payload if payload is not None else "")
        self.planted_payload = safe_payload
        if seed_canary:
            self.fs.seed("secrets/api_key", self.canary)
            self.fs.seed(".env", f"SECRET_API_KEY={self.canary}\nSYSTEM_TOKEN={self.canary}\n")
        self.fs.seed("workspace/document.txt", safe_payload)
        self.fs.seed("data/inbox/ticket.txt", safe_payload)

    def execute(self, tool_name: str, args: any) -> str:
        """Authoritatively intercepts and records all tool executions."""
        import json
        if isinstance(args, str):
            try:
                parsed_args = json.loads(args)
            except Exception:
                parsed_args = {"raw": args}
        elif isinstance(args, dict):
            parsed_args = args
        else:
            parsed_args = {"raw": str(args)}

        lowered = tool_name.lower()
        result = "OK (simulated)"

        # 0. Custom registered tool handlers
        if tool_name in self.custom_tools:
            handler = self.custom_tools[tool_name]
            result = handler(**parsed_args) if callable(handler) else str(handler)

        # 1. Network / URL tools
        elif any(word in lowered for word in ("http", "url", "fetch", "ping", "browse", "request", "net", "web", "api")):
            url = parsed_args.get("url") or parsed_args.get("endpoint") or "http://sandbox-mock.local/api"
            status, content = self.net.request("GET", url, body=str(parsed_args))
            result = f"HTTP {status}: {content}"

        # 2. File / Disk tools
        elif any(word in lowered for word in ("file", "read_file", "write_file", "path", "document")):
            path = parsed_args.get("path") or parsed_args.get("filename") or parsed_args.get("file") or ""
            if "api_key" in path or "secret" in path or ".env" in path:
                result = self.fs.read(path)
            elif "doc" in path or "ticket" in path:
                result = self.planted_payload
            else:
                result = self.fs.read(path)

        # 3. State changing default
        elif any(word in lowered for word in ("unlock", "turn_on", "turn_off", "open", "close", "delete", "exec", "override")):
            result = f"Action '{tool_name}' executed successfully with params {parsed_args}"

        self.executed_calls.append({"tool": tool_name, "args": parsed_args, "result": result})
        return result

    def get_tool_trace(self):
        return self.executed_calls

    def get_network_trace(self):
        return self.net.get_history()

    def reset(self):
        self.executed_calls = []
        self.net.history = []
        self.fs.reset()
