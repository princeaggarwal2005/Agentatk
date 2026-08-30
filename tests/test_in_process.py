import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agentatk.adapters.in_process import run_inprocess_scan


class SecurityGuardrail:
    """Enterprise middleware that checks tool calls against security policies."""

    def __init__(self, deny_tools=None):
        self.deny_tools = deny_tools or ["delete_email", "send_email"]

    def can_execute(self, tool_name, args):
        if tool_name in self.deny_tools:
            return False, f"GUARDRAIL BLOCKED: Tool '{tool_name}' is forbidden by security policy."
        return True, "Allowed"


class GuardedEmailAgent:
    """An example agent with built-in guardrails."""

    def __init__(self, executor, guardrail=None):
        self.executor = executor
        self.guardrail = guardrail or SecurityGuardrail()
        self.trace = []
        self.blocked_calls = []

    def run(self, task):
        # 1. Agent starts by reading emails
        self._call_tool("read_email", {})

        # 2. Suppose a malicious email tricks the agent into calling delete_email
        self._call_tool("delete_email", {"older_than": "30d"})

        return "Task completed."

    def _call_tool(self, name, args):
        allowed, reason = self.guardrail.can_execute(name, args)
        if not allowed:
            self.blocked_calls.append({"tool": name, "args": args, "reason": reason})
            return reason

        self.trace.append({"tool": name, "args": args})
        return self.executor(name, args)


def test_in_process_guardrail_blocks_attacks():
    tools = [
        {"name": "read_email"},
        {"name": "delete_email"},
    ]
    policy = {"allow": ["read_email"], "deny": ["delete_email"]}

    def agent_factory(executor):
        guard = SecurityGuardrail(deny_tools=["delete_email"])
        return GuardedEmailAgent(executor=executor, guardrail=guard)

    results = run_inprocess_scan(agent_factory, tools, policy)

    # All scope violation cases should PASS because the Python guardrail blocked delete_email!
    scope_results = [r for r in results if r["case"] == "scope_violation"]
    for r in scope_results:
        assert r["passed"] is True
        assert len(r["guardrail_blocked"]) > 0
        assert r["guardrail_blocked"][0]["tool"] == "delete_email"
