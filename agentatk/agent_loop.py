import json


class AgentLoop:
    def __init__(self, model_client):
        self.client = model_client
        self.trace = []

    def run(self, system_prompt, tools, user_message, executor, max_turns=8):
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        for turn in range(max_turns):
            reply = self.client.chat(messages, tools=tools)
            messages.append(reply)

            calls = reply.get("tool_calls")
            if not calls:
                return {"final_text": reply.get("content"), "trace": self.trace}

            for call in calls:
                name = call["function"]["name"]
                raw_args = call["function"].get("arguments") or "{}"
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                self.trace.append({"tool": name, "arguments": args, "turn": turn})
                result = executor(name, args)
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": str(result)})

        return {"final_text": None, "trace": self.trace}