import json
import re

# Rule-based heuristics for instant zero-latency tagging
SOURCE_KEYWORDS = ("read", "get", "fetch", "search", "list", "load", "inbox", "query", "view", "find", "check")
SINK_KEYWORDS = ("delete", "send", "write", "post", "update", "exec", "run", "pay", "order", "charge", "transfer", "remove", "drop", "modify", "patch", "cancel")


def classify_tools(tools, model_client=None):
    """
    Classifies a list of tools into Sources (read inputs) and Sinks (action/state modifications).
    Uses rule-based heuristics first, with a single batch LLM fallback for ambiguous tools.
    """
    sources = []
    sinks = []
    unclassified = []

    for tool in tools:
        func = tool.get("function", tool) if isinstance(tool, dict) else {"name": str(tool)}
        name = func.get("name", "").lower()
        desc = func.get("description", "").lower()
        full_text = f"{name} {desc}"

        is_src = any(kw in full_text for kw in SOURCE_KEYWORDS)
        is_snk = any(kw in full_text for kw in SINK_KEYWORDS)

        if is_src and not is_snk:
            sources.append(func.get("name"))
        elif is_snk:
            sinks.append(func.get("name"))
        else:
            unclassified.append(func)

    # If some tools are ambiguous, classify all of them in ONE single batch LLM call
    if unclassified and model_client:
        batch_results = _batch_classify_with_llm(model_client, unclassified)
        for name, category in batch_results.items():
            if category == "source" and name not in sources:
                sources.append(name)
            elif category == "sink" and name not in sinks:
                sinks.append(name)

    # Fallbacks if tools list was completely ambiguous
    if not sources and tools:
        first_func = tools[0].get("function", tools[0]) if isinstance(tools[0], dict) else {"name": str(tools[0])}
        sources.append(first_func.get("name"))

    if not sinks and tools:
        last_func = tools[-1].get("function", tools[-1]) if isinstance(tools[-1], dict) else {"name": str(tools[-1])}
        if last_func.get("name") not in sources:
            sinks.append(last_func.get("name"))
        else:
            sinks.append(sources[0])

    return {"sources": sources, "sinks": sinks}


def _batch_classify_with_llm(model_client, tools):
    """Classifies multiple tools in a single batch prompt."""
    tool_summaries = [f"- {t.get('name')}: {t.get('description', 'No description')}" for t in tools]
    prompt = (
        "You are an AI Security Analyzer. Classify each of the following tools as either 'source' (reads external data/inputs) "
        "or 'sink' (takes actions, modifies state, sends data, executes code).\n\n"
        "Tools:\n" + "\n".join(tool_summaries) + "\n\n"
        'Respond ONLY with valid JSON mapping tool names to "source" or "sink", for example:\n'
        '{"tool_a": "source", "tool_b": "sink"}'
    )

    try:
        reply = model_client.chat([{"role": "user", "content": prompt}])
        content = reply.get("content", "")
        json_match = re.search(r"\{.*\}", content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(0))
    except Exception:
        pass

    return {t.get("name"): "sink" for t in tools}
