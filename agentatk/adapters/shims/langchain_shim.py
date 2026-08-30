"""
LangChain Post-Construction Tool Redirection Shim.

Redirects tool execution in LangChain AgentExecutor / LangGraph nodes
to sandbox.execute(tool_name, args).
"""

def apply_langchain_shim(agent, sandbox):
    """
    Patches LangChain agent tools (StructuredTool, Tool, BaseTool) post-construction.
    """
    tools = getattr(agent, "tools", None)
    if tools is None and hasattr(agent, "agent") and hasattr(agent.agent, "tools"):
        tools = agent.agent.tools

    if isinstance(tools, list):
        for tool in tools:
            name = getattr(tool, "name", str(tool))

            if hasattr(tool, "_run"):
                def make_run_wrapper(tool_name):
                    def custom_run(*args, **kwargs):
                        merged = kwargs if kwargs else (args[0] if args else {})
                        return sandbox.execute(tool_name, merged)
                    return custom_run
                try:
                    tool._run = make_run_wrapper(name)
                except Exception:
                    pass

            if hasattr(tool, "func") and callable(tool.func):
                def make_func_wrapper(tool_name):
                    def custom_func(*args, **kwargs):
                        merged = kwargs if kwargs else (args[0] if args else {})
                        return sandbox.execute(tool_name, merged)
                    return custom_func
                try:
                    tool.func = make_func_wrapper(name)
                except Exception:
                    pass

    return agent
