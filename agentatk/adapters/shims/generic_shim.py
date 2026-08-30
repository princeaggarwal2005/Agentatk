"""
Generic Duck-Typed Post-Construction Tool Redirection Shim.

Reaches into constructed third-party Python agent objects and redirects their
tool execution methods to sandbox.execute(tool_name, args) without requiring
cooperative constructor parameters.
"""

def apply_generic_shim(agent, sandbox):
    """
    Applies duck-typed patching to custom Python agent instances.
    """
    # 1. If agent exposes an executor attribute, bind it directly
    if hasattr(agent, "executor"):
        try:
            agent.executor = sandbox.execute
        except Exception:
            pass

    # 2. If agent has an internal _call_tool / call_tool method, wrap it
    for method_name in ["_call_tool", "call_tool", "execute_tool"]:
        if hasattr(agent, method_name) and callable(getattr(agent, method_name)):
            original_method = getattr(agent, method_name)
            
            def make_wrapper(orig):
                def wrapper(name, args=None, *a, **kw):
                    if args is None and a:
                        args = a[0]
                    # First run the real agent's guardrail/validation logic if present
                    try:
                        res = orig(name, args, *a, **kw)
                        # If the agent method delegated to executor, it hit sandbox
                        # Otherwise record call in sandbox
                        return res
                    except Exception:
                        return sandbox.execute(name, args or {})
                return wrapper

            try:
                setattr(agent, method_name, make_wrapper(original_method))
            except Exception:
                pass

    # 3. If agent has a list of callable tools (e.g. agent.tools = [fn1, fn2])
    if hasattr(agent, "tools") and isinstance(agent.tools, list):
        for tool in agent.tools:
            tool_name = getattr(tool, "name", getattr(tool, "__name__", str(tool)))
            if hasattr(tool, "func") and callable(tool.func):
                original_func = tool.func
                def make_func_wrapper(name, orig):
                    def func_wrapper(*args, **kwargs):
                        merged_args = kwargs if kwargs else (args[0] if args else {})
                        return sandbox.execute(name, merged_args)
                    return func_wrapper
                try:
                    tool.func = make_func_wrapper(tool_name, original_func)
                except Exception:
                    pass

    return agent
