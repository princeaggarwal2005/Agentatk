"""
CrewAI Post-Construction Tool Redirection Shim.

Redirects tool execution in CrewAI Crew/Agent objects to sandbox.execute.
"""

def apply_crewai_shim(crew_or_agent, sandbox):
    """
    Patches CrewAI Agent or Crew tool collections post-construction.
    """
    agents = []
    if hasattr(crew_or_agent, "agents") and isinstance(crew_or_agent.agents, list):
        agents = crew_or_agent.agents
    else:
        agents = [crew_or_agent]

    for ag in agents:
        tools = getattr(ag, "tools", [])
        if isinstance(tools, list):
            for tool in tools:
                name = getattr(tool, "name", str(tool))
                if hasattr(tool, "func") and callable(tool.func):
                    def make_wrapper(tool_name):
                        def custom_func(*args, **kwargs):
                            merged = kwargs if kwargs else (args[0] if args else {})
                            return sandbox.execute(tool_name, merged)
                        return custom_func
                    try:
                        tool.func = make_wrapper(name)
                    except Exception:
                        pass
                elif hasattr(tool, "_run"):
                    def make_run_wrapper(tool_name):
                        def custom_run(*args, **kwargs):
                            merged = kwargs if kwargs else (args[0] if args else {})
                            return sandbox.execute(tool_name, merged)
                        return custom_run
                    try:
                        tool._run = make_run_wrapper(name)
                    except Exception:
                        pass

    return crew_or_agent
