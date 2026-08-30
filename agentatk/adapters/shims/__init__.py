"""
Unified Tool Redirection Shim Router.
"""

from .generic_shim import apply_generic_shim
from .langchain_shim import apply_langchain_shim
from .crewai_shim import apply_crewai_shim


def apply_shim(agent, sandbox, framework=None):
    """
    Applies the appropriate framework tool redirection shim to a live agent instance.
    """
    if framework == "langchain" or "langchain" in str(type(agent)).lower():
        return apply_langchain_shim(agent, sandbox)
    elif framework == "crewai" or "crewai" in str(type(agent)).lower():
        return apply_crewai_shim(agent, sandbox)
    else:
        return apply_generic_shim(agent, sandbox)
