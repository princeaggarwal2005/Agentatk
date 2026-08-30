import os
import re
import time
from typing import Any, Dict, List, Optional
import httpx
from dotenv import load_dotenv

load_dotenv()


class ModelClient:
    """
    Centralized Unified LLM Client with automatic multi-provider failover
    (Groq, Cerebras, OpenRouter, Local Ollama) to withstand TPM/RPM limits.
    """

    def __init__(self, base_url="", model=None, api_key=""):
        self.explicit_base_url = base_url
        self.explicit_model = model
        self.explicit_api_key = api_key
        self.providers = self._discover_providers()

    def _discover_providers(self) -> List[Dict[str, str]]:
        providers = []

        # 1. Explicit config if passed
        if self.explicit_base_url:
            providers.append({
                "name": "explicit",
                "base_url": self.explicit_base_url.rstrip("/"),
                "model": self.explicit_model or "qwen/qwen3.6-27b",
                "api_key": self.explicit_api_key or os.environ.get("OPENAI_API_KEY", "local-key"),
            })
            return providers

        # 2. Groq Provider
        groq_key = os.environ.get("GROQ_API_KEY")
        if groq_key and not groq_key.startswith("your_"):
            providers.append({
                "name": "groq",
                "base_url": "https://api.groq.com/openai/v1",
                "model": "qwen/qwen3.6-27b",
                "api_key": groq_key,
            })

        # 3. Cerebras Provider
        cerebras_key = os.environ.get("CEREBRAS_API_KEY")
        if cerebras_key:
            providers.append({
                "name": "cerebras",
                "base_url": "https://api.cerebras.ai/v1",
                "model": "gpt-oss-120b",
                "api_key": cerebras_key,
            })

        # 4. OpenRouter Provider
        openrouter_key = os.environ.get("OPENROUTER_API_KEY")
        if openrouter_key:
            providers.append({
                "name": "openrouter",
                "base_url": "https://openrouter.ai/api/v1",
                "model": "qwen/qwen-2.5-72b-instruct",
                "api_key": openrouter_key,
            })

        # 5. Local / Ollama Provider
        default_url = os.environ.get("DEFAULT_BASE_URL", "http://localhost:11434/v1").rstrip("/")
        providers.append({
            "name": "local",
            "base_url": default_url,
            "model": os.environ.get("DEFAULT_MODEL", "llama3.2"),
            "api_key": os.environ.get("OMNIROUTE_API_KEY") or "local-key",
        })

        return providers

    def chat(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        # Normalize tools to standard OpenAI function-calling schema
        normalized_tools = None
        if tools:
            normalized_tools = []
            for t in tools:
                fn = t.get("function", t) if isinstance(t, dict) else {"name": str(t)}
                raw_name = fn.get("name", "unknown")
                clean_name = re.sub(r"[^a-zA-Z0-9_-]", "_", str(raw_name)).strip("_")[:64] or "tool_fn"
                params = fn.get("parameters") or fn.get("inputSchema") or {"type": "object", "properties": {}}
                normalized_tools.append({
                    "type": "function",
                    "function": {
                        "name": clean_name,
                        "description": fn.get("description", "Tool function"),
                        "parameters": params,
                    },
                })

        last_error = None
        # Try configured providers in sequence for automatic failover
        for prov_idx, prov in enumerate(self.providers):
            headers = {
                "Authorization": f"Bearer {prov['api_key']}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": prov["model"],
                "messages": messages,
            }
            if normalized_tools:
                payload["tools"] = normalized_tools

            for attempt in range(3):
                try:
                    res = httpx.post(f"{prov['base_url']}/chat/completions", headers=headers, json=payload, timeout=35)
                    
                    if res.status_code == 429:
                        wait = 2 * (attempt + 1)
                        time.sleep(wait)
                        continue

                    if res.status_code in (400, 404, 401):
                        # Provider error -> shift to next provider
                        break

                    res.raise_for_status()
                    return res.json()["choices"][0]["message"]

                except Exception as err:
                    last_error = err
                    time.sleep(1)

        raise RuntimeError(f"All LLM providers failed or rate-limited. Last error: {last_error}")
