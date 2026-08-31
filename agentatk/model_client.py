import os
import re
import json
import time
from typing import Any, Dict, List, Optional
import httpx
from dotenv import load_dotenv

load_dotenv()

try:
    from google import genai
    from google.genai import types as genai_types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    genai_types = None


class ModelClient:
    """
    Centralized Unified LLM Client leveraging Google GenAI SDK (Gemini)
    as the primary reasoning and verification engine for AGENTATK,
    with multi-provider discovery and automatic fallback.
    """

    def __init__(self, base_url="", model=None, api_key=""):
        self.explicit_base_url = base_url or os.environ.get("OPENAI_BASE_URL") or os.environ.get("BASE_URL", "")
        self.explicit_model = model or os.environ.get("MODEL") or os.environ.get("AGENTATK_MODEL") or os.environ.get("LLM_MODEL")
        self.explicit_api_key = api_key or os.environ.get("API_KEY", "")
        self.gemini_client = self._init_gemini_client()
        self.providers = self._discover_providers()

    def _init_gemini_client(self):
        gemini_key = os.environ.get("GEMINI_API_KEY") or (self.explicit_api_key if "AIza" in (self.explicit_api_key or "") else "")
        if GENAI_AVAILABLE and gemini_key and not gemini_key.startswith("your_"):
            try:
                return genai.Client(api_key=gemini_key)
            except Exception:
                pass
        elif GENAI_AVAILABLE and (os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or os.environ.get("GOOGLE_CLOUD_PROJECT")):
            try:
                return genai.Client()
            except Exception:
                pass
        return None

    def _discover_providers(self) -> List[Dict[str, str]]:
        providers = []
        user_model = self.explicit_model

        # 1. Google Gemini via REST (if SDK not initialized or as backup)
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if gemini_key and not gemini_key.startswith("your_"):
            providers.append({
                "name": "gemini",
                "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
                "model": user_model or "gemini-2.5-flash",
                "api_key": gemini_key,
            })

        # 2. Explicit custom base URL if provided
        if self.explicit_base_url:
            providers.append({
                "name": "custom_endpoint",
                "base_url": self.explicit_base_url.rstrip("/"),
                "model": user_model or "gemini-2.5-flash",
                "api_key": self.explicit_api_key or os.environ.get("OPENAI_API_KEY", "local-key"),
            })
            return providers

        # 3. OpenAI Provider
        openai_key = os.environ.get("OPENAI_API_KEY")
        if openai_key and not openai_key.startswith("your_"):
            providers.append({
                "name": "openai",
                "base_url": "https://api.openai.com/v1",
                "model": user_model or "gpt-4o-mini",
                "api_key": openai_key,
            })

        # 4. Groq Provider
        groq_key = os.environ.get("GROQ_API_KEY")
        if groq_key and not groq_key.startswith("your_"):
            providers.append({
                "name": "groq",
                "base_url": "https://api.groq.com/openai/v1",
                "model": user_model or "llama-3.3-70b-versatile",
                "api_key": groq_key,
            })

        # 5. DeepSeek Provider
        deepseek_key = os.environ.get("DEEPSEEK_API_KEY")
        if deepseek_key and not deepseek_key.startswith("your_"):
            providers.append({
                "name": "deepseek",
                "base_url": "https://api.deepseek.com/v1",
                "model": user_model or "deepseek-chat",
                "api_key": deepseek_key,
            })

        # 6. Cerebras Provider
        cerebras_key = os.environ.get("CEREBRAS_API_KEY")
        if cerebras_key and not cerebras_key.startswith("your_"):
            providers.append({
                "name": "cerebras",
                "base_url": "https://api.cerebras.ai/v1",
                "model": user_model or "llama3.3-70b",
                "api_key": cerebras_key,
            })

        # 7. OpenRouter Provider
        openrouter_key = os.environ.get("OPENROUTER_API_KEY")
        if openrouter_key and not openrouter_key.startswith("your_"):
            providers.append({
                "name": "openrouter",
                "base_url": "https://openrouter.ai/api/v1",
                "model": user_model or "qwen/qwen-2.5-72b-instruct",
                "api_key": openrouter_key,
            })

        # 8. Local / Ollama Provider fallback
        default_url = os.environ.get("DEFAULT_BASE_URL", os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")).rstrip("/")
        providers.append({
            "name": "local",
            "base_url": default_url,
            "model": user_model or os.environ.get("DEFAULT_MODEL", "llama3.2"),
            "api_key": os.environ.get("OMNIROUTE_API_KEY") or "local-key",
        })

        return providers

    def _chat_with_genai_sdk(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
        """Executes chat completion via official Google GenAI SDK."""
        if not self.gemini_client or not GENAI_AVAILABLE:
            return None

        model_name = self.explicit_model or "gemini-2.5-flash"
        if not model_name.startswith("gemini-"):
            model_name = "gemini-2.5-flash"

        # Separate system instruction from conversational turns
        system_instruction = None
        contents = []
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            if role == "system":
                system_instruction = content
            elif role == "assistant":
                contents.append(genai_types.Content(role="model", parts=[genai_types.Part.from_text(text=str(content))]))
            else:
                contents.append(genai_types.Content(role="user", parts=[genai_types.Part.from_text(text=str(content))]))

        if not contents:
            contents = [genai_types.Content(role="user", parts=[genai_types.Part.from_text(text="Analyze and proceed.")])]

        # Format tools if provided
        genai_tools = None
        if tools:
            func_decls = []
            for t in tools:
                fn = t.get("function", t) if isinstance(t, dict) else {"name": str(t)}
                raw_name = fn.get("name", "tool_fn")
                clean_name = re.sub(r"[^a-zA-Z0-9_-]", "_", str(raw_name)).strip("_")[:64] or "tool_fn"
                params = fn.get("parameters") or fn.get("inputSchema") or {"type": "object", "properties": {}}
                func_decls.append(genai_types.FunctionDeclaration(
                    name=clean_name,
                    description=fn.get("description", "Agent tool function"),
                    parameters=params,
                ))
            if func_decls:
                genai_tools = [genai_types.Tool(function_declarations=func_decls)]

        config = genai_types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=genai_tools,
            temperature=0.4,
        )

        response = self.gemini_client.models.generate_content(
            model=model_name,
            contents=contents,
            config=config,
        )

        tool_calls = []
        if hasattr(response, "function_calls") and response.function_calls:
            for fc in response.function_calls:
                tool_calls.append({
                    "id": f"call_{fc.name}",
                    "type": "function",
                    "function": {
                        "name": fc.name,
                        "arguments": json.dumps(fc.args if hasattr(fc, "args") and fc.args else {}),
                    }
                })

        text_content = ""
        if hasattr(response, "text") and response.text:
            text_content = response.text

        return {
            "role": "assistant",
            "content": text_content,
            "tool_calls": tool_calls if tool_calls else None,
        }

    def chat(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        # 1. Try Google GenAI SDK first if configured
        if self.gemini_client:
            try:
                result = self._chat_with_genai_sdk(messages, tools)
                if result is not None:
                    return result
            except Exception as err:
                # Log and fallback to configured HTTP providers
                pass

        # 2. Normalize tools for OpenAI-compatible REST endpoints
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
                        last_error = f"{prov['name']} HTTP {res.status_code}: {res.text[:200]}"
                        break

                    res.raise_for_status()
                    return res.json()["choices"][0]["message"]

                except Exception as err:
                    last_error = err
                    time.sleep(1)

        raise RuntimeError(f"All configured LLM providers failed or rate-limited. Last error: {last_error}")
