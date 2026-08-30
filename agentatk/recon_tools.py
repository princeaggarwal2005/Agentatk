import os
import ast
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


IGNORED_SYSTEM_DIRS = {
    ".git", "__pycache__", "venv", ".venv", "node_modules", ".pytest_cache", 
    "runs", "scratch", "dist", "build", ".next", ".agentatk_cache",
    ".claude", ".gemini", ".agents", "_tmp_opfor", "agentatk.egg-info",
    "tests", "test", "__tests__", "spec", "specs", "train", "docs", "scripts"
}



def is_ignored_path(path: Path, root: Path) -> bool:
    """
    Determines if a path should be ignored during autonomous recon.
    Automatically ignores:
    - Virtual environments, git, build artifacts, cache, and test run output
    - Agentatk's own installation package (allowing users to clone agentatk directly into target repos)
    """
    try:
        abs_path = path.resolve()
        
        # 1. Ignore agentatk's own package directory
        pkg_dir = Path(__file__).resolve().parent
        if abs_path == pkg_dir or pkg_dir in abs_path.parents:
            return True
        
        # 2. Check path segments against ignored directories
        try:
            rel_parts = set(path.relative_to(root).parts)
        except ValueError:
            rel_parts = set(path.parts)

        if any(p in IGNORED_SYSTEM_DIRS for p in rel_parts):
            return True
            
        # 3. If agentatk is cloned inside target under name 'agentatk' or 'securitycheckeragent'
        if any(p in ("agentatk", "securitycheckeragent") for p in rel_parts):
            return True

    except Exception:
        pass
    return False


def list_files(target_dir: str, depth: int = 4) -> Dict[str, Any]:
    """Lists files up to a certain depth in the target directory."""
    root = Path(target_dir).resolve()
    if not root.exists():
        return {"ok": False, "error": f"Target directory '{target_dir}' does not exist"}

    files_list = []

    for path in root.rglob("*"):
        try:
            if is_ignored_path(path, root):
                continue
            if len(path.relative_to(root).parts) <= depth:
                files_list.append({
                    "path": str(path.relative_to(root)).replace("\\", "/"),
                    "is_dir": path.is_dir(),
                    "size": path.stat().st_size if path.is_file() else 0,
                })
        except Exception:
            continue

    return {"ok": True, "data": {"files": files_list}}


def read_file(file_path: str, max_bytes: int = 15000) -> Dict[str, Any]:
    """Reads content of a file up to max_bytes."""
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        return {"ok": False, "error": f"File '{file_path}' does not exist or is not a file"}

    try:
        content = path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
        return {"ok": True, "data": {"path": str(path), "content": content}}
    except Exception as e:
        return {"ok": False, "error": f"Failed to read file: {e}"}


def search_codebase(target_dir: str, query: str, max_results: int = 25) -> Dict[str, Any]:
    """Searches for regex/text pattern across files in target directory."""
    root = Path(target_dir).resolve()
    if not root.exists():
        return {"ok": False, "error": f"Directory '{target_dir}' does not exist"}

    matches = []

    for path in root.rglob("*"):
        try:
            if is_ignored_path(path, root) or not path.is_file():
                continue
            
            if path.suffix.lower() not in (".py", ".js", ".ts", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".md", ".txt", ".toml", ".go", ".rs", ".java"):
                continue

            content = path.read_text(encoding="utf-8", errors="replace")
            for idx, line in enumerate(content.splitlines(), start=1):
                if re.search(query, line, re.IGNORECASE):
                    matches.append({
                        "file": str(path.relative_to(root)).replace("\\", "/"),
                        "line": idx,
                        "content": line.strip()[:150],
                    })
                    if len(matches) >= max_results:
                        break
        except Exception:
            continue

    return {"ok": True, "data": {"matches": matches, "query": query}}


def inspect_symbol(file_path: str, symbol_name: str) -> Dict[str, Any]:
    """Locates symbols in Python or JavaScript/TypeScript files."""
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        return {"ok": False, "error": f"File '{file_path}' does not exist"}

    content = path.read_text(encoding="utf-8", errors="replace")
    found = []

    if path.suffix == ".py":
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if node.name == symbol_name or symbol_name.lower() in node.name.lower():
                        doc = ast.get_docstring(node) or ""
                        found.append({
                            "name": node.name,
                            "type": type(node).__name__,
                            "line": node.lineno,
                            "docstring": doc[:200],
                        })
        except Exception:
            pass

    # Regex search across TS/JS/others
    for idx, line in enumerate(content.splitlines(), start=1):
        if re.search(rf"\b(function|const|let|var|class|def)\s+{re.escape(symbol_name)}\b", line, re.IGNORECASE):
            found.append({
                "name": symbol_name,
                "type": "Declaration",
                "line": idx,
                "value_snippet": line.strip()[:150],
            })

    return {"ok": True, "data": {"symbol": symbol_name, "matches": found}}


def inspect_dependencies(target_dir: str) -> Dict[str, Any]:
    """Inspects requirements.txt, pyproject.toml, package.json, Cargo.toml, go.mod for frameworks & packages."""
    root = Path(target_dir).resolve()
    manifests = []
    packages = []
    frameworks = []

    req_txt = root / "requirements.txt"
    if req_txt.exists():
        manifests.append("requirements.txt")
        content = req_txt.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                pkg = line.split("==")[0].split(">=")[0].split("<=")[0].strip()
                packages.append(pkg)
                if any(f in pkg.lower() for f in ("langchain", "crewai", "autogen", "semantic-kernel", "homeassistant", "fastapi")):
                    frameworks.append(pkg)

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        manifests.append("pyproject.toml")
        content = pyproject.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            if "langchain" in line.lower():
                frameworks.append("LangChain")
            if "crewai" in line.lower():
                frameworks.append("CrewAI")
            if "autogen" in line.lower():
                frameworks.append("AutoGen")
            if "fastapi" in line.lower():
                frameworks.append("FastAPI")
            if "homeassistant" in line.lower() or "custom_components" in line.lower():
                frameworks.append("HomeAssistant Integration")

    pkg_json = root / "package.json"
    if pkg_json.exists():
        manifests.append("package.json")
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            packages.extend(deps.keys())
            if "@langchain/core" in deps or "langchain" in deps:
                frameworks.append("LangChain.js")
            if "@modelcontextprotocol/sdk" in deps:
                frameworks.append("MCP Server")
            if "express" in deps:
                frameworks.append("Express.js API")
            if "ai" in deps or "@ai-sdk" in str(deps):
                frameworks.append("Vercel AI SDK")
        except Exception:
            pass

    for manifest_path in root.glob("**/manifest.json"):
        manifests.append(str(manifest_path.relative_to(root)).replace("\\", "/"))
        frameworks.append("HomeAssistant Integration")

    return {
        "ok": True,
        "data": {
            "manifests": list(set(manifests)),
            "packages": list(set(packages)),
            "frameworks": list(set(frameworks)),
        },
    }


def _score_prompt(name: str, text: str) -> int:
    """Ranks system prompts to prefer rich, authoritative personas over generic task helpers."""
    score = 0
    t_lower = text.lower()
    name_upper = name.upper()

    if "PERSONA" in name_upper or "DEFAULT_PROMPT" in name_upper or "SYSTEM_PROMPT" in name_upper or "SYSTEM" in name_upper:
        score += 50
    elif "PROMPT" in name_upper or "INSTRUCTION" in name_upper:
        score += 20

    if "you are '" in t_lower or "you are an ai assistant" in t_lower or "you are a helpful" in t_lower or "you are max" in t_lower or "you are an autonomous" in t_lower:
        score += 40

    if "controls the devices" in t_lower or "assist the user" in t_lower or "help customers" in t_lower or "database through tools" in t_lower or "support agent" in t_lower:
        score += 30

    if "task-specific assistant" in t_lower or "default_ai_task_prompt" in name.lower():
        score -= 80
    if len(text) < 30:
        score -= 40

    return score


INTERNAL_HELPER_PREFIXES = (
    "strip_", "get_oai_", "_format_", "_convert_", "_parse_", 
    "_serialize_", "_deserialize_", "_validate_", "_normalize_", 
    "_init_", "_setup_", "async_get_api_instance", "action_", "on_",
    "fake_", "mock_", "stub_", "dummy_"
)


GENERIC_NON_TOOL_NAMES = {
    "get", "set", "close", "pop", "keys", "values", "items", "clear",
    "get_system_prompt", "get_persona", "build_user_prompt", "build_prompt",
    "prompt_key", "listener"
}

KNOWN_DEVICE_DOMAINS = [
    "garage_door", "media_player", "light", "switch", "button", "fan", 
    "cover", "lock", "climate", "vacuum", "todo", "timer", "script", 
    "blinds", "curtain", "door", "alarm", "valve", "siren"
]

SINK_VERBS = (
    "turn_on", "turn_off", "lock", "unlock", "open", "close", "delete", "exec", 
    "send", "post", "set_", "update", "cancel", "call_service", "override_", 
    "dispense", "refund", "process_", "create_", "query_", "execute_", "order", 
    "trade", "buy", "sell", "allocate", "rebalance", "liquidate", "drop", "truncate"
)

SOURCE_VERBS = (
    "read", "get", "fetch", "search", "list", "view", "receive", "listen", 
    "chat", "message", "lookup", "input", "prompt"
)


def _normalize_service_action(raw_name: str) -> Tuple[str, Optional[str]]:
    """Extracts canonical action name and optional domain."""
    clean = raw_name.lower().replace("hassservice_", "").strip()
    
    if "." in clean:
        parts = clean.split(".", 1)
        return parts[1], parts[0]

    for dom in KNOWN_DEVICE_DOMAINS:
        prefix = f"{dom}_"
        if clean.startswith(prefix):
            action = clean[len(prefix):]
            if len(action) >= 3:
                return action, dom

    if clean in ("open_cover", "close_cover", "stop_cover"):
        return clean, "cover"
    if clean in ("lock", "unlock"):
        return clean, "lock"
    if clean in ("set_temperature", "set_humidity", "set_hvac_mode", "set_fan_mode"):
        return clean, "climate"
    if clean in ("increase_speed", "decrease_speed"):
        return clean, "fan"

    return clean, None


def _extract_ts_js_tools_and_prompts(content: str, rel_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Extracts system prompts and tools from TypeScript / JavaScript files (LangChain.js, Express, etc.)."""
    prompts = []
    tools = []
    sources = []
    sinks = []

    # 1. System Prompt matching (e.g. const SYSTEM_PROMPT = `...` or "...")
    prompt_patterns = [
        r'(?:const|let|var)\s+([A-Za-z0-9_]*SYSTEM[A-Za-z0-9_]*)\s*=\s*[`"\']([\s\S]*?)[`"\'];',
        r'system_message\s*=\s*[`"\']([\s\S]*?)[`"\']',
        r'systemPrompt\s*:\s*[`"\']([\s\S]*?)[`"\']',
        r'(?:const|let|var)\s+([A-Za-z0-9_]*PROMPT[A-Za-z0-9_]*)\s*=\s*[`"\']([\s\S]*?)[`"\'];',
    ]

    for pat in prompt_patterns:
        for match in re.finditer(pat, content):
            groups = match.groups()
            if len(groups) == 2:
                name, text = groups[0], groups[1].strip()
            else:
                name, text = "system_prompt", groups[0].strip()

            if len(text) > 25 and not text.startswith("http"):
                prompts.append({
                    "file": rel_path,
                    "name": name,
                    "text": text,
                    "score": _score_prompt(name, text),
                })

    # 2. LangChain JS / Zod tool declarations (e.g. name: "lookup_order", description: "...")
    tool_decl_pat = r'name\s*:\s*["\']([a-zA-Z0-9_-]+)["\']\s*,\s*description\s*:\s*["\']([\s\S]*?)["\']'
    for match in re.finditer(tool_decl_pat, content):
        t_name = match.group(1).strip()
        t_desc = match.group(2).strip()
        
        tool_obj = {
            "name": t_name,
            "description": t_desc[:150],
            "file": rel_path,
            "line": content[:match.start()].count("\n") + 1,
            "parameters": {"type": "object", "properties": {}},
        }
        tools.append(tool_obj)

        lowered = t_name.lower()
        if any(v in lowered for v in SINK_VERBS):
            sinks.append({
                "name": t_name,
                "file": rel_path,
                "line": tool_obj["line"],
                "description": t_desc[:150],
                "type": "sink",
            })
        elif any(v in lowered for v in SOURCE_VERBS):
            sources.append({
                "name": t_name,
                "file": rel_path,
                "line": tool_obj["line"],
                "description": t_desc[:150],
                "type": "source",
            })

    # 3. Function declarations: function <name>() or const <name> = tool(...)
    fn_pat = r'(?:async\s+)?function\s+([a-zA-Z0-9_]+)\s*\('
    for match in re.finditer(fn_pat, content):
        fn_name = match.group(1).strip()
        if fn_name.startswith("_") or fn_name.startswith("test"):
            continue
        lowered = fn_name.lower()
        line_no = content[:match.start()].count("\n") + 1
        
        if any(v in lowered for v in SINK_VERBS):
            sinks.append({
                "name": fn_name,
                "file": rel_path,
                "line": line_no,
                "description": f"Action sink: {fn_name}",
                "type": "sink",
            })
        elif any(v in lowered for v in SOURCE_VERBS):
            sources.append({
                "name": fn_name,
                "file": rel_path,
                "line": line_no,
                "description": f"Source action: {fn_name}",
                "type": "source",
            })

    return prompts, tools, sources, sinks


def extract_agent_artifacts(target_dir: str) -> Dict[str, Any]:
    """
    Universal language- and framework-agnostic recon tool that extracts system prompts,
    tools, sources, and sinks across Python, TypeScript, JavaScript, OpenAPI, and schemas.
    """
    root = Path(target_dir).resolve()
    discovered_prompts = []
    raw_service_entries = []
    general_sinks = []
    discovered_sources = []
    discovered_guardrails = []
    discovered_domains = set()
    discovered_tools = []
    seen_tools = set()

    ignored_dir_names = {
        ".git", "__pycache__", "venv", ".venv", "node_modules", ".pytest_cache", 
        "runs", "dist", "build", "tests", "test", "__tests__", "spec", "specs", 
        "train", "docs", "scripts"
    }

    # 1. Scan across all source files (.py, .ts, .js, .json, .yaml, .yml, .go, .rs)
    for src_file in root.rglob("*"):
        if not src_file.is_file() or is_ignored_path(src_file, root):
            continue

        rel_path = src_file.relative_to(root).as_posix()
        ext = src_file.suffix.lower()

        # --- A. PYTHON FILES ---
        if ext == ".py":
            try:
                content = src_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            target_id = getattr(target, "id", "")
                            
                            if any(k in target_id.upper() for k in ("PROMPT", "PERSONA", "SYSTEM", "INSTRUCTION", "TEMPLATE")):
                                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                    val = node.value.value.strip()
                                    if len(val) > 20 and not val.startswith("http"):
                                        discovered_prompts.append({"file": rel_path, "name": target_id, "text": val, "score": _score_prompt(target_id, val)})
                                elif isinstance(node.value, ast.Dict):
                                    for k, v in zip(node.value.keys, node.value.values):
                                        if isinstance(v, ast.Constant) and isinstance(v.value, str) and len(v.value) > 20:
                                            pname = f"{target_id}.{getattr(k, 'value', '')}"
                                            discovered_prompts.append({"file": rel_path, "name": pname, "text": v.value, "score": _score_prompt(pname, v.value)})

                            if "DOMAINS" in target_id.upper():
                                if isinstance(node.value, (ast.List, ast.Set, ast.Tuple)):
                                    for elt in node.value.elts:
                                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                            discovered_domains.add(elt.value.strip())

                            if "ALLOWED_SERVICES" in target_id.upper() or "ALLOWED_TOOLS" in target_id.upper() or (target_id.upper().endswith("_SERVICES") and "PROMPT" not in target_id.upper()):
                                if isinstance(node.value, (ast.List, ast.Set, ast.Tuple)):
                                    for elt in node.value.elts:
                                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                            service_name = elt.value.strip()
                                            if len(service_name) > 2:
                                                raw_service_entries.append({
                                                    "raw_name": service_name,
                                                    "file": rel_path,
                                                    "line": node.lineno,
                                                })

                    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                        if any(pk in node.value for pk in ("You are '", "You are an AI", "You are a helpful", "Assistant that controls")):
                            if len(node.value) > 25:
                                discovered_prompts.append({"file": rel_path, "name": "persona_prompt", "text": node.value.strip(), "score": _score_prompt("persona_prompt", node.value.strip())})

                    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        fn_name = node.name
                        lowered = fn_name.lower()
                        if fn_name.startswith("test_") or fn_name.startswith("_"):
                            continue
                        if any(fn_name.startswith(pfx) or lowered.startswith(pfx) for pfx in INTERNAL_HELPER_PREFIXES):
                            continue
                        if any(lowered.startswith(pfx) for pfx in ("fake_", "mock_", "stub_", "dummy_")):
                            continue


                        doc = ast.get_docstring(node) or ""
                        lowered = fn_name.lower()

                        is_decorated_tool = False
                        for dec in node.decorator_list:
                            dec_id = getattr(dec, "id", "") or getattr(getattr(dec, "func", None), "id", "") or getattr(getattr(dec, "attr", None), "name", "")
                            if any(t in str(dec_id).lower() for t in ("tool", "action", "mcp", "service", "route", "post", "delete")):
                                is_decorated_tool = True

                        if not is_decorated_tool and lowered in GENERIC_NON_TOOL_NAMES:
                            continue

                        if is_decorated_tool or any(w in lowered for w in SINK_VERBS):
                            general_sinks.append({
                                "name": fn_name,
                                "file": rel_path,
                                "line": node.lineno,
                                "description": doc[:120] if doc else f"State-changing action sink: {fn_name}",
                                "type": "sink",
                            })
                        elif any(w in lowered for w in SOURCE_VERBS):
                            discovered_sources.append({
                                "name": fn_name,
                                "file": rel_path,
                                "line": node.lineno,
                                "description": doc[:120] if doc else f"Input source: {fn_name}",
                                "type": "source",
                            })

            except Exception:
                pass

        # --- B. TYPESCRIPT & JAVASCRIPT FILES ---
        elif ext in (".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"):
            try:
                content = src_file.read_text(encoding="utf-8", errors="replace")
                p_list, t_list, src_list, snk_list = _extract_ts_js_tools_and_prompts(content, rel_path)
                discovered_prompts.extend(p_list)
                general_sinks.extend(snk_list)
                discovered_sources.extend(src_list)
                for t in t_list:
                    if t["name"] not in seen_tools:
                        seen_tools.add(t["name"])
                        discovered_tools.append(t)
            except Exception:
                pass

        # --- C. TEXT / MARKDOWN / JSON / YAML ---
        elif ext in (".txt", ".md", ".json", ".yaml", ".yml", ".gbnf"):
            try:
                text = src_file.read_text(encoding="utf-8", errors="replace")[:2000]
                if any(pk in text for pk in ("You are '", "You are an", "You are a", "You are Max", "system_prompt", "AI Assistant", "SYSTEM_PROMPT")):
                    discovered_prompts.append({"file": rel_path, "name": src_file.name, "text": text.strip(), "score": _score_prompt(src_file.name, text.strip())})
            except Exception:
                pass

    # Sort prompts by score
    discovered_prompts.sort(key=lambda p: p.get("score", 0), reverse=True)

    # Deduplicate Prompts
    unique_prompts = []
    seen_prompts = set()
    for p in discovered_prompts:
        t = p["text"][:100]
        if t not in seen_prompts:
            seen_prompts.add(t)
            unique_prompts.append(p)

    # Canonical Service Sink Deduplication
    canonical_sinks_map: Dict[str, Dict[str, Any]] = {}

    for entry in raw_service_entries:
        raw_name = entry["raw_name"]
        action, domain = _normalize_service_action(raw_name)
        canonical_name = f"HassService_{action}"

        if canonical_name not in canonical_sinks_map:
            canonical_sinks_map[canonical_name] = {
                "name": canonical_name,
                "action": action,
                "domains": set(),
                "file": entry["file"],
                "line": entry["line"],
                "description": f"Device service action: {action}",
                "type": "sink",
            }
        
        if domain:
            canonical_sinks_map[canonical_name]["domains"].add(domain)

    for sink_entry in canonical_sinks_map.values():
        act = sink_entry["action"]
        if act in ("open_cover", "close_cover", "stop_cover", "toggle"):
            if "cover" in discovered_domains:
                sink_entry["domains"].add("cover")
        if act in ("lock", "unlock"):
            if "lock" in discovered_domains:
                sink_entry["domains"].add("lock")
        if act in ("set_temperature", "set_humidity", "set_hvac_mode", "set_fan_mode"):
            if "climate" in discovered_domains:
                sink_entry["domains"].add("climate")
        if act in ("turn_on", "turn_off", "toggle"):
            for d in ("light", "switch", "fan"):
                if d in discovered_domains:
                    sink_entry["domains"].add(d)

    registered_service_sinks = []
    for sink_entry in canonical_sinks_map.values():
        dom_list = sorted(list(sink_entry["domains"]))
        desc = f"Device service action: {sink_entry['action']}"
        if dom_list:
            desc += f" (Domains: {', '.join(dom_list)})"
        
        registered_service_sinks.append({
            "name": sink_entry["name"],
            "action": sink_entry["action"],
            "domains": dom_list,
            "file": sink_entry["file"],
            "line": sink_entry["line"],
            "description": desc,
            "type": "sink",
        })

    # Prioritize registered service sinks over generic functions if available, or combine
    all_sinks = registered_service_sinks + general_sinks
    unique_sinks = []
    seen_sink_names = set()
    for s in all_sinks:
        if s["name"] not in seen_sink_names:
            seen_sink_names.add(s["name"])
            unique_sinks.append(s)

    for s in unique_sinks:
        if s["name"] not in seen_tools:
            seen_tools.add(s["name"])
            discovered_tools.append({
                "name": s["name"],
                "description": s["description"],
                "parameters": {"type": "object", "properties": {}},
                "domains": s.get("domains", []),
            })

    for s in discovered_sources:
        if s["name"] not in seen_tools:
            seen_tools.add(s["name"])
            discovered_tools.append({
                "name": s["name"],
                "description": s["description"],
                "parameters": {"type": "object", "properties": {}},
            })

    return {
        "prompts": unique_prompts,
        "tools": discovered_tools,
        "sources": discovered_sources,
        "sinks": unique_sinks,
        "guardrails": discovered_guardrails,
        "domains": sorted(list(discovered_domains)),
    }
