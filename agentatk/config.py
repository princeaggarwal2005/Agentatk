import json
import os

import yaml


def load_target(config_path):
    config_dir = os.path.dirname(os.path.abspath(config_path))
    with open(config_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    api_key = os.environ.get(raw["api_key_env"])
    if not api_key:
        raise SystemExit(f"Environment variable '{raw['api_key_env']}' is not set.")

    policy_path = raw.get("policy_file")
    return {
        "name": raw["name"],
        "base_url": raw["base_url"].rstrip("/"),
        "model": raw["model"],
        "api_key": api_key,
        "system_prompt": raw["system_prompt"],
        "tools": _load_tools(_resolve(config_dir, raw["tools_file"])),
        "policy": _load_yaml(_resolve(config_dir, policy_path)) if policy_path else None,
    }


def _resolve(config_dir, path):
    if os.path.isabs(path):
        return path
    return os.path.join(config_dir, path)


def _load_tools(path):
    flat = _load_json(path)
    return [{"type": "function", "function": tool} for tool in flat]


def _load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)