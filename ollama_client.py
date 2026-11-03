from __future__ import annotations

import requests

DEFAULT_SYSTEM_PROMPT = """You are a network traffic analyst. Analyze only the packet-capture evidence provided. Separate observed facts from hypotheses, cite packet or stream identifiers where available, and do not claim maliciousness without supporting evidence. Do not invent packet contents or external context."""


def list_models(base_url: str) -> list[str]:
    """Return model names available from an Ollama server."""
    response = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
    response.raise_for_status()
    return [item["name"] for item in response.json().get("models", []) if item.get("name")]


def ask(
    base_url: str,
    model: str,
    system_prompt: str,
    user_prompt: str = "",
    conversation: list[dict[str, str]] | None = None,
) -> str:
    """Send a chat request to Ollama and return its response text."""
    messages = [{"role": "system", "content": system_prompt}]
    if conversation is None:
        messages.append({"role": "user", "content": user_prompt})
    else:
        messages.extend(conversation)
    response = requests.post(
        f"{base_url.rstrip('/')}/api/chat",
        json={"model": model, "stream": False, "messages": messages},
        timeout=None,
    )
    response.raise_for_status()
    return str(response.json().get("message", {}).get("content", ""))
