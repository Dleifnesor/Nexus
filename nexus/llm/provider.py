"""LLM provider abstraction with structured-output support.

Default provider is Ollama (local). OpenAI/Anthropic providers are available when an API
key is configured. All providers implement `generate` (free text) and `generate_structured`
(parse JSON into a pydantic model, with a repair retry).
"""
from __future__ import annotations

import json
import re
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from ..config import LLMConfig
from ..logging_ import get_logger

log = get_logger(__name__)

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    pass


class TokenCounter:
    """Approximate token accounting shared with the budget module."""

    def __init__(self) -> None:
        self.total = 0

    def add_text(self, *texts: str) -> None:
        for t in texts:
            if t:
                self.total += max(1, len(t) // 4)


class BaseProvider:
    def __init__(self, cfg: LLMConfig, counter: TokenCounter | None = None):
        self.cfg = cfg
        self.counter = counter or TokenCounter()

    def generate(self, prompt: str, system: str = "") -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def generate_structured(self, prompt: str, model: type[T], system: str = "") -> T:
        instruction = (
            f"{prompt}\n\nRespond with ONLY a valid JSON object matching this schema, "
            f"no prose, no markdown fences:\n{json.dumps(model.model_json_schema())}"
        )
        raw = self.generate(instruction, system=system)
        try:
            return _parse_model(raw, model)
        except (ValidationError, ValueError) as e:
            log.warning("Structured parse failed, attempting repair: %s", e)
            repair = (
                f"Your previous output was invalid: {e}\nHere is what you returned:\n{raw}\n\n"
                f"Return ONLY corrected JSON matching the schema."
            )
            raw2 = self.generate(repair, system=system)
            return _parse_model(raw2, model)


class OllamaProvider(BaseProvider):
    def generate(self, prompt: str, system: str = "") -> str:
        url = (self.cfg.base_url or "http://localhost:11434").rstrip("/") + "/api/generate"
        payload = {
            "model": self.cfg.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {"temperature": self.cfg.temperature},
        }
        self.counter.add_text(prompt, system)
        try:
            resp = httpx.post(url, json=payload, timeout=300)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise LLMError(f"Ollama request failed: {e}") from e
        text = resp.json().get("response", "")
        self.counter.add_text(text)
        return text


class OpenAIProvider(BaseProvider):
    def generate(self, prompt: str, system: str = "") -> str:
        base = (self.cfg.base_url or "https://api.openai.com/v1").rstrip("/")
        url = base + "/chat/completions"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        self.counter.add_text(prompt, system)
        try:
            resp = httpx.post(
                url,
                headers={"Authorization": f"Bearer {self.cfg.api_key}"},
                json={
                    "model": self.cfg.model,
                    "messages": messages,
                    "temperature": self.cfg.temperature,
                    "max_tokens": self.cfg.max_output_tokens,
                },
                timeout=300,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise LLMError(f"OpenAI request failed: {e}") from e
        text = resp.json()["choices"][0]["message"]["content"]
        self.counter.add_text(text)
        return text


class AnthropicProvider(BaseProvider):
    def generate(self, prompt: str, system: str = "") -> str:
        base = (self.cfg.base_url or "https://api.anthropic.com").rstrip("/")
        url = base + "/v1/messages"
        self.counter.add_text(prompt, system)
        try:
            resp = httpx.post(
                url,
                headers={
                    "x-api-key": self.cfg.api_key or "",
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": self.cfg.model,
                    "system": system,
                    "max_tokens": self.cfg.max_output_tokens,
                    "temperature": self.cfg.temperature,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=300,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise LLMError(f"Anthropic request failed: {e}") from e
        blocks = resp.json().get("content", [])
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        self.counter.add_text(text)
        return text


def build_provider(cfg: LLMConfig, counter: TokenCounter | None = None) -> BaseProvider:
    provider = (cfg.provider or "ollama").lower()
    if provider == "ollama":
        return OllamaProvider(cfg, counter)
    if provider == "openai":
        return OpenAIProvider(cfg, counter)
    if provider == "anthropic":
        return AnthropicProvider(cfg, counter)
    raise LLMError(f"Unknown LLM provider: {cfg.provider}")


def _parse_model(raw: str, model: type[T]) -> T:
    data = _extract_json(raw)
    return model.model_validate(data)


def _extract_json(raw: str) -> dict:
    raw = raw.strip()
    # strip markdown fences if present
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence:
        raw = fence.group(1)
    # find first balanced JSON object
    start = raw.find("{")
    if start == -1:
        raise ValueError("No JSON object found in LLM output")
    depth = 0
    for i in range(start, len(raw)):
        if raw[i] == "{":
            depth += 1
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(raw[start : i + 1])
    raise ValueError("Unbalanced JSON object in LLM output")
