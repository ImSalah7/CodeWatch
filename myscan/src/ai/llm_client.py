"""LLM Client - Optional AI-powered explanations via OpenAI, Anthropic, or Google.

Provides a unified interface for LLM providers with automatic fallback.
When no API key is configured, falls back to static explanations.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from an LLM provider."""
    content: str
    provider: str
    model: str
    tokens_used: int = 0
    latency_ms: float = 0.0


class LLMClient:
    """Unified LLM client with provider fallback."""

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ):
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._provider = provider or self._detect_provider()
        self._model = model or self._default_model()
        self._client = None

    def _detect_provider(self) -> str:
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        if os.environ.get("ANTHROPIC_API_KEY"):
            return "anthropic"
        if os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
            return "google"
        return "none"

    def _default_model(self) -> str:
        defaults = {
            "openai": "gpt-4o-mini",
            "anthropic": "claude-3-5-haiku-20241022",
            "google": "gemini-2.0-flash",
        }
        return defaults.get(self._provider, "none")

    @property
    def available(self) -> bool:
        return self._provider != "none"

    @property
    def provider_name(self) -> str:
        return self._provider

    @property
    def model_name(self) -> str:
        return self._model

    def _init_client(self):
        if self._client is not None:
            return
        if self._provider == "openai":
            try:
                from openai import OpenAI
                self._client = OpenAI()
            except ImportError:
                logger.warning("openai package not installed. Run: pip install openai")
                self._provider = "none"
        elif self._provider == "anthropic":
            try:
                import anthropic
                self._client = anthropic.Anthropic()
            except ImportError:
                logger.warning("anthropic package not installed. Run: pip install anthropic")
                self._provider = "none"
        elif self._provider == "google":
            try:
                import google.generativeai as genai
                api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
                genai.configure(api_key=api_key)
                self._client = genai
            except ImportError:
                logger.warning("google-generativeai package not installed. Run: pip install google-generativeai")
                self._provider = "none"

    def chat(self, prompt: str, system_prompt: str | None = None) -> LLMResponse | None:
        """Send a chat request and return the response."""
        if not self.available:
            return None

        self._init_client()
        if not self._client:
            return None

        import time
        start = time.time()

        try:
            if self._provider == "openai":
                return self._chat_openai(prompt, system_prompt, start)
            elif self._provider == "anthropic":
                return self._chat_anthropic(prompt, system_prompt, start)
            elif self._provider == "google":
                return self._chat_google(prompt, system_prompt, start)
        except Exception as e:
            logger.error(f"LLM request failed ({self._provider}): {e}")
            return None
        return None

    def _chat_openai(self, prompt: str, system_prompt: str | None, start: float) -> LLMResponse | None:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        content = response.choices[0].message.content or ""
        tokens = response.usage.total_tokens if response.usage else 0
        return LLMResponse(
            content=content,
            provider="openai",
            model=self._model,
            tokens_used=tokens,
            latency_ms=(time.time() - start) * 1000,
        )

    def _chat_anthropic(self, prompt: str, system_prompt: str | None, start: float) -> LLMResponse | None:
        kwargs = {
            "model": self._model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if system_prompt:
            kwargs["system"] = system_prompt

        response = self._client.messages.create(
            **kwargs,
            messages=[{"role": "user", "content": prompt}],
        )
        content = response.content[0].text if response.content else ""
        tokens = (response.usage.input_tokens + response.usage.output_tokens) if response.usage else 0
        return LLMResponse(
            content=content,
            provider="anthropic",
            model=self._model,
            tokens_used=tokens,
            latency_ms=(time.time() - start) * 1000,
        )

    def _chat_google(self, prompt: str, system_prompt: str | None, start: float) -> LLMResponse | None:
        model = self._client.GenerativeModel(
            self._model,
            system_instruction=system_prompt or None,
        )
        response = model.generate_content(
            prompt,
            generation_config=self._client.types.GenerationConfig(
                temperature=self.temperature,
                max_output_tokens=self.max_tokens,
            ),
        )
        content = response.text or ""
        tokens = response.usage_metadata.total_token_count if hasattr(response, "usage_metadata") else 0
        return LLMResponse(
            content=content,
            provider="google",
            model=self._model,
            tokens_used=tokens,
            latency_ms=(time.time() - start) * 1000,
        )


SYSTEM_PROMPT_SECURITY = """You are an expert application security engineer analyzing code vulnerabilities.
Provide concise, actionable explanations. Focus on:
1. What the vulnerability is and why it's dangerous
2. How an attacker would exploit it
3. The specific impact
4. How to fix it with code examples

Be technical but accessible. Use standard security terminology (CWE, OWASP)."""


def enhance_explanation(
    category: str,
    title: str,
    description: str,
    code_snippet: str,
    file_path: str = "",
    line: int = 0,
    severity: str = "",
    client: LLMClient | None = None,
) -> str | None:
    """Use LLM to generate an enhanced explanation for a finding.

    Returns enhanced explanation text, or None if LLM is unavailable.
    """
    if client is None:
        client = LLMClient()
    if not client.available:
        return None

    prompt = f"""Analyze this security finding and provide a detailed explanation:

**Category:** {category}
**Title:** {title}
**Description:** {description}
**Severity:** {severity}
**File:** {file_path}:{line}

**Vulnerable Code:**
```
{code_snippet[:1000] if code_snippet else "No code snippet available"}
```

Provide:
1. A clear explanation of why this is vulnerable
2. An attack scenario
3. The business impact
4. A secure code fix"""

    response = client.chat(prompt, system_prompt=SYSTEM_PROMPT_SECURITY)
    return response.content if response else None
