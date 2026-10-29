"""LLM-powered finding enrichment wired into the scan pipeline.

Optional: activates only when a provider API key is configured and the
``MYSCAN_LLM_ENHANCE`` env flag is not ``0``. On any failure, finding
content is left untouched (static explanations still apply).

Environment variables:
- ``MYSCAN_LLM_ENHANCE``: set to ``0`` to disable (default enabled)
- ``MYSCAN_LLM_MAX_FINDINGS``: max findings enriched per scan (default 20)
- ``MYSCAN_LLM_TIMEOUT``: per-finding timeout in seconds (default 30)
- ``MYSCAN_LLM_CONCURRENCY``: parallel LLM workers (default 4)
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import os
import threading
from typing import Any

from .llm_client import SYSTEM_PROMPT_SECURITY, LLMClient

logger = logging.getLogger(__name__)

_ENHANCE_FIELDS = ("why_vulnerable", "impact", "exploit_scenario", "fix_suggestion")

_cache: dict[str, dict[str, str]] = {}
_cache_lock = threading.Lock()
_enabled_flag: bool | None = None
_flag_lock = threading.Lock()


def _enabled() -> bool:
    global _enabled_flag
    with _flag_lock:
        if _enabled_flag is None:
            flag = os.environ.get("MYSCAN_LLM_ENHANCE", "1").strip().lower()
            _enabled_flag = flag not in ("0", "false", "no", "off")
        return _enabled_flag


def _cache_key(finding: Any) -> str:
    raw = (
        f"{finding.rule_id}:{finding.location.file_path}:{finding.location.line}:"
        f"{(finding.location.code_snippet or '')[:200]}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _severity_rank(finding: Any) -> int:
    return {
        "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
    }.get(getattr(finding.severity, "value", "info"), 0)


def _build_prompt(finding: Any) -> str:
    snippet = (finding.location.code_snippet or "")[:1500]
    return f"""Analyze this security finding and respond with valid JSON only, using EXACTLY these keys:
- "why_vulnerable": a clear explanation of why the code is vulnerable
- "impact": the security and business impact if exploited
- "exploit_scenario": a concrete step-by-step attack scenario
- "fix_suggestion": a concrete remediation with a short code sketch

Category: {finding.category.value}
Rule: {finding.rule_id}
Title: {finding.title}
Severity: {finding.severity.value}
File: {finding.location.file_path}:{finding.location.line}

Vulnerable Code:
```
{snippet or "No code snippet available"}
```

Return the JSON object only, no markdown fences, no commentary."""


def _parse_response(content: str) -> dict[str, str]:
    """Best-effort parse of an LLM response into field values."""
    text = (content or "").strip()
    if not text:
        return {}
    parsed = text
    if parsed.startswith("```"):
        parsed = parsed.strip("`")
        parsed = parsed.removeprefix("json").strip()
    try:
        data = json.loads(parsed)
    except ValueError:
        data = None
    if isinstance(data, dict):
        fields = {}
        for key in _ENHANCE_FIELDS:
            value = data.get(key)
            if isinstance(value, (str, int, float)) and str(value).strip():
                fields[key] = str(value).strip()
        return fields
    return {"why_vulnerable": text[:2000]}


def _apply_fields(finding: Any, fields: dict[str, str]) -> None:
    for attr in _ENHANCE_FIELDS:
        value = fields.get(attr)
        if value:
            setattr(finding, attr, value)


def _enhance_one(finding: Any, client: LLMClient) -> str | None:
    """Enhance one finding; returns 'enhanced', 'cached', or None on failure."""
    key = _cache_key(finding)
    with _cache_lock:
        cached = _cache.get(key)
    if cached:
        _apply_fields(finding, cached)
        return "cached"

    prompt = _build_prompt(finding)
    response = client.chat(prompt, system_prompt=SYSTEM_PROMPT_SECURITY)
    if response is None or not response.content:
        return None

    fields = _parse_response(response.content)
    if not fields:
        return None
    with _cache_lock:
        _cache[key] = fields
    _apply_fields(finding, fields)
    return "enhanced"


def enhance_findings(
    findings: list[Any],
    max_findings: int | None = None,
    timeout: float | None = None,
    max_workers: int | None = None,
) -> dict[str, Any]:
    """Enrich findings with LLM-generated explanations in the background.

    Returns a stats dict describing what was attempted/enhanced. Never
    raises: any failure leaves findings untouched.
    """
    if not _enabled():
        return {"enabled": False, "enhanced": 0, "attempted": 0}

    client = LLMClient()
    if not client.available:
        return {
            "enabled": True, "enhanced": 0, "attempted": 0,
            "error": "no LLM provider configured (set OPENAI/ANTHROPIC/GOOGLE API key)",
        }

    max_findings = max_findings or int(os.environ.get("MYSCAN_LLM_MAX_FINDINGS", "20"))
    timeout = timeout if timeout is not None else float(os.environ.get("MYSCAN_LLM_TIMEOUT", "30"))
    max_workers = max_workers or int(os.environ.get("MYSCAN_LLM_CONCURRENCY", "4"))
    max_workers = max(1, min(max_workers, 16))

    selected = sorted(findings, key=_severity_rank, reverse=True)[:max_findings]
    if not selected:
        return {"enabled": True, "enhanced": 0, "attempted": 0}

    stats: dict[str, Any] = {
        "enabled": True,
        "provider": client.provider_name,
        "model": client.model_name,
        "attempted": 0,
        "enhanced": 0,
        "cached": 0,
        "dropped_by_timeout": 0,
        "selected": len(selected),
    }

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    try:
        futures = [executor.submit(_enhance_one, finding, client) for finding in selected]
        batches = (len(futures) + max_workers - 1) // max_workers
        overall = timeout * batches + 15.0
        done, pending = concurrent.futures.wait(
            futures, timeout=overall, return_when=concurrent.futures.ALL_COMPLETED
        )
        for future in done:
            try:
                outcome = future.result()
                if outcome == "enhanced":
                    stats["enhanced"] += 1
                elif outcome == "cached":
                    stats["cached"] += 1
                stats["attempted"] += 1
            except Exception as exc:
                logger.warning("LLM enhancement failed: %s", exc)
                stats["attempted"] += 1
        stats["dropped_by_timeout"] = len(pending)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    return stats
