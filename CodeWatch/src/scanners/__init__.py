"""Base scanner interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.models import Finding, Language


class BaseScanner(ABC):
    """Base class for all scanners."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def scan_file(self, content: str, file_path: str, language: Language) -> list[Finding]:
        ...

    def should_scan(self, file_path: str) -> bool:
        return True


class BaseLanguageScanner(BaseScanner):
    """Scanner that operates on specific languages."""

    supported_languages: list[Language] = []

    def supports(self, language: Language) -> bool:
        return language in self.supported_languages

    def scan_file(self, content: str, file_path: str, language: Language) -> list[Finding]:
        if not self.supports(language):
            return []
        return self._scan(content, file_path, language)

    def _scan(self, content: str, file_path: str, language: Language) -> list[Finding]:
        return []
