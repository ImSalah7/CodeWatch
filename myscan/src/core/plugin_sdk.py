"""Plugin SDK - Extensible plugin architecture.

Allows developers to build:
- Custom scanners
- Custom rules
- Custom reporters
- Custom exporters
- Custom analysis phases

Usage:
    from src.core.plugin_sdk import PluginManager, ScannerPlugin, RulePlugin

    manager = PluginManager()
    manager.register(MyCustomScanner())
    manager.register(MyCustomRule())
"""

from __future__ import annotations

import importlib
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class PluginMetadata:
    """Metadata for a plugin."""
    name: str
    version: str
    author: str = ""
    description: str = ""
    plugin_type: str = ""
    dependencies: list[str] = field(default_factory=list)


class PluginBase(ABC):
    """Base class for all plugins."""

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        pass

    def initialize(self, config: dict) -> None:
        pass

    def shutdown(self) -> None:
        pass


class ScannerPlugin(PluginBase):
    """Plugin that adds custom scanning capabilities."""

    @abstractmethod
    def scan_file(self, file_path: str, content: str, language: str) -> list:
        pass

    def supported_extensions(self) -> list[str]:
        return []

    def supported_languages(self) -> list[str]:
        return []


class RulePlugin(PluginBase):
    """Plugin that adds custom detection rules."""

    @abstractmethod
    def get_rules(self) -> list:
        pass


class ReporterPlugin(PluginBase):
    """Plugin that adds custom report formats."""

    @abstractmethod
    def generate(self, result: Any) -> str:
        pass

    @property
    @abstractmethod
    def format_name(self) -> str:
        pass


class ExporterPlugin(PluginBase):
    """Plugin that exports findings to external systems."""

    @abstractmethod
    def export(self, findings: list, config: dict) -> bool:
        pass


class AnalysisPhasePlugin(PluginBase):
    """Plugin that adds custom analysis phases to the pipeline."""

    @abstractmethod
    def analyze(self, findings: list, context: dict) -> list:
        pass

    @property
    @abstractmethod
    def phase_name(self) -> str:
        pass

    @property
    def phase_order(self) -> int:
        return 100


class PluginManager:
    """Manages plugin registration, loading, and lifecycle."""

    def __init__(self):
        self._scanners: list[ScannerPlugin] = []
        self._rules: list[RulePlugin] = []
        self._reporters: list[ReporterPlugin] = []
        self._exporters: list[ExporterPlugin] = []
        self._analysis_phases: list[AnalysisPhasePlugin] = []
        self._all_plugins: list[PluginBase] = []
        self._config: dict = {}

    def register(self, plugin: PluginBase) -> None:
        meta = plugin.metadata
        logger.info(f"Registering plugin: {meta.name} v{meta.version} ({meta.plugin_type})")

        if isinstance(plugin, ScannerPlugin):
            self._scanners.append(plugin)
        if isinstance(plugin, RulePlugin):
            self._rules.append(plugin)
        if isinstance(plugin, ReporterPlugin):
            self._reporters.append(plugin)
        if isinstance(plugin, ExporterPlugin):
            self._exporters.append(plugin)
        if isinstance(plugin, AnalysisPhasePlugin):
            self._analysis_phases.append(plugin)
            self._analysis_phases.sort(key=lambda p: p.phase_order)

        self._all_plugins.append(plugin)

    def initialize_all(self, config: dict) -> None:
        self._config = config
        for plugin in self._all_plugins:
            try:
                plugin.initialize(config)
            except Exception as e:
                meta = plugin.metadata
                logger.error(f"Failed to initialize plugin {meta.name}: {e}")

    def shutdown_all(self) -> None:
        for plugin in self._all_plugins:
            try:
                plugin.shutdown()
            except Exception as e:
                meta = plugin.metadata
                logger.error(f"Failed to shutdown plugin {meta.name}: {e}")

    @property
    def scanners(self) -> list[ScannerPlugin]:
        return list(self._scanners)

    @property
    def rules(self) -> list[RulePlugin]:
        return list(self._rules)

    @property
    def reporters(self) -> list[ReporterPlugin]:
        return list(self._reporters)

    @property
    def exporters(self) -> list[ExporterPlugin]:
        return list(self._exporters)

    @property
    def analysis_phases(self) -> list[AnalysisPhasePlugin]:
        return list(self._analysis_phases)

    def get_all_scanner_rules(self) -> list:
        rules = []
        for plugin in self._rules:
            try:
                rules.extend(plugin.get_rules())
            except Exception as e:
                logger.error(f"Plugin {plugin.metadata.name} failed to provide rules: {e}")
        return rules

    def load_from_directory(self, directory: str) -> int:
        loaded = 0
        plugin_dir = Path(directory)
        if not plugin_dir.exists():
            return 0

        for py_file in plugin_dir.rglob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                module_name = str(py_file.relative_to(plugin_dir.parent)).replace(os.sep, ".").replace("/", ".").rstrip(".py")
                spec = importlib.util.spec_from_file_location(module_name, str(py_file))
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and issubclass(attr, PluginBase) and attr is not PluginBase
                                and not attr.__name__.startswith("Abstract")):
                            try:
                                instance = attr()
                                self.register(instance)
                                loaded += 1
                            except Exception as e:
                                logger.error(f"Failed to instantiate {attr.__name__}: {e}")
            except Exception as e:
                logger.error(f"Failed to load plugin from {py_file}: {e}")

        return loaded

    def list_plugins(self) -> list[dict]:
        result = []
        for plugin in self._all_plugins:
            meta = plugin.metadata
            result.append({
                "name": meta.name,
                "version": meta.version,
                "author": meta.author,
                "description": meta.description,
                "type": meta.plugin_type,
                "dependencies": meta.dependencies,
            })
        return result
