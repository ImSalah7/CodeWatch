"""Report generators."""

from __future__ import annotations

from .csv_report import CSVReporter
from .html_report import HTMLReporter
from .json_report import JSONReporter
from .markdown_report import MarkdownReporter
from .sarif import SARIFReporter

REPORTERS = {
    "sarif": SARIFReporter,
    "html": HTMLReporter,
    "csv": CSVReporter,
    "json": JSONReporter,
    "markdown": MarkdownReporter,
}
