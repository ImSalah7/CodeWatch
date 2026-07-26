"""Report generators."""

from __future__ import annotations

from .sarif import SARIFReporter
from .html_report import HTMLReporter
from .csv_report import CSVReporter
from .json_report import JSONReporter
from .markdown_report import MarkdownReporter

REPORTERS = {
    "sarif": SARIFReporter,
    "html": HTMLReporter,
    "csv": CSVReporter,
    "json": JSONReporter,
    "markdown": MarkdownReporter,
}
