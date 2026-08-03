"""Gate tests: precision/recall benchmark must stay above thresholds.

Runs the labeled vulnerable + clean corpora through the scan engine and
asserts the precision/recall gates and a zero-finding clean corpus.
"""

from scripts.benchmark_precision_recall import (
    BENCHMARK_DIR,
    PRECISION_GATE,
    RECALL_GATE,
    run_benchmark,
)


def test_benchmark_gates():
    report = run_benchmark(BENCHMARK_DIR)
    assert report["precision"] >= PRECISION_GATE
    assert report["recall"] >= RECALL_GATE
    assert report["clean_findings"] == []
    assert report["passed"] is True


def test_benchmark_reports_every_label():
    report = run_benchmark(BENCHMARK_DIR)
    assert report["false_negatives"] == 0
    assert report["true_positives"] == report["labels_total"]


def test_benchmark_false_positive_list_empty():
    report = run_benchmark(BENCHMARK_DIR)
    assert report["false_positives"] == []
