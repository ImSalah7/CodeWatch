"""Precision / recall benchmark for the scan engine.

Scans the labeled vulnerable corpus and the clean corpus under
``tests/benchmark`` and reports:

  precision = TP / (TP + FP)
  recall    = matched labels / total labels
  clean FP  = findings reported on the clean corpus

A finding counts as a true positive when its rule fires on a line the
manifest labels for that rule. Findings on a labeled line under a
*different* rule are counted as overlapping duplicates (excluded from
both TP and FP). Findings on unlabeled lines are false positives.
Only SECURITY and SECRET category findings participate in the metrics.

Usage:
    python scripts/benchmark_precision_recall.py [--dir PATH] [--json] [--strict]

Exit code is 1 (when --strict) if precision or recall fall below the
gates or the clean corpus reports any findings.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.config import ScanConfig
from src.core.engine import ScanEngine
from src.core.models import FindingCategory

BENCHMARK_DIR = Path(__file__).resolve().parents[1] / "tests" / "benchmark"
MANIFEST = "manifest.json"
RELEVANT_CATEGORIES = {FindingCategory.SECURITY, FindingCategory.SECRET}
LINE_TOLERANCE = 1
PRECISION_GATE = 0.7
RECALL_GATE = 0.8


def _relevant(findings) -> list:
    return [f for f in findings if f.category in RELEVANT_CATEGORIES]


def scan_dir(engine: ScanEngine, path: Path) -> list:
    result = engine.scan(str(path))
    return _relevant(result.findings)


def run_benchmark(benchmark_dir: Path) -> dict:
    manifest = json.loads((benchmark_dir / MANIFEST).read_text(encoding="utf-8"))
    engine = ScanEngine(ScanConfig(include_tests=True, include_docs=True))

    # Label lookup: (basename, line) -> set of expected rule ids.
    labels: dict[tuple[str, int], set[str]] = {}
    for entry in manifest["vulnerable"]:
        key = (Path(entry["file"]).name, int(entry["line"]))
        labels.setdefault(key, set()).add(entry["rule_id"])
    total_labels = sum(len(v) for v in labels.values())

    findings = scan_dir(engine, benchmark_dir / "vulnerable")
    matched: set[tuple] = set()
    duplicates: list[dict] = []
    false_positives: list[dict] = []
    for f in findings:
        key = (Path(f.location.file_path).name, f.location.line)
        expected = labels.get(key, set())
        if f.rule_id in expected:
            matched.add((key, f.rule_id))
        elif expected:
            duplicates.append({"rule_id": f.rule_id, "file": key[0], "line": key[1]})
        else:
            false_positives.append({"rule_id": f.rule_id, "file": key[0], "line": key[1]})

    true_positives = len(matched)
    false_negatives = total_labels - true_positives
    precision = true_positives / (true_positives + len(false_positives)) if (true_positives + len(false_positives)) else 1.0
    recall = true_positives / total_labels if total_labels else 1.0

    clean_findings = [
        {
            "rule_id": f.rule_id,
            "file": Path(f.location.file_path).name,
            "line": f.location.line,
        }
        for f in scan_dir(engine, benchmark_dir / "clean")
    ]

    return {
        "labels_total": total_labels,
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "overlapping_duplicates": duplicates,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "clean_findings": clean_findings,
        "gates": {
            "precision": PRECISION_GATE,
            "recall": RECALL_GATE,
            "clean_findings": 0,
        },
        "passed": (
            precision >= PRECISION_GATE
            and recall >= RECALL_GATE
            and not clean_findings
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, default=BENCHMARK_DIR)
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when gates fail")
    args = parser.parse_args()

    report = run_benchmark(args.dir)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Labels total:             {report['labels_total']}")
        print(f"True positives:           {report['true_positives']}")
        print(f"False negatives:          {report['false_negatives']}")
        print(f"False positives:          {len(report['false_positives'])}")
        for fp in report["false_positives"]:
            print(f"  - {fp['rule_id']} {fp['file']}:{fp['line']}")
        print(f"Overlapping duplicates:   {len(report['overlapping_duplicates'])}")
        print(f"Clean corpus findings:    {len(report['clean_findings'])}")
        for fp in report["clean_findings"]:
            print(f"  - {fp['rule_id']} {fp['file']}:{fp['line']}")
        print(f"Precision:                {report['precision']:.3f} (gate >= {report['gates']['precision']:.2f})")
        print(f"Recall:                   {report['recall']:.3f} (gate >= {report['gates']['recall']:.2f})")
        print(f"RESULT: {'PASS' if report['passed'] else 'FAIL'}")

    if args.strict and not report["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
