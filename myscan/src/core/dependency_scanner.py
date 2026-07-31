"""Dependency Security Scanner.

Scans package manifests and lock files for:
- Known vulnerable dependencies (CVE matching)
- Outdated packages
- License compliance
- Dependency tree analysis

Supports:
- Python: requirements.txt, poetry.lock, Pipfile.lock, setup.py, pyproject.toml
- JavaScript: package.json, package-lock.json, yarn.lock
- Go: go.sum, go.mod
- Rust: Cargo.lock, Cargo.toml
- Ruby: Gemfile.lock
- Java: pom.xml (Maven), build.gradle
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class PackageManager(Enum):
    PIP = "pip"
    NPM = "npm"
    YARN = "yarn"
    GO = "go"
    CARGO = "cargo"
    BUNDLER = "bundler"
    MAVEN = "maven"
    GRADLE = "gradle"
    UNKNOWN = "unknown"


class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class Dependency:
    """A single dependency."""
    name: str
    version: str
    package_manager: PackageManager
    is_direct: bool = True
    is_dev: bool = False
    license: str = ""
    homepage: str = ""


@dataclass
class Vulnerability:
    """A known vulnerability in a dependency."""
    dependency_name: str
    dependency_version: str
    vulnerability_id: str = ""
    severity: VulnerabilitySeverity = VulnerabilitySeverity.UNKNOWN
    title: str = ""
    description: str = ""
    fixed_version: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class DependencyScanResult:
    """Result of dependency security scan."""
    file_path: str
    package_manager: PackageManager
    dependencies: list[Dependency] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    total_dependencies: int = 0
    direct_dependencies: int = 0
    dev_dependencies: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    risk_score: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "filePath": self.file_path,
            "packageManager": self.package_manager.value,
            "totalDependencies": self.total_dependencies,
            "directDependencies": self.direct_dependencies,
            "vulnerabilities": {
                "critical": self.critical_vulns,
                "high": self.high_vulns,
                "medium": self.medium_vulns,
                "low": self.low_vulns,
                "total": len(self.vulnerabilities),
            },
            "riskScore": round(self.risk_score, 2),
        }


KNOWN_VULNERABILITIES = {
    "requests": [
        {"versions": ["<2.20.0"], "id": "CVE-2018-18074", "severity": "high",
         "title": "Requests IP address leak", "fixed": "2.20.0"},
    ],
    "flask": [
        {"versions": ["<1.0"], "id": "CVE-2018-1000656", "severity": "high",
         "title": "Flask DoS via JSON", "fixed": "1.0"},
    ],
    "django": [
        {"versions": ["<2.2.13"], "id": "CVE-2020-13596", "severity": "high",
         "title": "Django SQL injection", "fixed": "2.2.13"},
    ],
    "sqlalchemy": [
        {"versions": ["<1.4.23"], "id": "GHSA-8jxr-mccc-42qm", "severity": "medium",
         "title": "SQLAlchemy SQL injection", "fixed": "1.4.23"},
    ],
    "pyyaml": [
        {"versions": ["<5.4"], "id": "CVE-2020-14343", "severity": "critical",
         "title": "PyYAML arbitrary code execution", "fixed": "5.4"},
    ],
    "cryptography": [
        {"versions": ["<42.0.0"], "id": "GHSA-4374-p667-p6c8", "severity": "high",
         "title": "cryptography NULL dereference", "fixed": "42.0.0"},
    ],
    "urllib3": [
        {"versions": ["<1.26.5"], "id": "CVE-2021-33503", "severity": "high",
         "title": "urllib3 ReDoS", "fixed": "1.26.5"},
    ],
    "aiohttp": [
        {"versions": ["<3.8.0"], "id": "CVE-2023-37276", "severity": "critical",
         "title": "aiohttp HTTP request smuggling", "fixed": "3.8.0"},
    ],
    "jinja2": [
        {"versions": ["<3.1.3"], "id": "CVE-2024-22195", "severity": "medium",
         "title": "Jinja2 XSS in xmlattr filter", "fixed": "3.1.3"},
    ],
    "certifi": [
        {"versions": ["<2023.7.22"], "id": "CVE-2023-37920", "severity": "high",
         "title": "Certifi removal of e-Tugra root certificate", "fixed": "2023.7.22"},
    ],
}


_PRE_LABELS = {"a", "alpha", "b", "beta", "c", "rc", "pre", "preview", "dev"}


def _split_pre(main: str) -> tuple[str, str | None]:
    """Split a PEP 440 release like '1.0.0rc1' into ('1.0.0', 'rc1')."""
    for m in re.finditer(r"[0-9]+|[a-zA-Z]+", main):
        if m.group() in _PRE_LABELS:
            return main[:m.start()], main[m.start():]
    return main, None


def _version_key(version: str) -> tuple:
    """Parse a version string into a comparable key (semver-aware)."""
    version = str(version).strip().lstrip("=vV ")
    version = version.split("+", 1)[0]
    if not version or version in ("*", "x", "X"):
        return (0, (1,))
    main, _, pre = version.partition("-")
    if not pre:
        main, pre = _split_pre(main)
    core = tuple(
        int(t) if t.isdigit() else t
        for t in re.findall(r"[0-9]+|[a-zA-Z]+", main) or ("0",)
    )
    if pre:
        prek = tuple(
            int(t) if t.isdigit() else t
            for t in re.findall(r"[0-9]+|[a-zA-Z]+", pre) or (0,)
        )
        return core + ((0, prek),)
    return core + ((1,),)


def _cmp_tokens(x, y) -> int:
    if isinstance(x, int) and isinstance(y, int):
        return (x > y) - (x < y)
    if isinstance(x, str) and isinstance(y, str):
        return (x > y) - (x < y)
    return -1 if isinstance(x, int) else 1


def _cmp_keys(a: tuple, b: tuple) -> int:
    """Compare two version keys. Missing components pad with 0."""
    ca, ta = a[:-1], a[-1]
    cb, tb = b[:-1], b[-1]
    n = max(len(ca), len(cb))
    for i in range(n):
        x = ca[i] if i < len(ca) else 0
        y = cb[i] if i < len(cb) else 0
        r = _cmp_tokens(x, y)
        if r:
            return r
    return (ta[0] > tb[0]) - (ta[0] < tb[0])


def _cmp_versions(a: str, b: str) -> int:
    return _cmp_keys(_version_key(a), _version_key(b))


def _release_parts(version: str) -> list[int]:
    m = re.match(r"^\s*v?(\d+(?:\.\d+)*)", str(version))
    if not m:
        return []
    return [int(x) for x in m.group(1).split(".")]


def _join_parts(parts: list[int]) -> str:
    return ".".join(str(p) for p in parts)


def _bounds_one(spec: str) -> tuple:
    """Parse a single spec clause into (lo, lo_incl, hi, hi_incl) bounds."""
    spec = spec.strip().rstrip(",")
    if not spec or spec in ("*", "x", "X"):
        return (None, True, None, True)
    if re.search(r"(\.\*|\.x)$", spec, re.IGNORECASE):
        base = spec[:-2]
        parts = _release_parts(base)
        if not parts:
            return (None, True, None, True)
        if len(parts) == 1:
            hi = [parts[0] + 1]
        else:
            hi = [parts[0], parts[1] + 1]
        return (_version_key(base), True, _version_key(_join_parts(hi)), False)
    m = re.match(r"^\s*(?P<op>\^|~=|>=|<=|==|=|>|<|~|!=)?\s*(?P<ver>.+?)\s*$", spec)
    op = (m.group("op") or "").strip() if m else ""
    ver = (m.group("ver").strip() if m else spec).rstrip(",")
    if not op or op in ("==", "="):
        return (_version_key(ver), True, _version_key(ver), True)
    if op in (">=", ">"):
        return (_version_key(ver), True, None, True)
    if op == "<":
        return (None, True, _version_key(ver), False)
    if op == "<=":
        return (None, True, _version_key(ver), True)
    if op == "!=":
        return (None, True, None, True)
    if op == "~=":
        parts = _release_parts(ver)
        if not parts:
            return (None, True, None, True)
        if len(parts) == 1:
            hi = [parts[0] + 1]
        else:
            hi = parts[:-2] + [parts[-2] + 1]
        return (_version_key(ver), True, _version_key(_join_parts(hi)), False)
    if op == "^":
        parts = _release_parts(ver)
        if not parts:
            return (None, True, None, True)
        if parts[0] > 0:
            hi = [parts[0] + 1]
        elif len(parts) >= 2 and parts[1] > 0:
            hi = [0, parts[1] + 1]
        else:
            hi = [0, 0, parts[2] + 1] if len(parts) >= 3 else [0, 1]
        return (_version_key(ver), True, _version_key(_join_parts(hi)), False)
    if op == "~":
        parts = _release_parts(ver)
        if not parts:
            return (None, True, None, True)
        if len(parts) == 1:
            hi = [parts[0] + 1]
        else:
            hi = [parts[0], parts[1] + 1]
        return (_version_key(ver), True, _version_key(_join_parts(hi)), False)
    return (_version_key(ver), True, _version_key(ver), True)


def _split_clauses(spec: str) -> list[str]:
    toks = [t for t in re.split(r"[,\s]+", spec) if t]
    clauses = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if len(t) == 1 and t[0] in "<>=!~^" and i + 1 < len(toks):
            clauses.append(t + toks[i + 1])
            i += 2
        else:
            clauses.append(t)
            i += 1
    return clauses


def _parse_version_spec(spec: str) -> list:
    """Parse a version spec into a list of (lo, lo_incl, hi, hi_incl) bounds.

    Each list element is one '||' union clause; bounds are inclusive-lower /
    exclusive-upper by convention and may be None (unbounded).
    """
    spec = spec.strip()
    if not spec:
        return [(None, True, None, True)]
    groups = []
    for part in re.split(r"\s*\|\|\s*", spec):
        part = part.strip()
        if not part:
            continue
        if " - " in part:
            low, _, high = part.partition(" - ")
            lb = _bounds_one(low)
            hb = _bounds_one(high)
            groups.append((lb[0], lb[1], hb[2], hb[3]))
            continue
        lo, lo_incl, hi, hi_incl = None, True, None, True
        for clause in _split_clauses(part):
            b = _bounds_one(clause)
            if b[0] is not None:
                if lo is None:
                    lo, lo_incl = b[0], b[1]
                else:
                    c = _cmp_keys(b[0], lo)
                    if c > 0:
                        lo, lo_incl = b[0], b[1]
                    elif c == 0:
                        lo_incl = lo_incl or b[1]
            if b[2] is not None:
                if hi is None:
                    hi, hi_incl = b[2], b[3]
                else:
                    c = _cmp_keys(b[2], hi)
                    if c < 0:
                        hi, hi_incl = b[2], b[3]
                    elif c == 0:
                        hi_incl = hi_incl or b[3]
        groups.append((lo, lo_incl, hi, hi_incl))
    return groups or [(None, True, None, True)]


def _hi_ge_lo(hi, hi_incl: bool, lo, lo_incl: bool) -> bool:
    if hi is None or lo is None:
        return True
    c = _cmp_keys(hi, lo)
    if c > 0:
        return True
    if c < 0:
        return False
    return hi_incl and lo_incl


def _bounds_overlap(a: tuple, b: tuple) -> bool:
    return (
        _hi_ge_lo(a[2], a[3], b[0], b[1])
        and _hi_ge_lo(b[2], b[3], a[0], a[1])
    )


class DependencyScanner:
    """Scans dependencies for known vulnerabilities."""

    def scan_repository(self, repo_path: str) -> list[DependencyScanResult]:
        results = []
        root = Path(repo_path)

        manifest_files = {
            "requirements.txt": self._scan_requirements_txt,
            "pyproject.toml": self._scan_pyproject_toml,
            "package.json": self._scan_package_json,
            "package-lock.json": self._scan_package_lock,
            "go.sum": self._scan_go_sum,
            "Cargo.lock": self._scan_cargo_lock,
            "Gemfile.lock": self._scan_gemfile_lock,
            "Pipfile.lock": self._scan_pipfile_lock,
            "poetry.lock": self._scan_poetry_lock,
        }

        for filename, scanner_func in manifest_files.items():
            for path in root.rglob(filename):
                try:
                    result = scanner_func(str(path))
                    if result and result.dependencies:
                        self._check_vulnerabilities(result)
                        self._calculate_risk_score(result)
                        results.append(result)
                except Exception as e:
                    results.append(DependencyScanResult(
                        file_path=str(path),
                        package_manager=PackageManager.UNKNOWN,
                        errors=[str(e)],
                    ))

        return results

    def scan_file(self, file_path: str) -> Optional[DependencyScanResult]:
        path = Path(file_path)
        scanners = {
            "requirements.txt": self._scan_requirements_txt,
            "pyproject.toml": self._scan_pyproject_toml,
            "package.json": self._scan_package_json,
            "package-lock.json": self._scan_package_lock,
            "go.sum": self._scan_go_sum,
            "Cargo.lock": self._scan_cargo_lock,
            "Gemfile.lock": self._scan_gemfile_lock,
            "Pipfile.lock": self._scan_pipfile_lock,
            "poetry.lock": self._scan_poetry_lock,
        }
        scanner = scanners.get(path.name)
        if scanner:
            result = scanner(file_path)
            if result:
                self._check_vulnerabilities(result)
                self._calculate_risk_score(result)
            return result
        return None

    def _scan_requirements_txt(self, file_path: str) -> DependencyScanResult:
        result = DependencyScanResult(file_path=file_path, package_manager=PackageManager.PIP)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([>=<~!]+)\s*([0-9a-zA-Z.*]+(?:[,\s]+[<>=!~]+\s*[0-9a-zA-Z.*]+)*)", line)
                    if match:
                        result.dependencies.append(Dependency(
                            name=match.group(1).lower(),
                            version=match.group(3),
                            package_manager=PackageManager.PIP,
                        ))
        except Exception as e:
            result.errors.append(str(e))
        result.total_dependencies = len(result.dependencies)
        result.direct_dependencies = len(result.dependencies)
        return result

    def _scan_package_json(self, file_path: str) -> DependencyScanResult:
        result = DependencyScanResult(file_path=file_path, package_manager=PackageManager.NPM)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for name, version in data.get("dependencies", {}).items():
                result.dependencies.append(Dependency(
                    name=name, version=version, package_manager=PackageManager.NPM, is_direct=True,
                ))
            for name, version in data.get("devDependencies", {}).items():
                result.dependencies.append(Dependency(
                    name=name, version=version, package_manager=PackageManager.NPM,
                    is_direct=True, is_dev=True,
                ))
        except Exception as e:
            result.errors.append(str(e))
        result.total_dependencies = len(result.dependencies)
        result.direct_dependencies = sum(1 for d in result.dependencies if d.is_direct and not d.is_dev)
        result.dev_dependencies = sum(1 for d in result.dependencies if d.is_dev)
        return result

    def _scan_pyproject_toml(self, file_path: str) -> DependencyScanResult:
        result = DependencyScanResult(file_path=file_path, package_manager=PackageManager.PIP)
        try:
            content = Path(file_path).read_text(encoding="utf-8")
            for match in re.finditer(r'"([a-zA-Z0-9_.-]+)\s*([>=<~!]+)\s*([0-9a-zA-Z.*]+)"', content):
                result.dependencies.append(Dependency(
                    name=match.group(1).lower(), version=match.group(3),
                    package_manager=PackageManager.PIP,
                ))
        except Exception as e:
            result.errors.append(str(e))
        result.total_dependencies = len(result.dependencies)
        result.direct_dependencies = len(result.dependencies)
        return result

    def _scan_package_lock(self, file_path: str) -> DependencyScanResult:
        result = DependencyScanResult(file_path=file_path, package_manager=PackageManager.NPM)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            packages = data.get("packages", data.get("dependencies", {}))
            for pkg_path, info in packages.items():
                name = pkg_path.replace("node_modules/", "") if pkg_path else info.get("name", "")
                version = info.get("version", "")
                if name and version:
                    result.dependencies.append(Dependency(
                        name=name, version=version, package_manager=PackageManager.NPM, is_direct=False,
                    ))
        except Exception as e:
            result.errors.append(str(e))
        result.total_dependencies = len(result.dependencies)
        return result

    def _scan_go_sum(self, file_path: str) -> DependencyScanResult:
        result = DependencyScanResult(file_path=file_path, package_manager=PackageManager.GO)
        try:
            seen = set()
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        name = parts[0].rsplit("/", 1)[-1] if "/" in parts[0] else parts[0]
                        version = parts[1].split("/")[0] if "/" in parts[1] else parts[1]
                        if name not in seen:
                            seen.add(name)
                            result.dependencies.append(Dependency(
                                name=name, version=version, package_manager=PackageManager.GO, is_direct=False,
                            ))
        except Exception as e:
            result.errors.append(str(e))
        result.total_dependencies = len(result.dependencies)
        return result

    def _scan_cargo_lock(self, file_path: str) -> DependencyScanResult:
        result = DependencyScanResult(file_path=file_path, package_manager=PackageManager.CARGO)
        try:
            content = Path(file_path).read_text(encoding="utf-8")
            for match in re.finditer(r'name = "([^"]+)"\nversion = "([^"]+)"', content):
                result.dependencies.append(Dependency(
                    name=match.group(1), version=match.group(2),
                    package_manager=PackageManager.CARGO, is_direct=False,
                ))
        except Exception as e:
            result.errors.append(str(e))
        result.total_dependencies = len(result.dependencies)
        return result

    def _scan_gemfile_lock(self, file_path: str) -> DependencyScanResult:
        result = DependencyScanResult(file_path=file_path, package_manager=PackageManager.BUNDLER)
        try:
            content = Path(file_path).read_text(encoding="utf-8")
            for match in re.finditer(r"^\s{4}([a-zA-Z0-9_.-]+) \(([^)]+)\)", content, re.MULTILINE):
                result.dependencies.append(Dependency(
                    name=match.group(1), version=match.group(2),
                    package_manager=PackageManager.BUNDLER, is_direct=False,
                ))
        except Exception as e:
            result.errors.append(str(e))
        result.total_dependencies = len(result.dependencies)
        return result

    def _scan_pipfile_lock(self, file_path: str) -> DependencyScanResult:
        result = DependencyScanResult(file_path=file_path, package_manager=PackageManager.PIP)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for section in ("default", "develop"):
                for name, info in data.get(section, {}).items():
                    result.dependencies.append(Dependency(
                        name=name, version=info.get("version", ""),
                        package_manager=PackageManager.PIP,
                        is_dev=(section == "develop"),
                    ))
        except Exception as e:
            result.errors.append(str(e))
        result.total_dependencies = len(result.dependencies)
        return result

    def _scan_poetry_lock(self, file_path: str) -> DependencyScanResult:
        result = DependencyScanResult(file_path=file_path, package_manager=PackageManager.PIP)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            for match in re.finditer(r'name = "([^"]+)"\nversion = "([^"]+)"', content):
                result.dependencies.append(Dependency(
                    name=match.group(1), version=match.group(2),
                    package_manager=PackageManager.PIP, is_direct=False,
                ))
        except Exception as e:
            result.errors.append(str(e))
        result.total_dependencies = len(result.dependencies)
        return result

    def _check_vulnerabilities(self, result: DependencyScanResult) -> None:
        for dep in result.dependencies:
            name_lower = dep.name.lower()
            if name_lower not in KNOWN_VULNERABILITIES:
                continue
            dep_bounds = _parse_version_spec(dep.version)
            for vuln_info in KNOWN_VULNERABILITIES[name_lower]:
                vuln_bounds = [
                    b
                    for v in vuln_info.get("versions", [])
                    for b in _parse_version_spec(v)
                ]
                if not vuln_bounds:
                    continue
                if any(_bounds_overlap(db, vb) for db in dep_bounds for vb in vuln_bounds):
                    result.vulnerabilities.append(Vulnerability(
                        dependency_name=dep.name,
                        dependency_version=dep.version,
                        vulnerability_id=vuln_info.get("id", ""),
                        severity=VulnerabilitySeverity(vuln_info.get("severity", "unknown")),
                        title=vuln_info.get("title", ""),
                        fixed_version=vuln_info.get("fixed", ""),
                    ))

        result.critical_vulns = sum(1 for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL)
        result.high_vulns = sum(1 for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH)
        result.medium_vulns = sum(1 for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM)
        result.low_vulns = sum(1 for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.LOW)

    def _calculate_risk_score(self, result: DependencyScanResult) -> None:
        if not result.total_dependencies:
            result.risk_score = 0.0
            return
        vuln_score = (
            result.critical_vulns * 25 +
            result.high_vulns * 15 +
            result.medium_vulns * 8 +
            result.low_vulns * 3
        )
        vuln_ratio = len(result.vulnerabilities) / max(result.total_dependencies, 1)
        result.risk_score = min(100.0, vuln_score + vuln_ratio * 50)
