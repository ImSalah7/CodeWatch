"""SBOM Generator - Software Bill of Materials.

Generates SBOM in:
- CycloneDX JSON format
- SPDX JSON format

Includes:
- Component inventory
- Dependency tree
- License information
- Vulnerability references
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..__init__ import __version__
from .dependency_scanner import Dependency, DependencyScanResult, PackageManager


@dataclass
class SBOMComponent:
    """A component in the SBOM."""
    name: str
    version: str
    component_type: str = "library"
    publisher: str = ""
    description: str = ""
    license_id: str = ""
    purl: str = ""
    external_references: list[dict] = field(default_factory=list)
    hashes: list[dict] = field(default_factory=list)


@dataclass
class SBOMDocument:
    """Complete SBOM document."""
    spec_version: str = ""
    version: str = "1.0.0"
    name: str = ""
    components: list[SBOMComponent] = field(default_factory=list)
    dependencies: list[dict] = field(default_factory=list)
    tools: list[dict] = field(default_factory=list)
    timestamp: str = ""

    def to_cyclonedx_json(self) -> str:
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{hashlib.md5(self.name.encode()).hexdigest()}",
            "version": 1,
            "metadata": {
                "timestamp": self.timestamp or datetime.now(UTC).isoformat(),
                "tools": [{
                    "vendor": "CodeWatch",
                    "name": "CodeWatch",
                    "version": __version__,
                }],
                "component": {
                    "type": "application",
                    "name": self.name,
                    "version": self.version,
                },
            },
            "components": [],
            "dependencies": [],
        }

        for comp in self.components:
            component = {
                "type": comp.component_type,
                "name": comp.name,
                "version": comp.version,
            }
            if comp.publisher:
                component["author"] = comp.publisher
            if comp.description:
                component["description"] = comp.description
            if comp.license_id:
                component["licenses"] = [{"license": {"id": comp.license_id}}]
            if comp.purl:
                component["purl"] = comp.purl
            if comp.hashes:
                component["hashes"] = comp.hashes
            if comp.external_references:
                component["externalReferences"] = comp.external_references
            bom["components"].append(component)

        for dep in self.dependencies:
            bom["dependencies"].append(dep)

        return json.dumps(bom, indent=2)

    def to_spdx_json(self) -> str:
        doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.name,
            "documentNamespace": f"https://github.com/myscan/{self.name}",
            "creationInfo": {
                "created": self.timestamp or datetime.now(UTC).isoformat(),
                "creators": [f"Tool: CodeWatch {__version__}"],
                "licenseListVersion": "3.21",
            },
            "packages": [],
            "relationships": [],
        }

        root_pkg = {
            "SPDXID": "SPDXRef-Package",
            "name": self.name,
            "versionInfo": self.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [],
            "primaryPackagePurpose": "APPLICATION",
        }
        doc["packages"].append(root_pkg)

        for comp in self.components:
            pkg = {
                "SPDXID": f"SPDXRef-{comp.name.replace('/', '-').replace('.', '-')}",
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "checksums": [],
                "primaryPackagePurpose": "LIBRARY",
            }
            if comp.license_id:
                pkg["licenseConcluded"] = comp.license_id
                pkg["licenseDeclared"] = comp.license_id
            else:
                pkg["licenseConcluded"] = "NOASSERTION"
                pkg["licenseDeclared"] = "NOASSERTION"
            doc["packages"].append(pkg)

            doc["relationships"].append({
                "spdxElementId": "SPDXRef-Package",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": pkg["SPDXID"],
            })

        return json.dumps(doc, indent=2)


class SBOMGenerator:
    """Generates SBOM from scan results."""

    def generate_from_results(self, scan_results: list[DependencyScanResult], project_name: str = "") -> SBOMDocument:
        doc = SBOMDocument(
            name=project_name or "unknown-project",
            version="1.0.0",
            timestamp=datetime.now(UTC).isoformat(),
        )

        seen = set()
        for result in scan_results:
            for dep in result.dependencies:
                if dep.name not in seen:
                    seen.add(dep.name)
                    purl = self._to_purl(dep)
                    comp = SBOMComponent(
                        name=dep.name,
                        version=dep.version,
                        purl=purl,
                        license_id=dep.license,
                        component_type="library",
                    )
                    if dep.package_manager == PackageManager.PIP:
                        comp.publisher = "PyPI"
                    elif dep.package_manager in (PackageManager.NPM, PackageManager.YARN):
                        comp.publisher = "npm"
                    doc.components.append(comp)

        return doc

    def generate_from_dependencies(self, dependencies: list[Dependency], project_name: str = "") -> SBOMDocument:
        doc = SBOMDocument(
            name=project_name or "unknown-project",
            version="1.0.0",
            timestamp=datetime.now(UTC).isoformat(),
        )

        for dep in dependencies:
            purl = self._to_purl(dep)
            comp = SBOMComponent(
                name=dep.name,
                version=dep.version,
                purl=purl,
                license_id=dep.license,
                component_type="library",
            )
            doc.components.append(comp)

        return doc

    @staticmethod
    def _to_purl(dep: Dependency) -> str:
        type_map = {
            PackageManager.PIP: "pypi",
            PackageManager.NPM: "npm",
            PackageManager.YARN: "npm",
            PackageManager.GO: "golang",
            PackageManager.CARGO: "cargo",
            PackageManager.BUNDLER: "gem",
            PackageManager.MAVEN: "maven",
        }
        ptype = type_map.get(dep.package_manager, "generic")
        return f"pkg:{ptype}/{dep.name}@{dep.version}"
