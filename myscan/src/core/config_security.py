"""Configuration Security Scanner.

Analyzes infrastructure configuration files for security issues:
- Docker / Docker Compose
- Kubernetes manifests
- Terraform
- GitHub Actions workflows
- NGINX / Apache configs
- CI/CD pipelines
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class ConfigType(Enum):
    DOCKER = "docker"
    DOCKER_COMPOSE = "docker_compose"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    GITHUB_ACTIONS = "github_actions"
    NGINX = "nginx"
    APACHE = "apache"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    UNKNOWN = "unknown"


class ConfigSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ConfigFinding:
    """A security finding in a configuration file."""
    file_path: str
    config_type: ConfigType
    line: int
    severity: ConfigSeverity
    rule_id: str
    title: str
    description: str
    current_value: str = ""
    recommended_value: str = ""
    fix_suggestion: str = ""

    def to_dict(self) -> dict:
        return {
            "filePath": self.file_path,
            "configType": self.config_type.value,
            "line": self.line,
            "severity": self.severity.value,
            "ruleId": self.rule_id,
            "title": self.title,
            "description": self.description,
            "currentValue": self.current_value,
            "recommendedValue": self.recommended_value,
            "fixSuggestion": self.fix_suggestion,
        }


CONFIG_RULES = {
    "docker_privileged": {
        "title": "Privileged container",
        "severity": ConfigSeverity.CRITICAL,
        "pattern": r"privileged:\s*true",
        "description": "Container runs with privileged flag, giving full host access.",
        "fix": "Remove 'privileged: true' or set to false.",
    },
    "docker_latest_tag": {
        "title": "Using latest tag",
        "severity": ConfigSeverity.MEDIUM,
        "pattern": r"(?:image:\s*|FROM\s+)\S+:latest",
        "description": "Using 'latest' tag is unpredictable and may pull vulnerable images.",
        "fix": "Pin to a specific version tag.",
    },
    "docker_root_user": {
        "title": "Running as root",
        "severity": ConfigSeverity.HIGH,
        "pattern": r"USER\s+root|user:\s*root",
        "description": "Container runs as root, increasing attack surface.",
        "fix": "Add a non-root USER directive.",
    },
    "docker_expose_port": {
        "title": "Exposed port",
        "severity": ConfigSeverity.LOW,
        "pattern": r"EXPOSE\s+(\d+)",
        "description": "Port exposure should be reviewed for necessity.",
        "fix": "Ensure only required ports are exposed.",
    },
    "k8s_privileged": {
        "title": "Privileged pod",
        "severity": ConfigSeverity.CRITICAL,
        "pattern": r"privileged:\s*true",
        "description": "Pod runs with privileged security context.",
        "fix": "Remove privileged flag or set to false.",
    },
    "k8s_host_network": {
        "title": "Host network access",
        "severity": ConfigSeverity.HIGH,
        "pattern": r"hostNetwork:\s*true",
        "description": "Pod uses host network namespace.",
        "fix": "Remove hostNetwork or set to false.",
    },
    "k8s_host_pid": {
        "title": "Host PID namespace",
        "severity": ConfigSeverity.HIGH,
        "pattern": r"hostPID:\s*true",
        "description": "Pod shares host PID namespace.",
        "fix": "Remove hostPID or set to false.",
    },
    "k8s_allow_privilege_escalation": {
        "title": "Privilege escalation allowed",
        "severity": ConfigSeverity.HIGH,
        "pattern": r"allowPrivilegeEscalation:\s*true",
        "description": "Container allows privilege escalation.",
        "fix": "Set allowPrivilegeEscalation to false.",
    },
    "k8s_writable_rootfs": {
        "title": "Writable root filesystem",
        "severity": ConfigSeverity.MEDIUM,
        "pattern": r"readOnlyRootFilesystem:\s*false",
        "description": "Root filesystem is writable.",
        "fix": "Set readOnlyRootFilesystem to true.",
    },
    "terraform_public_acl": {
        "title": "Public S3 bucket ACL",
        "severity": ConfigSeverity.CRITICAL,
        "pattern": r'acl\s*=\s*"public-read|acl\s*=\s*"public-read-write',
        "description": "S3 bucket has public ACL.",
        "fix": "Use 'private' ACL or S3 bucket policies.",
    },
    "terraform_no_encryption": {
        "title": "S3 bucket without encryption",
        "severity": ConfigSeverity.HIGH,
        "pattern": r"server_side_encryption_configuration",
        "description": "Check if encryption is configured.",
        "fix": "Add server_side_encryption_configuration.",
    },
    "terraform_public_db": {
        "title": "Publicly accessible database",
        "severity": ConfigSeverity.CRITICAL,
        "pattern": r"publicly_accessible\s*=\s*true",
        "description": "RDS instance is publicly accessible.",
        "fix": "Set publicly_accessible to false.",
    },
    "terraform_open_cidr": {
        "title": "Open CIDR block",
        "severity": ConfigSeverity.HIGH,
        "pattern": r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
        "description": "Security group allows traffic from any IP.",
        "fix": "Restrict CIDR to specific IP ranges.",
    },
    "gh_actions_script_injection": {
        "title": "Potential script injection",
        "severity": ConfigSeverity.HIGH,
        "pattern": r"\$\{\{.*github\.event\.",
        "description": "GitHub Actions expression may be vulnerable to script injection.",
        "fix": "Use environment variables instead of direct expression injection.",
    },
    "gh_actions_write_permissions": {
        "title": "Write-all permissions",
        "severity": ConfigSeverity.MEDIUM,
        "pattern": r"permissions:\s*\n\s*contents:\s*write|permissions:\s*write-all",
        "description": "Workflow has broad write permissions.",
        "fix": "Grant only minimum required permissions.",
    },
    "nginx_server_tokens": {
        "title": "Server tokens enabled",
        "severity": ConfigSeverity.LOW,
        "pattern": r"server_tokens\s+on",
        "description": "Server version exposed in response headers.",
        "fix": "Set 'server_tokens off'.",
    },
    "nginx_directory_listing": {
        "title": "Directory listing enabled",
        "severity": ConfigSeverity.MEDIUM,
        "pattern": r"autoindex\s+on",
        "description": "Directory listing is enabled.",
        "fix": "Set 'autoindex off'.",
    },
    "gitlab_script_execution": {
        "title": "Script execution in CI",
        "severity": ConfigSeverity.MEDIUM,
        "pattern": r"script:\s*\|",
        "description": "Multi-line script block should be reviewed.",
        "fix": "Review script content for security issues.",
    },
}


class ConfigSecurityScanner:
    """Scans configuration files for security issues."""

    FILE_PATTERNS = {
        "Dockerfile": ConfigType.DOCKER,
        "dockerfile": ConfigType.DOCKER,
        "docker-compose.yml": ConfigType.DOCKER_COMPOSE,
        "docker-compose.yaml": ConfigType.DOCKER_COMPOSE,
        "compose.yml": ConfigType.DOCKER_COMPOSE,
        "compose.yaml": ConfigType.DOCKER_COMPOSE,
        ".github/workflows/": ConfigType.GITHUB_ACTIONS,
        "nginx.conf": ConfigType.NGINX,
        ".gitlab-ci.yml": ConfigType.GITLAB_CI,
    }

    EXTENSION_PATTERNS = {
        ".tf": ConfigType.TERRAFORM,
        ".tf.json": ConfigType.TERRAFORM,
    }

    K8S_KEYWORDS = {"apiVersion", "kind", "metadata", "spec"}
    K8S_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Service", "ConfigMap", "Ingress"}

    def scan_repository(self, repo_path: str) -> list[ConfigFinding]:
        findings = []
        root = Path(repo_path)

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            config_type = self._identify_config(path)
            if config_type != ConfigType.UNKNOWN:
                file_findings = self.scan_file(str(path), config_type)
                findings.extend(file_findings)

        return findings

    def scan_file(self, file_path: str, config_type: Optional[ConfigType] = None) -> list[ConfigFinding]:
        path = Path(file_path)
        if config_type is None:
            config_type = self._identify_config(path)

        if config_type == ConfigType.UNKNOWN:
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        findings = []
        lines = content.split("\n")

        for rule_id, rule in CONFIG_RULES.items():
            for i, line in enumerate(lines, 1):
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    findings.append(ConfigFinding(
                        file_path=file_path,
                        config_type=config_type,
                        line=i,
                        severity=rule["severity"],
                        rule_id=rule_id,
                        title=rule["title"],
                        description=rule["description"],
                        current_value=line.strip(),
                        recommended_value=rule.get("fix", ""),
                        fix_suggestion=rule.get("fix", ""),
                    ))

        return findings

    def _identify_config(self, path: Path) -> ConfigType:
        name = path.name
        for pattern, ctype in self.FILE_PATTERNS.items():
            if pattern in str(path) or name == pattern:
                return ctype

        if path.suffix in self.EXTENSION_PATTERNS:
            return self.EXTENSION_PATTERNS[path.suffix]

        if name == "Dockerfile" or name.startswith("Dockerfile."):
            return ConfigType.DOCKER

        if ".github" in str(path) and path.suffix in (".yml", ".yaml"):
            return ConfigType.GITHUB_ACTIONS

        if name in ("Jenkinsfile",):
            return ConfigType.JENKINS

        if name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            return ConfigType.MAVEN

        if path.suffix in (".yml", ".yaml"):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")[:500]
                if any(kw in content for kw in self.K8S_KEYWORDS):
                    if any(kind in content for kind in self.K8S_KINDS):
                        return ConfigType.KUBERNETES
            except Exception:
                pass

        if name in ("nginx.conf",) or ".nginx" in str(path).lower():
            return ConfigType.NGINX

        if name in (".htaccess", "httpd.conf", "apache2.conf"):
            return ConfigType.APACHE

        return ConfigType.UNKNOWN
